'use strict';

const net = require('net');
const crypto = require('crypto');
const request = require('supertest');
const { server } = require('../server.js');

beforeAll(async () => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
});

afterAll(async () => {
  await new Promise((resolve) => {
    server.close(resolve);
    setTimeout(resolve, 1000);
  });
});

describe('protocol v2 schema endpoint', () => {
  test('GET /protocol/semantic-frame-v2.schema.json returns v2 schema', async () => {
    const res = await request(server).get('/protocol/semantic-frame-v2.schema.json');
    expect(res.status).toBe(200);
    expect(res.body.$id).toBe('semantic-frame-v2');
    expect(res.body.required).toContain('frameType');
    expect(res.body.required).toContain('checksum');
    expect(res.body.required).toContain('removedIds');
  });
});

describe('WebSocket protocol negotiation', () => {
  function wsHandshake() {
    return new Promise((resolve, reject) => {
      const key = crypto.randomBytes(16).toString('base64');
      const socket = net.connect(server.address().port, '127.0.0.1');
      let settled = false;
      const finish = (value, error) => {
        if (settled) return;
        settled = true;
        socket.removeAllListeners('data');
        socket.removeAllListeners('error');
        socket.removeAllListeners('connect');
        if (error) reject(error);
        else resolve(value);
      };
      socket.on('connect', () => {
        socket.write(
          'GET /ws HTTP/1.1\r\n' +
            'Host: 127.0.0.1\r\n' +
            'Upgrade: websocket\r\n' +
            'Connection: Upgrade\r\n' +
            `Sec-WebSocket-Key: ${key}\r\n` +
            'Sec-WebSocket-Version: 13\r\n' +
            '\r\n',
        );
      });
      let buf = Buffer.alloc(0);
      socket.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        const headerEnd = buf.indexOf('\r\n\r\n');
        if (headerEnd === -1) return;
        const header = buf.slice(0, headerEnd).toString('utf8');
        const statusMatch = header.match(/HTTP\/1\.1 (\d+)/);
        if (!statusMatch) return;
        const status = Number(statusMatch[1]);
        if (status !== 101) {
          socket.destroy();
          finish(null, new Error(`Expected 101, got ${status}`));
          return;
        }
        socket._wsTrailing = buf.slice(headerEnd + 4);
        finish(socket);
      });
      socket.on('error', (err) => finish(null, err));
    });
  }

  function encodeWsText(payload) {
    const data = Buffer.from(JSON.stringify(payload), 'utf8');
    const len = data.length;
    let header;
    if (len < 126) {
      header = Buffer.alloc(2);
      header[0] = 0x81;
      header[1] = len | 0x80;
    } else {
      header = Buffer.alloc(4);
      header[0] = 0x81;
      header[1] = 126 | 0x80;
      header.writeUInt16BE(len, 2);
    }
    const mask = crypto.randomBytes(4);
    const masked = Buffer.alloc(len);
    for (let i = 0; i < len; i++) masked[i] = data[i] ^ mask[i & 3];
    return Buffer.concat([header, mask, masked]);
  }

  function readWsMessages(socket, timeoutMs = 1000) {
    return new Promise((resolve, reject) => {
      const messages = [];
      let settled = false;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.removeAllListeners('data');
        socket.removeAllListeners('close');
        socket.removeAllListeners('error');
        resolve(value);
      };
      const timer = setTimeout(() => finish(messages), timeoutMs);
      let buf = socket._wsTrailing || Buffer.alloc(0);
      delete socket._wsTrailing;
      function processBuffer() {
        while (buf.length >= 2) {
          const opcode = buf[0] & 0x0f;
          const masked = (buf[1] & 0x80) !== 0;
          let payloadLen = buf[1] & 0x7f;
          let offset = 2;
          if (payloadLen === 126) {
            if (buf.length < 4) return;
            payloadLen = buf.readUInt16BE(2);
            offset = 4;
          } else if (payloadLen === 127) {
            if (buf.length < 10) return;
            payloadLen = buf.readUInt32BE(6);
            offset = 10;
          }
          const total = offset + (masked ? 4 : 0) + payloadLen;
          if (buf.length < total) return;
          let payload = buf.slice(offset + (masked ? 4 : 0), total);
          if (masked) {
            const maskKey = buf.slice(offset, offset + 4);
            const out = Buffer.alloc(payloadLen);
            for (let i = 0; i < payloadLen; i++) out[i] = payload[i] ^ maskKey[i & 3];
            payload = out;
          }
          if (opcode === 0x1) {
            try {
              messages.push(JSON.parse(payload.toString('utf8')));
            } catch {
              /* ignore malformed JSON */
            }
          }
          buf = buf.slice(total);
        }
      }
      processBuffer();
      socket.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        processBuffer();
      });
      socket.on('error', reject);
      socket.on('close', () => finish(messages));
    });
  }

  test('join with protocolVersion echoes it back', async () => {
    const socket = await wsHandshake();
    await readWsMessages(socket, 200);
    socket.write(encodeWsText({ type: 'join', channel: 'proto-room', protocolVersion: 'v2' }));
    const msgs = await readWsMessages(socket, 500);
    const joined = msgs.find((m) => m && m.type === 'joined');
    expect(joined).toBeTruthy();
    expect(joined.protocolVersion).toBe('v2');
    socket.destroy();
  });

  test('relay preserves sourceNodeId', async () => {
    const s1 = await wsHandshake();
    const s2 = await wsHandshake();
    await readWsMessages(s1, 200);
    await readWsMessages(s2, 200);
    s1.write(encodeWsText({ type: 'join', channel: 'relay-room' }));
    s2.write(encodeWsText({ type: 'join', channel: 'relay-room' }));
    await readWsMessages(s1, 300);
    await readWsMessages(s2, 300);

    s1.write(encodeWsText({ type: 'ping', value: 7 }));
    const msgs = await readWsMessages(s2, 500);
    const relayed = msgs.find((m) => m && m.type === 'ping');
    expect(relayed).toBeTruthy();
    expect(relayed.sourceNodeId).toBeTruthy();
    expect(relayed.value).toBe(7);
    s1.destroy();
    s2.destroy();
  });

  test('permission-request is routed only to target node', async () => {
    const s1 = await wsHandshake();
    const s2 = await wsHandshake();
    const s3 = await wsHandshake();
    await readWsMessages(s1, 200);
    await readWsMessages(s2, 200);
    await readWsMessages(s3, 200);

    s1.write(encodeWsText({ type: 'join', channel: 'perm-room' }));
    const msgs1 = await readWsMessages(s1, 400);
    const joined1 = msgs1.find((m) => m.type === 'joined');
    expect(joined1).toBeTruthy();

    s2.write(encodeWsText({ type: 'join', channel: 'perm-room' }));
    const msgs2 = await readWsMessages(s2, 400);
    const joined2 = msgs2.find((m) => m.type === 'joined');
    expect(joined2).toBeTruthy();

    s3.write(encodeWsText({ type: 'join', channel: 'perm-room' }));

    s1.write(
      encodeWsText({
        type: 'permission-request',
        requestId: 'r1',
        targetNodeId: joined2.id,
        requestedBy: joined1.id,
      }),
    );

    const s2Msgs = await readWsMessages(s2, 500);
    const s3Msgs = await readWsMessages(s3, 500);
    expect(s2Msgs.some((m) => m.type === 'permission-request')).toBe(true);
    expect(s3Msgs.some((m) => m.type === 'permission-request')).toBe(false);

    s1.destroy();
    s2.destroy();
    s3.destroy();
  });
});
