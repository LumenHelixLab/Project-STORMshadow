'use strict';

const http = require('http');
const net = require('net');
const crypto = require('crypto');
const { server } = require('../server.js');

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

let baseUrl;

beforeAll((done) => {
  server.listen(0, '127.0.0.1', () => {
    const { port } = server.address();
    baseUrl = `http://127.0.0.1:${port}`;
    done();
  });
});

afterAll(async () => {
  await new Promise((resolve) => {
    server.close(resolve);
    // Force resolve if close hangs on open keep-alive/WebSocket sockets.
    setTimeout(resolve, 1000);
  });
});

function request(method, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(`${baseUrl}${path}`, { method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks),
        });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

describe('static file server', () => {
  test('GET / returns index.html', async () => {
    const res = await request('GET', '/');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/html/);
    expect(res.body.length).toBeGreaterThan(0);
    expect(Number(res.headers['content-length'])).toBe(res.body.length);
    expect(res.headers['cache-control']).toMatch(/max-age=/);
  });

  test('HEAD / returns headers without body', async () => {
    const res = await request('HEAD', '/');
    expect(res.status).toBe(200);
    expect(res.body.length).toBe(0);
    expect(Number(res.headers['content-length'])).toBeGreaterThan(0);
  });

  test('OPTIONS / returns allowed methods', async () => {
    const res = await request('OPTIONS', '/');
    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-methods']).toMatch(/GET/);
  });

  test('POST / is not allowed', async () => {
    const res = await request('POST', '/');
    expect(res.status).toBe(405);
  });

  test('GET /protocol/semantic-frame-v1.schema.json returns JSON', async () => {
    const res = await request('GET', '/protocol/semantic-frame-v1.schema.json');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/application\/json/);
    const json = JSON.parse(res.body.toString('utf8'));
    expect(json.$id).toBe('semantic-frame-v1');
  });

  test('GET /nonexistent returns 404', async () => {
    const res = await request('GET', '/nonexistent-file.html');
    expect(res.status).toBe(404);
  });

  test('GET /..%2fetc/passport traversal is rejected', async () => {
    const res = await request('GET', '/..%2fetc/passwd');
    expect(res.status).toBe(400);
  });

  test('Range request returns 206 partial content', async () => {
    const full = await request('GET', '/');
    const len = full.body.length;
    const res = await request('GET', '/', { Range: 'bytes=0-9' });
    expect(res.status).toBe(206);
    expect(res.body.length).toBe(10);
    expect(res.headers['content-range']).toBe(`bytes 0-9/${len}`);
  });
});

describe('websocket relay', () => {
  function wsHandshake() {
    return new Promise((resolve, reject) => {
      const key = crypto.randomBytes(16).toString('base64');
      const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
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
        expect(header).toContain(`Sec-WebSocket-Accept: ${accept}`);
        // Save any WebSocket frame bytes that arrived in the same segment as the handshake response.
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
    } else if (len < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x81;
      header[1] = 126 | 0x80;
      header.writeUInt16BE(len, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x81;
      header[1] = 127 | 0x80;
      header.writeUInt32BE(0, 2);
      header.writeUInt32BE(len, 6);
    }
    const mask = crypto.randomBytes(4);
    const masked = Buffer.alloc(len);
    for (let i = 0; i < len; i++) masked[i] = data[i] ^ mask[i & 3];
    return Buffer.concat([header, mask, masked]);
  }

  function readWsMessages(socket, timeoutMs = 2000) {
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
            const mask = buf.slice(offset, offset + 4);
            const out = Buffer.alloc(payloadLen);
            for (let i = 0; i < payloadLen; i++) out[i] = payload[i] ^ mask[i & 3];
            payload = out;
          }
          if (opcode === 0x1) {
            try { messages.push(JSON.parse(payload.toString('utf8'))); } catch (_) {}
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

  test('WebSocket upgrade on /ws succeeds and sends hello', async () => {
    const socket = await wsHandshake();
    const msgs = await readWsMessages(socket, 2000);
    expect(msgs.length).toBeGreaterThanOrEqual(1);
    expect(msgs[0].type).toBe('hello');
    expect(msgs[0].id).toMatch(/^node-/);
    socket.destroy();
  });

  test('join channel returns joined confirmation', async () => {
    const socket = await wsHandshake();
    await readWsMessages(socket, 300); // consume hello
    socket.write(encodeWsText({ type: 'join', channel: 'test-room' }));
    const msgs = await readWsMessages(socket, 500);
    const joined = msgs.find((m) => m && m.type === 'joined');
    expect(joined).toBeTruthy();
    expect(joined.channel).toBe('test-room');
    socket.destroy();
  });

  test('message is relayed between peers on same channel', async () => {
    const s1 = await wsHandshake();
    const s2 = await wsHandshake();
    await readWsMessages(s1, 300);
    await readWsMessages(s2, 300);
    s1.write(encodeWsText({ type: 'join', channel: 'relay-room' }));
    s2.write(encodeWsText({ type: 'join', channel: 'relay-room' }));
    await readWsMessages(s1, 300);
    await readWsMessages(s2, 300);

    s1.write(encodeWsText({ type: 'ping', n: 42 }));
    const s2Msgs = await readWsMessages(s2, 500);
    const relayed = s2Msgs.find((m) => m && m.type === 'ping');
    expect(relayed).toBeTruthy();
    expect(relayed.n).toBe(42);
    expect(relayed.sourceNodeId).toBeTruthy();
    s1.destroy();
    s2.destroy();
  });
});
