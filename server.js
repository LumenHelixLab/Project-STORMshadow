'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 4173;
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

// Resolved base directories used to prevent path-traversal in the file server.
const STATIC_ROOT   = path.resolve(__dirname, 'public');
const PROTOCOL_ROOT = path.resolve(__dirname, 'protocol');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'text/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg':  'image/svg+xml',
};

// Map<socket, { id: string, channel: string }>
const clients = new Map();

// ─── WebSocket frame encoding ────────────────────────────────────────────────

/**
 * Encode a JS value as a masked-free WebSocket text frame (server → client).
 * Supports small (<126 B), medium (126–65 535 B) and large (≥65 536 B) payloads.
 * @param {unknown} payload
 * @returns {Buffer}
 */
function encodeFrame(payload) {
  const data = Buffer.from(JSON.stringify(payload), 'utf8');
  const len = data.length;

  let header;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[0] = 0x81; // FIN + opcode text (0x1)
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 127;
    header.writeUInt32BE(0, 2);   // high 32 bits (zero for payloads < 4 GB)
    header.writeUInt32BE(len, 6); // low  32 bits
  }

  return Buffer.concat([header, data]);
}

/**
 * Decode one or more WebSocket frames from a Buffer.
 * Browsers always mask frames sent to the server.
 * Returns decoded text messages (parsed JSON) and any incomplete trailing bytes.
 * @param {Buffer} buffer
 * @returns {{ messages: unknown[], controls: string[], remaining: Buffer }}
 */
function decodeFrames(buffer) {
  const messages = [];
  const controls = [];
  let remaining = buffer;

  while (remaining.length >= 2) {
    const firstByte  = remaining[0];
    const secondByte = remaining[1];
    const opcode     = firstByte & 0x0f;
    const masked     = (secondByte & 0x80) !== 0;
    let payloadLen   = secondByte & 0x7f;
    let offset       = 2;

    if (payloadLen === 126) {
      if (remaining.length < 4) break;
      payloadLen = remaining.readUInt16BE(2);
      offset = 4;
    } else if (payloadLen === 127) {
      if (remaining.length < 10) break;
      // Ignore high 32 bits; sufficient for payloads < 4 GB.
      payloadLen = remaining.readUInt32BE(6);
      offset = 10;
    }

    const maskBytes = masked ? 4 : 0;
    const totalSize = offset + maskBytes + payloadLen;
    if (remaining.length < totalSize) break;

    let payload;
    if (masked) {
      const maskKey = remaining.slice(offset, offset + 4);
      payload = Buffer.alloc(payloadLen);
      for (let i = 0; i < payloadLen; i++) {
        payload[i] = remaining[offset + 4 + i] ^ maskKey[i & 3];
      }
    } else {
      payload = remaining.slice(offset, offset + payloadLen);
    }

    if (opcode === 0x1) {
      // Text frame — parse as JSON
      try {
        messages.push(JSON.parse(payload.toString('utf8')));
      } catch (_) {
        // malformed JSON — drop silently
      }
    } else if (opcode === 0x8) {
      // Connection-close frame
      controls.push('close');
    }
    // Pings, pongs, and binary frames are intentionally ignored.

    remaining = remaining.slice(totalSize);
  }

  return { messages, controls, remaining };
}

// ─── WebSocket helpers ───────────────────────────────────────────────────────

function randomNodeId() {
  return 'node-' + crypto.randomBytes(3).toString('hex');
}

function sendToSocket(socket, payload) {
  try {
    socket.write(encodeFrame(payload));
  } catch (_) {
    // socket may already be closed
  }
}

// ─── WebSocket upgrade handler ───────────────────────────────────────────────

function handleUpgrade(req, socket) {
  const key = req.headers['sec-websocket-key'];
  if (!key) {
    socket.destroy();
    return;
  }

  // RFC 6455 §1.3 handshake
  const acceptKey = crypto
    .createHash('sha1')
    .update(key + WS_GUID)
    .digest('base64');

  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${acceptKey}\r\n` +
    '\r\n',
  );

  const id   = randomNodeId();
  const meta = { id, channel: 'semantic-lab' };
  clients.set(socket, meta);

  // Send hello immediately
  sendToSocket(socket, { type: 'hello', id, at: Date.now() });

  let buf = Buffer.alloc(0);

  socket.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    const { messages, controls, remaining } = decodeFrames(buf);
    buf = remaining;

    // Handle close frame
    if (controls.includes('close')) {
      clients.delete(socket);
      // Best-effort: send the RFC 6455 close acknowledgement frame.
      // The write may fail if the peer already closed the TCP connection, which is safe to ignore.
      try { socket.write(Buffer.from([0x88, 0x00])); } catch (_) {}
      socket.destroy();
      return;
    }

    for (const msg of messages) {
      if (!msg || typeof msg !== 'object') continue;

      if (msg.type === 'join') {
        // Client selects a relay channel
        meta.channel = (typeof msg.channel === 'string' && msg.channel.trim())
          ? msg.channel.trim()
          : 'semantic-lab';
        sendToSocket(socket, {
          type:    'joined',
          channel: meta.channel,
          id:      meta.id,
          at:      Date.now(),
        });
      } else {
        // Relay all other packets to every peer on the same channel
        const outgoing = Object.assign({}, msg, {
          sourceNodeId: meta.id,
          channel:      meta.channel,
          relayedAt:    Date.now(),
        });
        for (const [peer, peerMeta] of clients) {
          if (peer !== socket && peerMeta.channel === meta.channel) {
            sendToSocket(peer, outgoing);
          }
        }
      }
    }
  });

  const cleanup = () => clients.delete(socket);
  socket.on('close', cleanup);
  socket.on('error', cleanup);
}

// ─── Static file server ──────────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  let urlPath = (req.url || '/').split('?')[0];
  if (urlPath === '/') urlPath = '/index.html';

  // Resolve the file path and guard against path-traversal attacks.
  // Protocol schema files live in /protocol/; everything else in public/.
  let filePath;
  if (urlPath.startsWith('/protocol/')) {
    const rel = urlPath.slice('/protocol/'.length);
    filePath = path.resolve(PROTOCOL_ROOT, rel);
    if (!filePath.startsWith(PROTOCOL_ROOT + path.sep) && filePath !== PROTOCOL_ROOT) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Bad request');
      return;
    }
  } else {
    const rel = urlPath.startsWith('/') ? urlPath.slice(1) : urlPath;
    filePath = path.resolve(STATIC_ROOT, rel);
    if (!filePath.startsWith(STATIC_ROOT + path.sep) && filePath !== STATIC_ROOT) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Bad request');
      return;
    }
  }

  const ext         = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  // filePath has been validated to be within STATIC_ROOT or PROTOCOL_ROOT above.
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
});

server.on('upgrade', (req, socket, _head) => {
  if (req.url === '/ws') {
    handleUpgrade(req, socket);
  } else {
    socket.destroy();
  }
});

server.listen(PORT, () => {
  console.log(`SemBro server running at http://localhost:${PORT}`);
});
