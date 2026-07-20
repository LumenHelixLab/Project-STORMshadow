'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 4173;
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

// Allowed origins for WebSocket upgrade. Empty means no origin check.
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

// Content-Security-Policy for the static file server.
const CSP_HEADER =
  process.env.CSP ||
  "default-src 'self'; " +
    "connect-src 'self' ws: wss:; " +
    "img-src 'self' data: blob:; " +
    "media-src 'self' https:; " +
    "script-src 'self'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "frame-ancestors 'none'; " +
    "base-uri 'self';";

// Resolved base directories used to prevent path-traversal in the file server.
const STATIC_ROOT = path.resolve(__dirname, 'public');
const PROTOCOL_ROOT = path.resolve(__dirname, 'protocol');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.mp3': 'audio/mpeg',
  '.ogg': 'audio/ogg',
  '.wav': 'audio/wav',
};

const CACHE_MAX_AGE = 60; // seconds for static assets

// In-process per-IP rate limiter for WebSocket messages.
// Production deployments should replace this with a shared store (Redis/etc.)
const RATE_WINDOW_MS = Number(process.env.RATE_WINDOW_MS) || 1000;
const RATE_MAX_PER_WINDOW = Number(process.env.RATE_MAX_PER_WINDOW) || 120;
const WS_MAX_PAYLOAD_BYTES = Number(process.env.WS_MAX_PAYLOAD_BYTES) || 1024 * 1024; // 1 MiB

/** @type {Map<string, number[]>} */
const rateBuckets = new Map();

/**
 * Simple per-IP rate limit check. Mutates buckets in place.
 * @param {string} ip
 * @returns {boolean} true if within limit
 */
function isUnderRateLimit(ip) {
  const now = Date.now();
  const windowStart = now - RATE_WINDOW_MS;
  let stamps = rateBuckets.get(ip);
  if (!stamps) {
    stamps = [];
    rateBuckets.set(ip, stamps);
  }
  // Drop old timestamps
  while (stamps.length && stamps[0] <= windowStart) stamps.shift();
  if (stamps.length >= RATE_MAX_PER_WINDOW) return false;
  stamps.push(now);
  return true;
}

/** Zero-dependency structured logger. */
const logger = {
  info: (msg, meta) =>
    console.log(
      JSON.stringify(
        Object.assign({ level: 'info', msg, time: new Date().toISOString() }, meta || {}),
      ),
    ),
  warn: (msg, meta) =>
    console.warn(
      JSON.stringify(
        Object.assign({ level: 'warn', msg, time: new Date().toISOString() }, meta || {}),
      ),
    ),
  error: (msg, meta) =>
    console.error(
      JSON.stringify(
        Object.assign({ level: 'error', msg, time: new Date().toISOString() }, meta || {}),
      ),
    ),
  debug: (msg, meta) => {
    if (process.env.DEBUG) {
      console.debug(
        JSON.stringify(
          Object.assign({ level: 'debug', msg, time: new Date().toISOString() }, meta || {}),
        ),
      );
    }
  },
};

/**
 * Get client IP from request/socket, preferring x-forwarded-for only if trusted.
 * @param {http.IncomingMessage} req
 * @returns {string}
 */
function clientIp(req) {
  if (process.env.TRUST_PROXY) {
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string') {
      return xff.split(',')[0].trim();
    }
  }
  return req.socket?.remoteAddress || 'unknown';
}

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
    header.writeUInt32BE(0, 2); // high 32 bits (zero for payloads < 4 GB)
    header.writeUInt32BE(len, 6); // low  32 bits
  }

  return Buffer.concat([header, data]);
}

/**
 * Decode one or more WebSocket frames from a Buffer.
 * Browsers always mask frames sent to the server.
 * Returns decoded text messages (parsed JSON) and any incomplete trailing bytes.
 * Enforces a maximum payload size to avoid unbounded memory use.
 * @param {Buffer} buffer
 * @param {number} maxPayloadBytes
 * @returns {{ messages: unknown[], controls: string[], remaining: Buffer, error?: string }}
 */
function decodeFrames(buffer, maxPayloadBytes) {
  const messages = [];
  const controls = [];
  let remaining = buffer;

  while (remaining.length >= 2) {
    const firstByte = remaining[0];
    const secondByte = remaining[1];
    const opcode = firstByte & 0x0f;
    const masked = (secondByte & 0x80) !== 0;
    let payloadLen = secondByte & 0x7f;
    let offset = 2;

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

    if (payloadLen > maxPayloadBytes) {
      return { messages, controls, remaining: Buffer.alloc(0), error: 'payload_too_large' };
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
      } catch (err) {
        logger.debug('Malformed JSON WebSocket frame', { error: err.message });
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
  const ip = clientIp(req);
  if (!isUnderRateLimit(ip)) {
    socket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n');
    socket.destroy();
    return;
  }

  // Origin validation for WebSocket connections
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.length && (!origin || !ALLOWED_ORIGINS.includes(origin))) {
    logger.warn('WebSocket upgrade rejected due to origin', { origin, ip });
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }

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

  const id = randomNodeId();
  const meta = { id, channel: 'semantic-lab', ip };
  clients.set(socket, meta);

  logger.info('websocket client connected', { id, channel: meta.channel, ip });

  // Send hello immediately
  sendToSocket(socket, { type: 'hello', id, at: Date.now() });

  let buf = Buffer.alloc(0);

  socket.on('data', (chunk) => {
    if (!isUnderRateLimit(ip)) {
      logger.warn('WebSocket rate limit exceeded', { id, ip });
      sendToSocket(socket, { type: 'error', reason: 'rate_limited' });
      clients.delete(socket);
      try {
        socket.write(Buffer.from([0x88, 0x00]));
      } catch {
        /* socket may already be closed */
      }
      socket.destroy();
      return;
    }

    buf = Buffer.concat([buf, chunk]);
    const { messages, controls, remaining, error } = decodeFrames(buf, WS_MAX_PAYLOAD_BYTES);

    if (error === 'payload_too_large') {
      logger.warn('WebSocket payload too large', { id, ip });
      sendToSocket(socket, { type: 'error', reason: 'payload_too_large' });
      clients.delete(socket);
      try {
        socket.write(Buffer.from([0x88, 0x00]));
      } catch {
        /* socket may already be closed */
      }
      socket.destroy();
      return;
    }

    buf = remaining;

    // Handle close frame
    if (controls.includes('close')) {
      clients.delete(socket);
      // Best-effort: send the RFC 6455 close acknowledgement frame.
      // The write may fail if the peer already closed the TCP connection, which is safe to ignore.
      try {
        socket.write(Buffer.from([0x88, 0x00]));
      } catch {
        /* socket may already be closed */
      }
      socket.destroy();
      return;
    }

    for (const msg of messages) {
      if (!msg || typeof msg !== 'object') continue;

      if (msg.type === 'join') {
        // Client selects a relay channel
        const requested =
          typeof msg.channel === 'string' && msg.channel.trim()
            ? msg.channel.trim()
            : 'semantic-lab';
        logger.info('client joined channel', { id, from: meta.channel, to: requested, ip });
        meta.channel = requested;
        meta.protocolVersion = msg.protocolVersion || 'v1';
        sendToSocket(socket, {
          type: 'joined',
          channel: meta.channel,
          id: meta.id,
          protocolVersion: meta.protocolVersion,
          at: Date.now(),
        });
      } else if (msg.type === 'permission-request' || msg.type === 'permission-response') {
        // Relay permission messages only to the intended target node on the same channel
        const outgoing = Object.assign({}, msg, {
          sourceNodeId: meta.id,
          channel: meta.channel,
          relayedAt: Date.now(),
        });
        for (const [peer, peerMeta] of clients) {
          if (
            peer !== socket &&
            peerMeta.channel === meta.channel &&
            peerMeta.id === msg.targetNodeId
          ) {
            sendToSocket(peer, outgoing);
          }
        }
      } else {
        // Relay all other packets to every peer on the same channel
        const outgoing = Object.assign({}, msg, {
          sourceNodeId: meta.id,
          channel: meta.channel,
          relayedAt: Date.now(),
        });
        for (const [peer, peerMeta] of clients) {
          if (peer !== socket && peerMeta.channel === meta.channel) {
            sendToSocket(peer, outgoing);
          }
        }
      }
    }
  });

  const cleanup = () => {
    if (clients.has(socket)) {
      logger.info('websocket client disconnected', { id, channel: meta.channel, ip });
      clients.delete(socket);
    }
  };
  socket.on('close', cleanup);
  socket.on('error', (err) => {
    logger.debug('websocket socket error', { id, error: err.message });
    cleanup();
  });
}

// ─── Static file server ──────────────────────────────────────────────────────

/**
 * Respond to OPTIONS/HEAD for a validated file path.
 * @param {string} filePath
 * @param {http.ServerResponse} res
 * @param {string} contentType
 * @param {fs.Stats} stats
 * @param {string} method
 */
function serveMetadata(filePath, res, contentType, stats, method) {
  const headers = {
    'Content-Type': contentType,
    'Content-Length': stats.size.toString(),
    'Cache-Control': `public, max-age=${CACHE_MAX_AGE}`,
    'Accept-Ranges': 'bytes',
    'Last-Modified': stats.mtime.toUTCString(),
    ETag: `"${stats.mtime.getTime().toString(36)}-${stats.size.toString(36)}"`,
  };
  res.writeHead(200, headers);
  if (method === 'HEAD') res.end();
  else res.end();
}

/**
 * Parse a Range header for a given file size. Returns null if unsatisfiable or not a simple byte range.
 * @param {string|undefined} rangeHeader
 * @param {number} totalSize
 * @returns {{ start: number, end: number, length: number } | null}
 */
function parseRange(rangeHeader, totalSize) {
  if (!rangeHeader || !rangeHeader.startsWith('bytes=')) return null;
  const spec = rangeHeader.slice(6).split(',')[0].trim();
  if (spec.startsWith('-')) {
    const suffix = Number(spec.slice(1));
    if (!Number.isFinite(suffix) || suffix <= 0) return null;
    const start = Math.max(0, totalSize - suffix);
    return { start, end: totalSize - 1, length: totalSize - start };
  }
  const parts = spec.split('-');
  if (parts.length !== 2) return null;
  const start = Number(parts[0]);
  let end = parts[1] === '' ? totalSize - 1 : Number(parts[1]);
  if (!Number.isFinite(start) || start < 0 || start >= totalSize) return null;
  if (!Number.isFinite(end) || end < start || end >= totalSize) return null;
  return { start, end, length: end - start + 1 };
}

const server = http.createServer((req, res) => {
  const method = req.method || 'GET';

  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
      'Access-Control-Max-Age': '86400',
    });
    res.end();
    return;
  }

  if (method !== 'GET' && method !== 'HEAD') {
    res.writeHead(405, { 'Content-Type': 'text/plain', Allow: 'GET, HEAD, OPTIONS' });
    res.end('Method not allowed');
    return;
  }

  let urlPath = (req.url || '/').split('?')[0];
  if (urlPath === '/') urlPath = '/index.html';

  // Early rejection of any URL containing path-traversal sequences before
  // the path is resolved.  This covers both decoded ('..') and percent-encoded
  // ('%2e%2e') forms after Node's built-in URL normalization.
  if (urlPath.includes('..')) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('Bad request');
    return;
  }

  // Resolve the file path within an allowed base directory.
  // Protocol schema files live in /protocol/; everything else in public/.
  // The boundary check is a secondary defence-in-depth guard.
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

  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
      return;
    }

    const range = parseRange(req.headers.range, stats.size);

    // If method is HEAD or no range requested, serve full metadata/contents.
    if (method === 'HEAD' || !range) {
      if (method === 'HEAD') {
        serveMetadata(filePath, res, contentType, stats, method);
        return;
      }

      const headers = {
        'Content-Type': contentType,
        'Content-Length': stats.size.toString(),
        'Cache-Control': `public, max-age=${CACHE_MAX_AGE}`,
        'Accept-Ranges': 'bytes',
        'Last-Modified': stats.mtime.toUTCString(),
        ETag: `"${stats.mtime.getTime().toString(36)}-${stats.size.toString(36)}"`,
        'Content-Security-Policy': CSP_HEADER,
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      };
      res.writeHead(200, headers);
      const stream = fs.createReadStream(filePath);
      stream.on('error', (streamErr) => {
        logger.error('static file stream error', { path: filePath, error: streamErr.message });
        if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Internal server error');
      });
      stream.pipe(res);
      return;
    }

    // Partial content (Range request)
    const headers = {
      'Content-Type': contentType,
      'Content-Length': range.length.toString(),
      'Content-Range': `bytes ${range.start}-${range.end}/${stats.size}`,
      'Cache-Control': `public, max-age=${CACHE_MAX_AGE}`,
      'Accept-Ranges': 'bytes',
    };
    res.writeHead(206, headers);
    const stream = fs.createReadStream(filePath, { start: range.start, end: range.end });
    stream.on('error', (streamErr) => {
      logger.error('static file range stream error', { path: filePath, error: streamErr.message });
      if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Internal server error');
    });
    stream.pipe(res);
  });
});

server.on('upgrade', (req, socket, _head) => {
  if (req.url === '/ws') {
    handleUpgrade(req, socket);
  } else {
    socket.destroy();
  }
});

// Only start listening when this file is the entry point, so tests can import
// the server without binding a port.
if (require.main === module) {
  server.listen(PORT, () => {
    logger.info('SemBro server started', { port: PORT, url: `http://localhost:${PORT}` });
  });
}

module.exports = { server, clients, logger };
