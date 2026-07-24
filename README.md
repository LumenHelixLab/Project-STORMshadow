# Project-STORMshadow

**NUMO Semantic Browser** — a WebSocket proof-of-concept that transmits *page structure*, not pixels.

Instead of streaming screenshots or video frames, the source browser captures the visible page as structured JSON (element roles, text, bounding boxes, interaction flags, media URLs) and relays it over WebSocket. A receiver browser reconstructs a lightweight thin-client view locally — no pixel stream, no video codec.

## Quick start

```bash
npm install
npm start
# Server runs at http://localhost:4173
```

Open `http://localhost:4173` in **two browser tabs**.

| Tab | Setting |
|-----|---------|
| Tab 1 | Mode → **Source** · click **Connect** · click **Capture now** or **Auto on** |
| Tab 2 | Mode → **Receiver** · click **Connect** |

Both tabs must use the same **Channel** (default: `semantic-lab`). The receiver tab will reconstruct the source page's semantic elements as they arrive.

## File map

| File | Purpose |
|------|---------|
| `server.js` | Static file server + no-dependency WebSocket relay |
| `public/index.html` | Full browser app: capture engine, receiver renderer, controls, stats, wire inspector |
| `protocol/semantic-frame-v1.schema.json` | JSON Schema for the original `semantic-frame-v1` wire format |
| `protocol/semantic-frame-v2.schema.json` | JSON Schema for `semantic-frame-v2` with key/delta frames and checksums |
| `package.json` | Project scripts and dev dependencies (jest, eslint, prettier) |

## How it works

```
Source DOM → captureSemanticFrame() → JSON over WebSocket → server relays → renderFrame() → thin client UI
```

The core idea: send *meaning*, not pixels.

- The **source** reads DOM nodes, extracts roles / text / bounds / media metadata, and sends a compact JSON frame.
- The **server** relays frames between tabs on the same channel with no external WebSocket library.
- The **receiver** renders absolutely-positioned native elements scaled to fit, including native `<video>` / `<audio>` players for media.

## Implemented milestones

1. **Foundation Hardening** — `HEAD`/`OPTIONS`, `Range`, caching headers, WebSocket rate limiting, structured logging, smoke tests.
2. **Protocol v2** — key/delta frames, `removedIds`, SHA-256 checksums, protocol version negotiation.
3. **Capture Engine Upgrade** — `MutationObserver`, computed styles, focus/hover state, semantic grouping.
4. **Receiver Renderer Upgrade** — layered renderer, quality levels, native controls, reduced-motion support.
5. **Bi-Directional Input Relay** — click/scroll/keyboard replay, permission handshake, remote cursor.
6. **Security & Privacy** — optional AES-GCM E2EE, CSP/security headers, origin validation, PII redaction, password omission.
7. **Tooling** — ESLint, Prettier, Jest tests, protocol v2 tests.

## Development commands

```bash
npm test       # run Jest tests
npm run lint   # run ESLint
npm run format # run Prettier
```

## Notes

- The source page fixture includes a `<video>` element that loads a sample clip from `https://www.w3schools.com/html/mov_bbb.mp4` (a well-known public test file). If that URL is unavailable in your network environment the video element will show a blank player, but the semantic capture will still work — the element and its metadata are captured regardless of whether the media has loaded.
