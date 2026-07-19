# Project-SemBro

**NUMO Semantic Browser** — a WebSocket proof-of-concept that transmits *page structure*, not pixels.

Instead of streaming screenshots or video frames, the source browser captures the visible page as structured JSON (element roles, text, bounding boxes, interaction flags, media URLs) and relays it over WebSocket. A receiver browser reconstructs a lightweight thin-client view locally — no pixel stream, no video codec.

## Quick start

```bash
node server.js
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
| `protocol/semantic-frame-v1.schema.json` | JSON Schema for the `semantic-frame-v1` wire format |
| `package.json` | Project name and start scripts (no runtime npm dependencies) |

## How it works

```
Source DOM → captureSemanticFrame() → JSON over WebSocket → server relays → renderFrame() → thin client UI
```

The core idea: send *meaning*, not pixels.

- The **source** reads DOM nodes, extracts roles / text / bounds / media metadata, and sends a compact JSON frame.
- The **server** relays frames between tabs on the same channel with no external WebSocket library.
- The **receiver** renders absolutely-positioned native elements scaled to fit, including native `<video>` / `<audio>` players for media.

See the problem-statement document for the full architecture description.

## Notes

- The source page fixture includes a `<video>` element that loads a sample clip from `https://www.w3schools.com/html/mov_bbb.mp4` (a well-known public test file). If that URL is unavailable in your network environment the video element will show a blank player, but the semantic capture will still work — the element and its metadata are captured regardless of whether the media has loaded.
