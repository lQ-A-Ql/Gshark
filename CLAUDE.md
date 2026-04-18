# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GShark-Sentinel is a desktop offline traffic analysis tool (PCAP/PCAPNG) built with:
- **Desktop shell**: Go 1.22 + Wails v2 (root module: `github.com/gshark/sentinel/desktop`)
- **Backend**: Go 1.25 HTTP/SSE server (module: `github.com/gshark/sentinel/backend`)
- **Frontend**: React 18 + TypeScript + Vite + Tailwind CSS v4
- Go workspace (`go.work`) links both modules; workspace requires Go 1.25

## Commands

### Running in Development

```powershell
# Desktop-only development entry
./scripts/start-dev.ps1

# Direct Wails development mode
./scripts/start-wails-dev.ps1
```

Both scripts kill processes on ports 34115/17891 before starting.

### Testing

```bash
# Backend tests
cd backend && go test ./...

# Single backend test
cd backend && go test ./internal/engine/... -run TestName

# Frontend tests (single run, no watch — uses Vitest)
cd frontend && pnpm run test

# Frontend tests in watch mode
cd frontend && npx vitest

# Full validation pipeline (go test, gofmt, vitest, frontend build)
./scripts/check-all.ps1
```

### Building

```bash
# Desktop asset build (vite build + copies backend binary)
cd frontend && pnpm run build:wails

# Desktop app
wails build

# Build tags: use -tags dev to disable self-update, -tags production to enable it
wails build -tags dev
```

### Linting

```bash
# Backend format check
cd backend && gofmt -l .

# Fix formatting
cd backend && gofmt -w .
```

## Architecture

### Communication Flow

```
Wails Desktop Shell (app.go)
  └─ spawns ──> Backend HTTP server (127.0.0.1:17891)
                  └─ auth via GSHARK_BACKEND_TOKEN env var
Frontend (React) ──HTTP/SSE──> Backend
```

The desktop shell (`app.go`) manages the backend process lifecycle, generates an auth token, and exposes file dialog methods to the frontend via Wails bindings.

### Backend (`/backend`)

Entry point: `cmd/sentinel/main.go` — two modes:
- `serve [addr]` — HTTP server mode (default `127.0.0.1:17891`)
- `parse <file.pcapng> [filter]` — CLI mode

Key packages:
- `internal/engine` — core analysis: packet store, stream reassembly, display filters, threat hunting, YARA matching. `service.go` is the central Service struct (~1800 lines) managing stream cache (LRU 256), display filter cache (LRU 16), plugin manager, YARA config.
- `internal/transport` — HTTP/SSE server and event hub (~1400 lines, 40+ REST endpoints). Bearer token auth + audit logging middleware.
- `internal/tshark` — tshark CLI wrapper, industrial protocol parsers (Modbus, S7comm, DNP3, CIP, PROFINET, BACnet, IEC 104, OPC UA), automotive parsers (CAN, J1939, DoIP, UDS, OBD-II, CANopen, DBC)
- `internal/plugin` — plugin discovery and JS (goja VM) / Python (subprocess IPC) runtime execution
- `internal/model` — shared types (Packet, ParseOptions, etc.)

Key engine behaviors:
- **PCAP loading** uses a 3-tier tshark parsing fallback: `fast_list` → `ek` → `compat_fields`
- **Stream reassembly** falls back through: memory → index → file
- **Threat hunting** runs prefix matching + plugins + YARA + steganography detection

### Frontend (`/frontend/src/app`)

- `App.tsx` / `routes.tsx` — root and 16 lazy-loaded routes (react-router v7)
- `core/types.ts` — TypeScript interfaces mirroring backend model types
- `core/engine.ts` — protocol tree and hex dump builders
- `integrations/wailsBridge.ts` — backend API client implementing `BackendBridge` interface; HTTP with Bearer auth; Wails desktop bindings; SSE subscriptions with exponential backoff reconnect
- `state/SentinelContext.tsx` — `SentinelProvider` managing global state (packets, streams, plugins, threat analysis); `PAGE_SIZE = 2000`; use `useSentinel()` hook
- `pages/` — one file per feature: Workspace, HttpStream, TcpStream, UdpStream, ThreatHunting, Objects, IndustrialAnalysis, VehicleAnalysis, MediaAnalysis, UsbAnalysis, etc.
- `components/ui/` — shadcn/ui Radix-based components

Notable deps: `@monaco-editor/react`, `recharts`, `react-resizable-panels`, `react-dnd`

### Plugin System

Plugins live in `backend/plugins/rules/`. Each plugin is a pair:
- `<id>.json` — metadata (id, name, version, runtime, capabilities, enabled)
- `<id>.js` or `<id>.py` — logic

JS plugins: `onPacket(packet, ctx)` + optional `onFinish(ctx)`; executed via goja VM
Python plugins: stdin/stdout JSON line protocol
Plugins run during threat hunting. See `docs/plugin-interface.md` for the plugin API spec.

### Data Flow

1. Load PCAP → tshark parses → packets streamed to frontend via SSE
2. Display filters applied in `internal/engine/filter.go`
3. Stream reassembly on demand (`stream_decoder.go`)
4. Threat hunting runs plugins + YARA rules (`threat_hunt_stream.go`, `yara_batch.go`)
5. Object extraction and export (`object_mapping.go`)
