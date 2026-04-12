# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GShark-Sentinel is a desktop offline traffic analysis tool (PCAP/PCAPNG) built with:
- **Desktop shell**: Go + Wails v2 (root module: `github.com/gshark/sentinel/desktop`)
- **Backend**: Go 1.22 HTTP/SSE server (module: `github.com/gshark/sentinel/backend`)
- **Frontend**: React 18 + TypeScript + Vite + Tailwind CSS

## Commands

### Running in Development

```powershell
# Desktop-only development entry
./scripts/start-dev.ps1

# Direct Wails development mode
./scripts/start-wails-dev.ps1
```

### Testing

```bash
# Backend tests
cd backend && go test ./...

# Single backend test
cd backend && go test ./internal/engine/... -run TestName

# Frontend tests (single run, no watch)
cd frontend && npm run test -- --run

# Full validation pipeline
./scripts/check-all.ps1
```

### Building

```bash
# Desktop asset build
cd frontend && pnpm run build:wails

# Desktop app
wails build
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
- `internal/engine` — core analysis: packet store, stream reassembly, display filters, threat hunting, YARA matching
- `internal/transport` — HTTP/SSE server and event hub (status/error/packet events)
- `internal/tshark` — tshark invocation, industrial protocol parsers (Modbus, S7comm, DNP3, CIP, PROFINET, BACnet, IEC 104, OPC UA), automotive parsers (CAN, J1939, DoIP, UDS, OBD-II, CANopen, DBC)
- `internal/plugin` — plugin discovery and JS/Python runtime execution
- `internal/model` — shared types (Packet, ParseOptions, etc.)

### Frontend (`/frontend/src/app`)

- `App.tsx` / `routes.tsx` — root and routing
- `core/` — engine client, packet types, coloring rules
- `pages/` — one file per feature: `Workspace.tsx` (main view), `HttpStream.tsx`, `TcpStream.tsx`, `ThreatHunting.tsx`, `IndustrialAnalysis.tsx`, `VehicleAnalysis.tsx`, etc.
- `state/` — shared state management
- `components/` — reusable UI components

### Plugin System

Plugins live in `backend/plugins/rules/`. Each plugin is a pair:
- `<id>.json` — metadata/config
- `<id>.js` or `<id>.py` — logic (JavaScript via goja, or Python)

Plugins run during threat hunting. See `docs/plugin-interface.md` for the plugin API spec.

### Data Flow

1. Load PCAP → tshark parses → packets streamed to frontend via SSE
2. Display filters applied in `internal/engine/filter.go`
3. Stream reassembly on demand (`stream_decoder.go`)
4. Threat hunting runs plugins + YARA rules (`threat_hunt_stream.go`, `yara_batch.go`)
5. Object extraction and export (`object_mapping.go`)
