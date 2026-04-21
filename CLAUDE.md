# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GShark-Sentinel is a desktop-first offline traffic analysis tool for PCAP/PCAPNG.

- Desktop shell: Go + Wails (`github.com/gshark/sentinel/desktop`)
- Backend API/SSE service: Go (`github.com/gshark/sentinel/backend`)
- Frontend: React 18 + TypeScript + Vite + Tailwind CSS
- Parsing engine: tshark wrappers plus protocol-specific analyzers
- Go workspace: `go.work` ties root desktop module and `./backend` (workspace Go 1.25)

## Environment Notes

- Recommended development environment is Windows.
- Required tools: Go, Node.js 20+, `pnpm`, `tshark`, Wails CLI.
- Root module targets Go 1.22; backend/workspace targets Go 1.25.
- Development is desktop-only: start via Wails scripts, not separate frontend/backend web workflows.

## Common Commands

### Install frontend dependencies

```bash
cd frontend && pnpm install
```

### Development

```powershell
# Desktop development entry (delegates to Wails dev)
./scripts/start-dev.ps1

# Direct Wails dev mode
./scripts/start-wails-dev.ps1
```

Notes:
- `start-wails-dev.ps1` force-releases ports `34115` and `17891` before starting.
- Desktop app starts/reuses backend service on `127.0.0.1:17891`.

### Backend standalone run (without Wails)

```bash
# HTTP server mode
cd backend && go run ./cmd/sentinel serve 127.0.0.1:17891

# CLI parse mode
cd backend && go run ./cmd/sentinel parse <capture.pcapng> [display-filter]
```

### Tests

```bash
# Root desktop-shell tests only
go test ./...

# Backend all tests
cd backend && go test ./...

# Backend single package
cd backend && go test ./internal/engine/...

# Backend single test
cd backend && go test ./internal/engine/... -run TestName

# Frontend tests (Vitest single run)
cd frontend && pnpm run test

# Frontend single test file
cd frontend && pnpm run test -- src/app/pages/VehicleAnalysis.test.ts

# Frontend test by name
cd frontend && npx vitest run -t "test name"
```

### Formatting / checks

```bash
# Backend format check
cd backend && gofmt -l .

# Backend format fix
cd backend && gofmt -w .

# Full project checks (desktop tests + backend fmt/tests + frontend tests/build)
./scripts/check-all.ps1
```

### Build

```bash
# Build frontend assets and copy backend binary into frontend/dist
cd frontend && pnpm run build:wails

# Build desktop app
wails build

# Disable self-update logic in build
wails build -tags dev

# Enable self-update logic in build
wails build -tags production
```

### Release packaging

```powershell
# Build release bundle + version.json
python .\scripts\build_release_package.py v0.0.5

# Reuse existing build artifact
python .\scripts\build_release_package.py v0.0.5 --skip-build
```

## High-Level Architecture

### Runtime topology

```
Wails Desktop Shell (app.go)
  └─ manages backend process + auth token
     └─ Backend HTTP/SSE server (127.0.0.1:17891)
Frontend (React) ── HTTP + SSE ──> Backend
```

Desktop responsibilities:
- Starts backend process on app startup, stops it on shutdown.
- Provides Wails file-dialog bindings to frontend.
- Injects/reads backend auth token (`GSHARK_BACKEND_TOKEN`).

### Backend structure (`backend/`)

- `cmd/sentinel/main.go`: entry point with `serve` and `parse` modes.
- `internal/transport`: HTTP router + SSE hub + auth/audit middleware; exposes API endpoints used by UI.
- `internal/engine/service.go`: orchestration core (capture lifecycle, caches, stream state, threat hunting, tool runtime config).
- `internal/tshark`: tshark invocations, packet streaming/parsing helpers, industrial/vehicle/media protocol extraction.
- `internal/plugin`: plugin manager and JS/Python runtime handling.
- `internal/model`: backend API/shared data contracts.

Important backend behavior:
- Packet ingestion uses staged tshark strategies (fast path with fallbacks).
- Stream reassembly is cached and can fall back to file/index reconstruction.
- Threat hunting combines prefix matching, plugins, and YARA.
- Runtime tool config includes tshark/ffmpeg/python/speech/yara settings via API.

### Frontend structure (`frontend/src/app`)

- `routes.tsx`: lazy-loaded feature routes.
- `state/SentinelContext.tsx`: central app state (packet pagination, selected packet, stream state, threat/media progress, plugin state).
- `integrations/wailsBridge.ts`: typed backend bridge for HTTP/SSE + desktop bindings.
- `core/types.ts`: frontend contract types mirroring backend responses.
- `pages/*`: feature views (workspace, stream views, threat hunting, protocol analyses, media/USB/tools pages).

Frontend data flow:
- SSE events (`packet/status/error`) update context state incrementally.
- Paginated packet APIs (`/api/packets/page`, locate APIs) drive large-capture browsing.
- Stream pages load chunked stream data and support payload patch persistence.

### Plugins and rules

- Plugin directory: `backend/plugins/rules/`.
- Plugin manager loads JSON metadata + logic entry (`.js`/`.py`) and validates IDs/capabilities.
- Threat hunting invokes enabled plugins during analysis runs.
- YARA rules/assets live under `backend/rules/yara/` and are copied into build artifacts for runtime use.

## Operational knobs that affect behavior

- `GSHARK_BACKEND_TOKEN`: backend bearer token (generated if absent).
- `GSHARK_ALLOW_EXISTING_BACKEND=1`: allows desktop app to reuse an already-running backend on `127.0.0.1:17891`.
- `VITE_BACKEND_URL`: frontend API base override (defaults to `http://127.0.0.1:17891`).
- `GSHARK_UPDATE_MANIFEST_REF`: override update manifest branch/ref used by updater flow.
