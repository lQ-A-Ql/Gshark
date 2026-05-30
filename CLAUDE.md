# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

meow~traffic is a desktop-first offline traffic analysis tool for PCAP/PCAPNG.

Branding note: the product display name is now `meow~traffic`, while compatibility identifiers such as `github.com/gshark/sentinel/...`, `MEOW_TRAFFIC_*`, `meow-traffic`, and `sentinel-backend.exe` intentionally remain unchanged in this repository.

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
- ESLint is part of frontend CI. Prettier is configured as a scoped baseline check for touched/split frontend files; only `gofmt` is mandatory for Go.
- Frontend uses `@` path alias (`@` → `./src`) configured in `vite.config.ts`.
- Frontend tests use Vitest with jsdom environment; setup file at `src/test/setup.ts` mocks ResizeObserver, localStorage, PointerEvent, and canvas context.
- ESLint rules: unused vars prefixed with `_` are allowed (`@typescript-eslint/no-unused-vars` with `argsIgnorePattern: "^_"`); `@typescript-eslint/no-explicit-any` is off; `react-hooks/rules-of-hooks` is error-level.
- Package manager is pinned: `pnpm@10.31.0` (enforced by `pnpm run package-manager:check` in CI).

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
cd frontend && pnpm run test:run

# Frontend typecheck
cd frontend && pnpm run typecheck

# Frontend CI bundle
cd frontend && pnpm run ci

# Frontend lint
cd frontend && pnpm run lint

# Frontend single test file
cd frontend && pnpm run test:run -- src/app/pages/VehicleAnalysis.test.ts

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

# Optional frontend lint/format checks for touched code
cd frontend && pnpm run lint
cd frontend && pnpm run format:check
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
Frontend (React) ── typed Wails IPC (desktop) / HTTP + SSE (browser) ──> Backend
```

Desktop responsibilities:
- Starts backend process on app startup, stops it on shutdown.
- Provides Wails file-dialog bindings to frontend.
- Injects/reads backend auth token (`MEOW_TRAFFIC_BACKEND_TOKEN`).
- Self-update system (`desktop_update.go`) checks GitHub releases when built with `-tags production`; disabled with `-tags dev`.

### Backend structure (`backend/`)

- `cmd/sentinel/main.go`: entry point with `serve` and `parse` modes.
- `internal/transport`: HTTP router (stdlib `net/http.ServeMux`, not a framework) + SSE hub + auth/audit middleware; all routes registered in `Server.Handler()`.
- `internal/engine/service.go`: orchestration core (capture lifecycle, caches, stream state, threat hunting, tool runtime config).
- `internal/tshark`: tshark invocations, packet streaming/parsing helpers, industrial/vehicle/media protocol extraction.
- `internal/plugin`: plugin manager and JS (goja) / Python runtime handling.
- `internal/miscpkg`: MISC zip package management (import/invoke/delete).
- `internal/model`: backend API/shared data contracts.

Important backend behavior:
- Packet ingestion uses staged tshark strategies (fast path with fallbacks).
- Stream reassembly is cached and can fall back to file/index reconstruction.
- Threat hunting combines prefix matching, plugins, and YARA.
- Runtime tool config includes tshark/ffmpeg/python/speech/yara settings via API.
- YARA rules under `backend/rules/yara/` are embedded via Go embed and copied into build artifacts.

Backend architecture boundaries (CI-enforced via `go test ./internal/architecture`):
- `model` has no dependencies on `engine`, `transport`, `tshark`, `plugin`, or `miscpkg`.
- `transport` does not depend on `tshark` internals.
- Report builders (`analysis_report*`) stay pure — no tshark/transport imports, no capture state references.
- Report rule metadata is registry-owned (only in `analysis_report_rules.go` / `analysis_report_shared.go`).
- `internal/report` stays dependency-light (no engine/transport/tshark).
- Evidence files stay transport-free.
- Transport handlers must pass request context to long-running service methods.

### Frontend structure (`frontend/src/app`)

- `routes.tsx`: React Router v7 with lazy-loaded feature routes.
- `state/SentinelContext.tsx`: central app state (packet pagination, selected packet, stream state, threat/media progress, plugin state). This is a large monolithic context (~73KB).
- `integrations/`: backend communication layer (see integrations architecture below).
- `core/types.ts`: frontend contract types mirroring backend responses.
- `pages/*`: feature views (workspace, stream views, threat hunting, protocol analyses, media/USB/tools pages).
- `components/ui/`: Radix UI primitives (button, dialog, card, tooltip, etc.).
- `misc/`: MISC module system — registry, built-in module components, and custom zip module support.
- `features/`: feature-specific code organized by domain (apt, c2, evidence).

Frontend data flow:
- SSE events (`packet/status/error`) update context state incrementally.
- Paginated packet APIs (`/api/packets/page`, locate APIs) drive large-capture browsing.
- Stream pages load chunked stream data and support payload patch persistence.

### Frontend integrations layer

The `integrations/` directory follows a 3-tier pattern:

- `wire/` — Raw backend DTO types (field-for-field match of JSON responses). No logic.
- `mappers/` — Pure functions converting wire DTOs to frontend view models. No React, no side effects.
- `clients/` — Domain-specific API call wrappers. Transport-only, no UI or feature logic.

App code consumes `backendClients` (which composes clients) or individual domain clients. Pages and features never reach into wire/mapper layers directly.

### Frontend layering rules (CI-enforced)

The boundary check (`pnpm run boundary:check`) enforces these import invariants:

1. No production code may import `./integrations/wailsBridge` — use `integrations/backendClients`.
2. Only `integrations/` may reach into `bridgeTypes`, `bridgeFactory`, `httpBridge`, `desktopBridge`, or `bridgeDomains`. App code must consume domain projections from `integrations/backendClients`.
3. State code (`state/**`) may not import UI components (`pages/` or `components/`).
4. Pages may not import mappers directly — consume feature/core view models.
5. Pages may not add new direct dependencies on aggregate `backendClients`.
6. Features may not import from other features (route through `core/`, `components/analysis`, or `integrations/`).
7. Mappers (`integrations/mappers/**`) stay UI-free: no React, no pages/components, no feature rules.
8. Clients (`integrations/clients/**`) stay transport-only: no pages, components, or features.
9. UI primitives (`components/ui/**`) stay domain-free.
10. Shared analysis components (`components/analysis/**`) stay domain-neutral — no features/ imports.

### Frontend size budgets

Every key frontend file has a line-count budget enforced by `pnpm run size:check`. If a file exceeds its budget, CI fails. When adding code to a budgeted file, check `frontend/scripts/check-size.mjs` for the limit. If you need more space, split the logic into a sibling module rather than raising the budget.

All mapper files (`integrations/mappers/`) and wire DTO files (`integrations/wire/`) must have a size budget entry — unbudgeted files also fail CI.

### Plugins and rules

- Plugin directory: `backend/plugins/rules/`.
- Plugin manager loads JSON metadata + logic entry (`.js`/`.py`) and validates IDs/capabilities.
- Allowed plugin capabilities: `packet.read`, `threat.emit`, `logging`, `finish.hook`, `metadata.read`.
- Threat hunting invokes enabled plugins during analysis runs.
- YARA rules/assets live under `backend/rules/yara/` and are copied into build artifacts for runtime use.

### MISC module system

- Built-in modules (frontend): HTTPLoginAnalysis, SMTPSession, MySQLSession, ShiroRememberMe, NTLMSessionMaterials, WinRMDecrypt, SMB3SessionKey, PayloadWebShellDecoder.
- Custom zip modules: `manifest.json + api.json + form.json + backend.js/.py`, managed via `internal/miscpkg/manager.go`.
- Scaffold new modules: `./scripts/new-misc-module.ps1` (e.g. `powershell -ExecutionPolicy Bypass -File .\scripts\new-misc-module.ps1 -Id echo-demo -Title "Echo Demo" -Runtime javascript -Zip`).
- Spec: `docs/misc-module-interface.md`.
- Example: `examples/misc-modules/echo-demo`.

### Backend governance

The `internal/governance` package maintains a machine-readable defect register (`docs/governance-defect-register.json`). CI validates (`go test ./internal/governance`):
- Resolved defects must have closure evidence (commit, modified files, validation commands, evidence tests).
- Open defects must not have closure evidence.
- Report rendering and archive path conventions are tested.
- Self-audit and integration tests verify governance consistency.

## CI

- GitHub Actions (`.github/workflows/ci.yml`): triggers on push (any branch) and PRs.
- Backend job (ubuntu-latest): `gofmt -l .` + architecture boundary tests + focused contract tests + governance register tests + `go test ./...`.
- Frontend job (ubuntu-latest): `corepack enable` + `pnpm install --frozen-lockfile` + `pnpm run ci` (package-manager:check + typecheck + ESLint + scoped-format + size + boundary + desktop IPC migration checks + Vitest + build).
- Desktop job (windows-latest): `pnpm run build:wails` + `check-desktop-assets.ps1` + root Go tests with both `-tags dev` and `-tags production`.
- Full local check: `./scripts/check-all.ps1` (desktop tests + backend fmt/tests + frontend package-manager/tests/typecheck/lint/scoped-format/size/build).

## Operational knobs that affect behavior

- `MEOW_TRAFFIC_BACKEND_TOKEN`: backend bearer token (generated if absent).
- `MEOW_TRAFFIC_ALLOW_EXISTING_BACKEND=1`: allows desktop app to reuse an already-running backend on `127.0.0.1:17891`.
- `VITE_BACKEND_URL`: frontend API base override (defaults to `http://127.0.0.1:17891`).
- `MEOW_TRAFFIC_UPDATE_MANIFEST_REF`: override update manifest branch/ref used by updater flow.
- `MEOW_TRAFFIC_FFMPEG`: explicit FFmpeg path for backend media processing.
- `MEOW_TRAFFIC_PYTHON`: explicit Python interpreter path for plugin/module runtime.
- `MEOW_TRAFFIC_VOSK_MODEL`: explicit Vosk model directory for speech transcription.

## Desktop IPC architecture

Wails desktop data plane uses **typed IPC bindings** (not generic `InvokeBackend`). Frontend React WebView calls specific Wails typed bindings via `desktopBridge`; missing typed bindings fail with `generic_ipc_disabled` and do **not** fall back to browser HTTP or generic IPC.

Key points:
- Control-plane calls (capture status, packet page, start/stop, TLS, runtime probe) carry local timeout/abort protection.
- Desktop SSE events are forwarded as `meow-traffic:backend:*` Wails runtime events; WebView does not directly connect to `/api/events`.
- Blob responses over desktop IPC are capped at 50MB.
- Browser-dev mode (non-Wails) continues using HTTP/SSE via `httpBridge`.
- See `frontend/src/app/integrations/desktopBridge.ts` and `frontend/src/app/integrations/desktopTypedBridgeCore.ts`.
