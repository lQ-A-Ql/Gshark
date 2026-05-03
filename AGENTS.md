# AGENTS.md

## Build tags gate the desktop app

Root `main.go`, `app.go`, `build_mode_*.go` all require `//go:build dev || production`. Without a tag, `go build`/`go test` at root compiles `main_nondesktop.go` which just prints a message and exits.

```bash
# Root tests need a build tag
go test -tags dev ./...

# Backend has no build tag requirement
cd backend && go test ./...
```

## Two Go modules, one workspace

- Root (`go.mod`): `github.com/gshark/sentinel/desktop`, Go 1.22 — Wails desktop shell only
- `backend/` (`go.mod`): `github.com/gshark/sentinel/backend`, Go 1.25 — all real logic
- `go.work` at root ties them together for IDE/`go test` convenience

When running backend commands, `cd backend` first. The root module has almost no logic.

## CI vs local tooling mismatch

CI (`.github/workflows/ci.yml`) uses `npm ci` with `package-lock.json`. Local dev uses `pnpm`. Both lockfiles exist in `frontend/`. CI does NOT run frontend tests — only `npm run build`.

## Frontend build quirks

- `pnpm run build:wails` = `vite build` + copies backend binary into `frontend/dist/` (via `scripts/build-backend-binary.ps1`). This is the command Wails uses.
- `pnpm run build` = plain Vite build only (what CI runs).
- Vite config enforces: never add `.css`, `.tsx`, `.ts` to `assetsInclude`.
- `@` alias → `./src` (configured in `vite.config.ts`).
- Test environment: jsdom, setup file at `src/test/setup.ts`.
- No ESLint or Prettier configured.

## Backend: no framework, stdlib router

HTTP router is `net/http.ServeMux` in `internal/transport`. Routes registered in `Server.Handler()`. Don't expect chi/gin/echo patterns.

## Formatting

Go: `gofmt` only. Run `cd backend && gofmt -l .` to check, `gofmt -w .` to fix. CI enforces this.

## Ports

Backend: `17891`. Wails dev server: `34115`. `scripts/start-wails-dev.ps1` kills both before starting.

## Env vars

- `GSHARK_BACKEND_TOKEN` — bearer token (auto-generated if absent)
- `GSHARK_ALLOW_EXISTING_BACKEND=1` — reuse already-running backend
- `VITE_BACKEND_URL` — frontend API override (default `http://127.0.0.1:17891`)

## Full local check

```powershell
./scripts/check-all.ps1
```

Runs: root Go tests (no build tag — desktop-only tests are skipped) → backend gofmt check → backend tests → frontend tests → frontend build.

## MISC module scaffolding

```powershell
./scripts/new-misc-module.ps1
```

Spec: `docs/misc-module-interface.md`.

## Wails dev: backend binary caching gotcha

`main.go` embeds `frontend/dist/sentinel-backend.exe` at compile time. When you modify backend code, the old binary may be cached in 3 places:

- `frontend/dist/sentinel-backend.exe` (embedded)
- `build/bin/sentinel-backend.exe`
- `%TEMP%/gshark-sentinel/backend/sentinel-backend.exe`

If `wails dev` doesn't pick up your backend changes, delete all three + clear Go build cache. `scripts/start-wails-dev.ps1` does NOT auto-clean these yet.

## Implemented subsystems (as of 2026-05-03)

| Subsystem | Key files |
|-----------|-----------|
| Capture lifecycle | `service.go`: `BeginCaptureLoad`, `LoadPCAPWithRun`, `PrepareCaptureReplacement`, capture task registry |
| C2 decrypt | `c2_decrypt.go`: VShell 3-KDF (md5(salt), md5(salt+vkey), md5(saltPad32+vkey)), CS keyed offline workbench, raw-stream candidates |
| WebShell | `stream_payload_sources.go`: suspicious URI scanner, repeat-burst/command-exec rules, stream reassembly fallback |
| Payload inspector | `stream_decoder.go` + `stream_payload_inspector.go`: inspect/decode with confidence + failure stages |
| YARA | `yara_stream_targets.go`: context-aware stream target building |
| Speech | `speech_to_text.go`: batch transcription registered in capture task registry |
| Media | `media_playback.go`: `MediaPlaybackWithContext`, ffmpeg with `exec.CommandContext` |
| Evidence schema | `frontend/src/app/features/evidence/evidenceSchema.ts`: `UnifiedEvidenceRecord` |
| Frontend lifecycle | `SentinelContext.tsx`: `prepareForCaptureReplacement`, `captureTaskScope`; `useAbortableRequest` hook |
| Frontend types | `core/types/`: 13 个子模块（packet, stream, traffic, c2, apt, industrial, vehicle, media, usb, misc-protocols, misc-modules, tools, index） |
| Frontend feature hooks | `features/*/use*.ts`: 8 个 hooks（c2, apt, industrial, vehicle, media, usb, traffic, object） |

Full audit history: `docs/audit-development-report-archive-2026-05-02/`

## Context pattern for new handlers

New HTTP handlers MUST use `WithContext` variants:

```go
// ✅ correct
result, err := s.svc.ThreatHuntWithContext(r.Context(), ...)
result, err := s.svc.C2Decrypt(r.Context(), ...)

// ❌ wrong — blocks close/replacement cancellation
result, err := s.svc.ThreatHunt(...)
result, err := s.svc.Objects(...)
```

Legacy `context.Background()` wrappers exist for desktop synchronous calls only. Never use them in HTTP handlers.

## Test baseline

- Backend: `cd backend && go test ./...` — 6 packages (engine, miscpkg, plugin, transport, tshark, yara)
- Frontend: `cd frontend && pnpm run test` — 18 test files, 85 tests
- TypeScript strict: `cd frontend && npx tsc --noEmit --noUnusedLocals --noUnusedParameters`
- Full check: `./scripts/check-all.ps1`
