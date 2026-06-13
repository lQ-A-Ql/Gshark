# Contributing

This repository is a desktop-first offline traffic analysis workbench. Product branding is `meow~traffic`; historical compatibility identifiers such as `sentinel`, `meow-traffic`, `github.com/gshark/sentinel/...`, `sentinel-backend.exe`, and `MEOW_TRAFFIC_*` remain valid unless a dedicated migration changes them.

## Modules

- Root module: `github.com/gshark/sentinel/desktop`, Go 1.22, Wails shell only.
- Backend module: `github.com/gshark/sentinel/backend`, Go 1.25, real analysis logic.
- `go.work` ties both modules together for local development.

Root desktop code requires `dev` or `production` build tags. Backend commands should be run from `backend/`.

```powershell
go test -tags dev ./...

cd backend
go test ./...
```

## Frontend

Frontend uses pnpm only. Keep `frontend/pnpm-lock.yaml`; do not add npm lockfiles.

```powershell
cd frontend
corepack enable
corepack prepare pnpm@10.31.0 --activate
pnpm install --frozen-lockfile
```

The top-level frontend CI command is split into observable groups:

```powershell
pnpm run ci:quality
pnpm run ci:boundaries
pnpm run ci:desktop
pnpm run ci:test-build
pnpm run ci
```

Desktop data-plane work should use typed Wails IPC. Do not add generic IPC fallback for migrated `/api/*` surfaces. Type governance is part of `ci:boundaries` and blocks new raw `as any` in `desktopTypedBridgeRules.ts`, new open core `| string` unions, and new wide wire DTO inheritance outside the compatibility allowlist.

## Backend

HTTP uses `net/http.ServeMux` in `backend/internal/transport`. New HTTP handlers must pass `r.Context()` into context-aware service methods.

`engine.Service` remains the stable facade for transport and Wails. New engine root files must have a domain owner in the architecture boundary test. Pure logic should move to dependency-light subpackages that do not depend on root `engine`, `transport`, `tshark`, HTTP, or process execution.

Use `gofmt` only:

```powershell
cd backend
gofmt -l .
go test ./internal/architecture -run TestBackendArchitectureBoundaries -count=1 -v
go test ./...
```

## Local Full Check

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check-all.ps1
```

The full check includes desktop asset build, root build-tag tests, backend formatting and tests, backend coverage report, frontend grouped CI, Wails asset checks, and ignored tracked file detection.

## Documentation

Update the authority documents when changing public surfaces:

- HTTP route: `docs/api/openapi.yaml`
- typed Wails data-plane binding: `docs/project-design-and-constraints.md`
- core type or wire DTO family: architecture or design docs
- MISC package interface: `docs/misc-module-interface.md`
- CI/build/package-manager rule: `docs/project-development-guide.md`
- architecture or governance rule: `docs/full-governance-phase1-register.md` or `docs/governance-defect-register.json`
