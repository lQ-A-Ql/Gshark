# Module Dead-Code Audit - 2026-06-24

## Scope

This audit reviewed frontend source reachability, Wails desktop shell code, backend model/engine/transport packages, and governance evidence after the typed-only Wails IPC and in-process backend migration.

## Removed

- Frontend unreachable production modules:
  - unused UI primitives: `alert.tsx`, `card.tsx`
  - old USB/MISC presentation fragments: `UsbHidTablePaging.tsx`, `MiscModuleCard.tsx`, `MiscToolsHero.tsx`
  - obsolete preload/cache/context barrels: `preloadMetrics.ts`, `lruCache.ts`, `state/contexts/index.ts`
  - old generic Wails bridge facade: `integrations/wailsBridge.ts`
- Frontend obsolete generic IPC guardrail scripts:
  - binding cleanup, removal preflight, retirement readiness, and rollback guard scripts/tests
  - active post-removal monitor, Wails binding check, desktop transport policy, old-binding compatibility, and MISC inventory checks remain.
- Wails desktop shell dead code:
  - removed child-backend window hiding helpers, since desktop now mounts backend runtime in-process.
  - removed the old raw SSE event parser path; desktop events now forward payloads directly from `transport.Hub`.
- Backend dead code:
  - retired legacy `model.Plugin` and `model.PluginSource`; current extension surface is MISC modules.
  - removed unused engine test seam/fields/helpers: `filterFrameIDsFn`, C2 stats metadata field, VShell stream `lastKind`, duplicate payloadinspect decode helpers.
  - removed unused rule/YARA wrappers and unused transport test helper.
  - simplified staticcheck findings that obscured real dead-code findings.
- Governance:
  - updated the canonical defect register evidence for P1-14 so it no longer references deleted `app_backend_extract_test.go`.

## Intentionally Retained

- Browser-dev HTTP/SSE code remains intentional compatibility/debugging surface.
- Backend HTTP routes remain intentional for CLI/browser-dev and are invoked in-process by Wails desktop through `desktopruntime`.
- Frontend post-removal generic IPC monitors remain as reintroduction guardrails, even though the old implementation is gone.
- Test fixtures and historical audit archives were not treated as production dead code.
- Public backend library APIs reported by whole-program deadcode were retained unless independent reference checks confirmed they were not part of a current contract.

## Verification

- `go run honnef.co/go/tools/cmd/staticcheck@latest ./...` from `backend` passed.
- `go run honnef.co/go/tools/cmd/staticcheck@latest -tags dev ./...` from repository root passed.
- `cd backend && go test ./...` passed after fixing stale governance evidence.
- Root and frontend gates are recorded in the final handoff for this audit round.
