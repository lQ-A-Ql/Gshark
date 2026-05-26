# Desktop IPC old generated binding exit plan

> Scope: Round 19 exit planning only. Do not remove in Round 19.

This document records the remaining approved uses of the old generated Wails `DesktopApp` binding surface and the conditions required before the generic IPC adapter can be retired. It complements `docs/desktop-ipc-iteration-status.json`; the JSON tracker remains the current round state source, while this file explains the exit criteria.

## Current status

status: guarded

The old generated binding surface is not an approved path for new desktop data-plane features. It remains only for shell/bootstrap compatibility, browser-dev authentication support, native dialogs, update flow, and the single generic IPC adapter while the compatibility window is being observed.

## Approved uses

| File | Approved methods | Reason |
|---|---|---|
| `frontend/src/app/integrations/backendClients.ts` | `window.go.main.DesktopApp` | Bootstrap lookup for the Wails binding object. |
| `frontend/src/app/integrations/httpBridge.ts` | `GetBackendAuthToken` | Browser-dev and fallback HTTP auth bootstrap; this must stay available while HTTP/SSE debugging is supported. |
| `frontend/src/app/integrations/ipcBackendTransport.ts` | `InvokeBackendJSON`, `InvokeBackendBlob`, `InvokeBackendText` | Single guarded generic IPC adapter. It rejects migrated typed routes via `typed_binding_required` and is the only remaining adapter slated for future retirement. |
| `frontend/src/app/integrations/clients/captureClient.ts` | `OpenCaptureDialog` | Native PCAP selection shell feature, not a business data-plane route. |
| `frontend/src/app/integrations/clients/desktopClient.ts` | `BackendStatus`, `CheckAppUpdate`, `InstallAppUpdate`, `OpenDBCDialog` | Desktop shell/update/dialog features; not evidence, stream, analysis, object, MISC, or tooling data-plane routes. |
| `frontend/src/app/integrations/desktopBridge.ts` and `desktopTypedBridge*.ts` | typed DesktopApp methods | Typed bridge ownership; these files may call typed methods but must not expand generic IPC. |

## Exit trigger

Do not remove `InvokeBackendJSON`, `InvokeBackendBlob`, or `InvokeBackendText` until all of the following are true:

- Three consecutive green rounds have `desktopWebviewTyped.directBackendApiRequestCount = 0`.
- `frontend/scripts/check-desktop-generic-ipc-allowlist.mjs` reports no unclassified client routes.
- `frontend/scripts/check-desktop-old-binding-compat.mjs` reports no new direct old generated binding uses.
- `frontend/scripts/check-desktop-misc-compat-inventory.mjs` reports no MISC desktop compatibility routes.
- `cd frontend && pnpm run ci` and `cd frontend && pnpm run build:wails` pass in the same round.
- Browser-dev HTTP/SSE remains green, including HTTP auth bootstrap and EventSource readiness.
- A real Wails WebView smoke run passes after the adapter is disabled in a feature branch.
- The disabled-adapter smoke is built with either `VITE_DESKTOP_GENERIC_IPC_POLICY=disabled` or legacy `VITE_DESKTOP_DISABLE_GENERIC_IPC=1` and run with `scripts/check-desktop-ipc-smoke.ps1 -DisableGenericIpcAdapterExperiment`, so `genericIpcDisableExperimentBuildFlag = true` and `desktopWebviewTyped.directBackendApiRequestCount = 0` are recorded in the smoke summary.
- A release-candidate rollback path is documented and tested: `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` must force adapter-enabled compatibility even when the legacy disable alias is set.
- The default-disabled release candidate must complete three consecutive default-disabled observation rounds before adapter removal is considered.

## Removal sequence

1. Round 24 makes desktop release default to disabled generic IPC adapter routing. `VITE_DESKTOP_DISABLE_GENERIC_IPC=1` remains only a legacy alias; do not promote it to the default control path.
2. Keep `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` as the rollback/override switch for release candidates until multiple default-disabled rounds are green.
3. Record each default-disabled observation round in `docs/desktop-ipc-iteration-status.json`, including default-disabled smoke, compat rollback smoke, `directBackendApiRequestCount = 0`, and browser-dev green.
4. Do not remove adapter code until three consecutive default-disabled observation rounds are recorded and all guardrails remain green.
5. Run the full gate and Wails smoke with the adapter disabled.
6. If smoke still reports `directBackendApiRequestCount = 0`, consider adapter removal only in a separate round; do not remove adapter code in the same round as the final observation.
7. Keep `GetBackendAuthToken`, `OpenCaptureDialog`, `BackendStatus`, update methods, and native dialog methods until each is replaced by an explicit typed shell contract or intentionally retained as shell API.

## Non-goals

- Do not remove browser-dev HTTP/SSE debugging.
- Do not rewrite historical archive reports to match this final plan.
- Do not treat shell/update/dialog methods as data-plane debt unless they start carrying business domain payloads.
