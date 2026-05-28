# Desktop IPC old generated binding exit plan

> Scope: Round 19 exit planning only. Do not remove in Round 19.

This document records the remaining approved uses of the old generated Wails `DesktopApp` binding surface and the conditions required before the generic IPC adapter can be retired. It complements `docs/desktop-ipc-iteration-status.json`; the JSON tracker remains the current round state source, while this file explains the exit criteria.

## Current status

status: shell-compat-only; backend/generated InvokeBackend* removed

The old generated binding surface is not an approved path for new desktop data-plane features. After Round 29, `desktopBridge` no longer constructs the frontend generic IPC adapter. After Round 34, backend/generated `InvokeBackendJSON`, `InvokeBackendBlob`, and `InvokeBackendText` are removed, and the old generated binding surface is limited to shell/bootstrap compatibility, browser-dev authentication support, native dialogs, and update flow.

Post-removal facts required by guardrails:

- removed InvokeBackendJSON
- removed InvokeBackendBlob
- removed InvokeBackendText
- `deletionReady = true`

## Approved uses

| File | Approved methods | Reason |
|---|---|---|
| `frontend/src/app/integrations/backendClients.ts` | `window.go.main.DesktopApp` | Bootstrap lookup for the Wails binding object. |
| `frontend/src/app/integrations/httpBridge.ts` | `GetBackendAuthToken` | Browser-dev and fallback HTTP auth bootstrap; this must stay available while HTTP/SSE debugging is supported. |
| `frontend/src/app/integrations/clients/captureClient.ts` | `OpenCaptureDialog` | Native PCAP selection shell feature, not a business data-plane route. |
| `frontend/src/app/integrations/clients/desktopClient.ts` | `BackendStatus`, `CheckAppUpdate`, `InstallAppUpdate`, `OpenDBCDialog` | Desktop shell/update/dialog features; not evidence, stream, analysis, object, MISC, or tooling data-plane routes. |
| `frontend/src/app/integrations/desktopBridge.ts` and `desktopTypedBridge*.ts` | typed DesktopApp methods | Typed bridge ownership; these files may call typed methods but must not expand generic IPC. |

## Exit trigger

`InvokeBackendJSON`, `InvokeBackendBlob`, and `InvokeBackendText` were removed in Round 34 only after the prior exit criteria were satisfied or made machine-verifiable. Post-removal checks must keep all of the following true:

- Three consecutive green rounds have `desktopWebviewTyped.directBackendApiRequestCount = 0`.
- `frontend/scripts/check-desktop-generic-ipc-allowlist.mjs` reports no unclassified client routes.
- `frontend/scripts/check-desktop-old-binding-compat.mjs` reports no new direct old generated binding uses.
- `frontend/scripts/check-desktop-misc-compat-inventory.mjs` reports no MISC desktop compatibility routes.
- `cd frontend && pnpm run ci` and `cd frontend && pnpm run build:wails` pass in the same round.
- Browser-dev HTTP/SSE remains green, including HTTP auth bootstrap and EventSource readiness.
- A real Wails WebView smoke run passes after the adapter is disabled in a feature branch.
- The disabled-adapter smoke is built with either `VITE_DESKTOP_GENERIC_IPC_POLICY=disabled` or legacy `VITE_DESKTOP_DISABLE_GENERIC_IPC=1` and run with `scripts/check-desktop-ipc-smoke.ps1 -DisableGenericIpcAdapterExperiment`, so `genericIpcDisableExperimentBuildFlag = true` and `desktopWebviewTyped.directBackendApiRequestCount = 0` are recorded in the smoke summary.
- A release-candidate rollback/no-op contract is documented and tested: after Round 29, `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` must remain recognizable but must not force adapter-enabled compatibility.
- The default-disabled release candidate must complete three consecutive default-disabled observation rounds before adapter removal is considered.
- `frontend/scripts/check-wails-bindings.mjs` forbids removed `InvokeBackendJSON`, `InvokeBackendBlob`, and `InvokeBackendText`.
- `frontend/scripts/check-desktop-generic-ipc-binding-cleanup-preflight.mjs` reports `deletionReady = true`.

## Removal sequence

1. Round 24 makes desktop release default to disabled generic IPC adapter routing. `VITE_DESKTOP_DISABLE_GENERIC_IPC=1` remains only a legacy alias; do not promote it to the default control path.
2. Keep `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` as a recognizable policy value. After Round 29 it is a documented no-op for adapter enablement; source-level rollback would require restoring the `desktopBridge` adapter construction.
3. Record each default-disabled observation round in `docs/desktop-ipc-iteration-status.json`, including default-disabled smoke, compat rollback smoke, `directBackendApiRequestCount = 0`, and browser-dev green.
4. Do not remove adapter code until three consecutive default-disabled observation rounds are recorded and all guardrails remain green.
5. Run the full gate and Wails smoke with the frontend adapter construction removed.
6. If smoke still reports `directBackendApiRequestCount = 0`, consider backend/generated `InvokeBackend*` cleanup only in a separate preflight round; do not remove backend/generated bindings in the same round as frontend adapter construction removal.
7. Keep `GetBackendAuthToken`, `OpenCaptureDialog`, `BackendStatus`, update methods, and native dialog methods until each is replaced by an explicit typed shell contract or intentionally retained as shell API.

## Adapter removal preflight

Round 28 is an adapter removal preflight, not a deletion round. The preflight inventory must include every remaining `InvokeBackendJSON`, `InvokeBackendBlob`, `InvokeBackendText`, and `createIpcBackendTransport` reference in production source and generated Wails bindings.

The reversible deletion plan is:

1. Remove the `createIpcBackendTransport` construction gate from `desktopBridge` only in a dedicated candidate removal round. Round 29 completed this source-level step.
2. Remove `InvokeBackendJSON`, `InvokeBackendBlob`, and `InvokeBackendText` from the shell binding and generated Wails bindings only after backend binding removal or an explicit keep-as-unreachable decision.
3. Keep `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` documented as a recognizable no-op after Round 29. It is no longer an env-only rollback switch.
4. Keep browser-dev HTTP/SSE independent from desktop adapter removal.
5. If full gates or Wails smoke fail, restore the `desktopBridge` adapter construction and stay in governance.

## Adapter removal candidate

Round 29 removes only the frontend construction/use of `createIpcBackendTransport` from `desktopBridge`. It intentionally does not remove `ipcBackendTransport.ts`, `DesktopShellBinding.InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`, backend `DesktopApp.InvokeBackend*` methods, or generated Wails bindings.

Post-candidate facts:

- `desktopBridge` builds its base data bridge from `createDisabledGenericIpcBackendTransport`.
- Typed desktop overrides still take precedence.
- Missing typed data-plane bindings fail with `generic_ipc_disabled` and do not call `InvokeBackendJSON`.
- Runtime/MCP/capture/TLS control-plane compatibility fallback explicitly uses `fallbackBridge`, not generic IPC.
- Wails runtime event subscription remains active through `EventsOn`.
- `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` remains recognizable for telemetry/tests but does not re-enable adapter construction.

## Backend/generated generic IPC binding cleanup preflight

Round 30 is a backend/generated generic IPC binding cleanup preflight, not a deletion round.

Current expected result: `deletionReady = false`.

Deletion was blocked in Round 30 by these code facts:

- `typed helper reuse`: typed backend methods still call exported `DesktopApp.InvokeBackendBlob` or `DesktopApp.InvokeBackendText` internally.
- The current typed helper reuse list is `DownloadObjectsZip`, `GetWinRMDecryptResultText`, `ExportWinRMDecryptResult`, `ExportMediaBatchTranscription`, `DownloadMediaArtifact`, and `GetMediaPlaybackBlob`.
- `desktop_backend_proxy_test.go` still directly tests `InvokeBackendJSON`, `InvokeBackendBlob`, and `InvokeBackendText`.
- `check-wails-bindings generic-ipc group` still requires generated `InvokeBackendJSON`, `InvokeBackendBlob`, and `InvokeBackendText`.
- `ipcBackendTransport.ts` still contains unreachable `createIpcBackendTransport` and active `createDisabledGenericIpcBackendTransport`.

Round 31 update:

- `typed helper reuse` is now empty.
- Typed blob/text methods call non-exported `invokeBackendBlob` / `invokeBackendText` helpers.
- `desktop_backend_proxy_test.go` covers object ZIP, WinRM text/export, media batch export, media artifact download, and media playback through typed methods.
- `desktop_backend_proxy_test.go` still directly tests `InvokeBackendJSON`; that remaining test is kept until the generated binding deletion round.

Round 32 update:

- `createDisabledGenericIpcBackendTransport` moved to `desktopDisabledGenericIpcTransport.ts`.
- `generic_ipc_disabled` fail-fast behavior moved with the disabled transport, away from the legacy `ipcBackendTransport.ts` adapter inventory.
- Wails runtime event subscription moved to `desktopEventTransport.ts` and remains shared by the disabled transport and the legacy adapter inventory.
- `ipcBackendTransport.ts` still contains unreachable `createIpcBackendTransport` plus `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText` calls as inventory.

Round 33 update:

- `desktop_backend_proxy_test.go` no longer directly calls `DesktopApp.InvokeBackendJSON`.
- JSON backend proxy behavior is covered through typed `GetIndustrialAnalysis`.
- Multipart backend proxy behavior is covered through typed `ImportMiscModulePackageFromPath`.
- Backend exported `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText` still exist until a dedicated deletion round updates generated Wails bindings and frontend inventory together.

Round 34 update:

- Backend/generated generic IPC binding cleanup is now deletion-completed.
- Backend exported `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText` methods are removed.
- Generated Wails `DesktopApp.d.ts` and `DesktopApp.js` no longer export `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`.
- `desktopTransportBindingShell.ts` no longer declares `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`.
- `ipcBackendTransport.ts` legacy adapter inventory is deleted.
- Shared `DesktopIpcRequestError`, `IpcBackendTransport`, `withDesktopIpcControls`, and blob limit checks moved to `desktopIpcControls.ts`.
- `check-wails-bindings` no longer has a `generic-ipc` group; it now rejects removed `InvokeBackend*` bindings.
- `frontend/scripts/check-desktop-old-binding-compat.mjs` no longer allows `ipcBackendTransport.ts` `InvokeBackend*` inventory.
- Browser-dev HTTP/SSE remains independent from this cleanup.

Round 35 update:

- Post-removal monitoring is now CI-enforced by `frontend/scripts/check-desktop-generic-ipc-post-removal-monitor.mjs`.
- `pnpm run ci` runs `desktop-generic-ipc-post-removal:check`.
- The monitor blocks restored `ipcBackendTransport.ts`, restored `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`, restored `createIpcBackendTransport`, stale README wording, stale tracker audit evidence, and missing CI wiring.
- README now documents typed IPC first, `generic_ipc_disabled` fail-fast, browser-dev HTTP/SSE retained, and Wails runtime events retained.
- Round 35 did not change runtime transport and reused Round 34 post-removal Wails smoke evidence.

Next safe step:

- Round 36 final closure audit is complete.
- Full gates, `build:wails`, desktop assets, post-removal monitor, removal preflight, binding cleanup preflight, Wails binding, old-binding compatibility, desktop release smoke, WebView typed smoke, and browser-dev smoke are green.
- WebView typed smoke records `directBackendApiRequestCount = 0`, `totalInstrumentedNetworkRequests = 0`, `genericIpcPolicy = disabled`, and `genericIpcDisableExperimentBuildFlag = true`.
- Remaining old generated binding access is shell/control-plane compatibility only: backend auth token, native file/dialog/update APIs, and `window.go.main.DesktopApp` discovery.
- Do not treat shell/control-plane compatibility methods as data-plane migration debt unless they begin carrying business-domain payloads.
- Do not restore generic IPC data-plane without a deliberate rollback plan.

## Non-goals

- Do not remove browser-dev HTTP/SSE debugging.
- Do not rewrite historical archive reports to match this final plan.
- Do not treat shell/update/dialog methods as data-plane debt unless they start carrying business domain payloads.
