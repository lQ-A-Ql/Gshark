# Desktop IPC typed migration plan

> Product branding is `meow~traffic`; internal compatibility identifiers such as `gshark`, `sentinel`, `GSHARK_*`, and `sentinel-backend.exe` remain current implementation names.

This document is the versioned control plan for moving the Wails desktop build from generic backend IPC proxy calls toward typed IPC domain bindings. Local round reports may contain detailed evidence, but the current migration policy and phase status should be reflected here and in `docs/desktop-ipc-iteration-status.json`.

## Transport policy

- Desktop release: prefer typed Wails IPC for migrated domains, fall back to generic IPC only for domains that are not typed yet, and do not silently fall back to browser HTTP when a typed IPC method exists but fails.
- Desktop dev with current bindings: same as desktop release for typed IPC failures; generic IPC remains the data-plane fallback for domains that have not been typed yet.
- Browser dev without Wails bindings: keep HTTP and EventSource fallback for local debugging.
- Old generated bindings: short-term compatibility only. They can use fallback paths when a method is missing, but new desktop-facing capabilities should not be added through that path.

## Iteration rules

- Each development round should migrate one primary domain and may include one cross-domain cleanup.
- A round must record the migration target, changed surface, focused tests, full gates when run, desktop/browser behavior, score, blockers, and recommended next slice.
- A hard blocker forces the next round to stay on blocker repair before any new domain migration.
- `docs/governance-defect-register.json` remains reserved for project-level architecture defects; this IPC migration uses its own tracker.

## Score model

Each round is scored out of 100:

- Contract Correctness: 25
- Desktop Policy Compliance: 20
- Regression Safety: 20
- Diagnostics and Failure Shape: 15
- Docs and Traceability: 10
- Dev/Browser Compatibility: 10

Decision thresholds:

- 90 or above: the round can advance to the next domain or phase.
- 80 to 89: functionality is usable, but the next round must stay in the current phase for cleanup.
- Below 80: the next round must repair blockers only.

Hard blockers:

- `go test -tags dev ./...` fails.
- `cd backend && go test ./...` fails.
- `cd frontend && pnpm run ci` fails.
- `cd frontend && pnpm run build:wails` fails.
- `node frontend/scripts/check-wails-bindings.mjs` fails.
- A migrated desktop domain still performs direct WebView requests to `127.0.0.1:17891/api/...`.
- Desktop release silently falls back to HTTP after a typed IPC method exists and fails.
- `docs/desktop-ipc-iteration-status.json` is not updated.

## Phase status

| Phase | Domain | Status | Completion rule |
|---|---|---|---|
| 0 | Iteration governance and tracker | completed | Plan and JSON tracker exist; round scoring template is documented. |
| 1 | Transport policy | completed | Binding groups are checked; typed control-plane failures do not silently fall back to browser HTTP; `scripts/check-desktop-ipc-smoke.ps1` covers Wails bootstrap, browser-dev HTTP/SSE, and real Wails WebView typed smoke with zero direct backend `/api` requests observed. |
| 2 | Stream typed IPC | completed | Stream and packet-detail read/write calls have typed DesktopApp methods and desktopBridge routes; real Wails WebView typed smoke loads HTTP stream 29 and verifies stream indexes without WebView direct backend `/api` requests. |
| 3 | Object, security material, tooling | completed | Object, WinRM, SMB3, NTLM, protocol-tool reads have typed DesktopApp methods and desktopBridge routes; real Wails WebView typed smoke covers objects and HTTP-login tooling without WebView direct backend `/api` requests. |
| 4 | Analysis and evidence | completed | Main analysis and evidence calls have typed DesktopApp methods and desktopBridge routes; real Wails WebView typed smoke covers industrial analysis and object-filtered evidence without WebView direct backend `/api` requests. |
| 5 | Generic IPC tightening | completed | Desktop generic IPC is restricted to explicit non-domain compatibility paths such as upload/events/runtime identity/health and the guarded old binding adapter; MISC runtime routes are typed for desktop release, browser-dev keeps HTTP multipart upload, and runtime generic IPC rejects requests when a typed binding already covers the route. |

## Manual smoke checklist

Machine preflight:

- Run `powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1`.
- Confirm the script reports Wails release bootstrap success, real Wails WebView typed smoke success, browser-dev HTTP/SSE success, opened `http.pcap`, non-empty packet page, HTTP stream sample, industrial analysis, object evidence, and object/tooling API probes.
- Confirm `desktopWebviewTyped.directBackendApiRequestCount = 0` in `output/desktop-ipc-smoke/desktop-ipc-smoke-summary.json`.
- Confirm the WebView typed smoke result includes `mediaTotalPackets` and `mediaSessionCount`; `0` is an acceptable business-empty result for samples without media sessions, not a transport failure.
- Confirm the Wails bootstrap log does not contain `error parsing arguments`, `expected 0`, or `process message error` for typed zero-argument bindings.

Desktop Wails:

- Open a PCAP.
- Verify packet page loading.
- Open one HTTP or TCP stream.
- Run one analysis page.
- Run an evidence filter.
- Open an object or tooling page.
- Confirm migrated domains do not appear as direct WebView fetches to backend `/api/...` in DevTools Network.

Browser dev:

- Start frontend dev mode without Wails bindings.
- Confirm HTTP and EventSource fallback still work.
- Confirm desktop-only typed IPC policy does not block browser debugging.

## Post-phase typed cycles

| Round | Domain | Status | Completion evidence |
|---|---|---|---|
| 4 | Runtime generic IPC guardrail for migrated typed routes | completed | `createIpcBackendTransport` rejects generic IPC when the matching typed binding exists. |
| 5 | Media typed IPC | completed | Media analysis, transcription, batch lifecycle, artifact export, batch export, and playback have typed DesktopApp methods, typed frontend overrides, route-to-binding guardrails, Go contract tests, frontend integration tests, Wails binding checks, and WebView smoke coverage. |
| 6 | Packet locate/full packet read typed IPC | completed | `LocatePacketPage` and `GetPacket` have typed DesktopApp methods, typed frontend overrides, route-to-binding guardrails, Go contract tests, frontend integration tests, Wails binding checks, and WebView smoke coverage for sampled packet locate/detail. |
| 7 | Hunting typed IPC | completed | `ListThreatHits`, `GetHuntingRuntimeConfig`, and `UpdateHuntingRuntimeConfig` have typed DesktopApp methods, typed frontend overrides, route-to-binding guardrails, Go contract tests, frontend integration tests, Wails binding checks, and WebView smoke coverage for threat hunting plus runtime config. |
| 8 | Vehicle DBC management typed IPC | completed | `ListVehicleDBCProfiles`, `AddVehicleDBC`, and `RemoveVehicleDBC` have typed DesktopApp methods, typed frontend overrides, route-to-binding guardrails, Go contract tests, frontend integration tests, Wails binding checks, and WebView smoke coverage for DBC profile listing. |
| 9 | Plugin management typed IPC | completed | `ListPlugins`, `GetPluginSource`, `SavePluginSource`, `AddPlugin`, `DeletePlugin`, `TogglePlugin`, and `SetPluginsEnabled` have typed DesktopApp methods, typed frontend overrides, route-to-binding guardrails, Go contract tests, frontend integration tests, Wails binding checks, and WebView smoke coverage for plugin listing. |
| 10 | Generic IPC allowlist guardrail | completed | `frontend/scripts/check-desktop-generic-ipc-allowlist.mjs` classifies client `/api` route literals as migrated typed routes or explicit compatibility routes; CI now runs `desktop-generic-ipc:check`; WebView smoke still reports `directBackendApiRequestCount = 0`. |
| 11 | Old generated binding compatibility guardrail | completed | `frontend/scripts/check-desktop-old-binding-compat.mjs` restricts direct old generated DesktopApp binding reads to backend auth token, native file/dialog/update shell features, the single generic IPC adapter, and typed bridge ownership; CI now runs `desktop-old-binding:check`; WebView smoke still reports `directBackendApiRequestCount = 0`. |
| 12 | MISC multipart native-binding design | completed | `docs/desktop-ipc-misc-native-binding-design.md` recorded the MISC generic route inventory and target typed method shape; `frontend/scripts/check-desktop-misc-compat-inventory.mjs` now verifies those routes are classified as migrated typed desktop routes with no remaining MISC desktop compatibility routes; CI runs `desktop-misc-compat:check`; WebView smoke still reports `directBackendApiRequestCount = 0`. |
| 13 | MISC ListMiscModules typed IPC | completed | `ListMiscModules` has a typed DesktopApp method, frontend typed override, Go contract test, Wails binding check coverage, runtime generic IPC block, MISC inventory split between migrated list and remaining import/delete/invoke compatibility, and WebView smoke evidence with `miscModuleCount = 8` plus `directBackendApiRequestCount = 0`. |
| 14 | MISC mutating package-state isolation boundary | completed | `scripts/check-desktop-ipc-smoke.ps1` now creates per-run MISC package directories under `output/desktop-ipc-smoke/misc-packages` for desktop release, desktop WebView, and browser-dev; WebView smoke records `miscPackageDir` and `backendMiscPackageDir`, verifies they match, and keeps `directBackendApiRequestCount = 0`. |
| 15 | MISC DeleteMiscModulePackage typed IPC | completed | `DeleteMiscModulePackage` has a typed DesktopApp method, frontend typed override, Go contract test, Wails binding check coverage, runtime generic IPC block, and WebView smoke evidence with `miscDeleteBindingAvailable = true` plus `directBackendApiRequestCount = 0`. At this point import/invoke were still open follow-up slices. |
| 16 | MISC RunMiscModulePackage typed IPC | completed | `RunMiscModulePackage` has a typed DesktopApp method, frontend typed override, Go contract test for the invoke route/body, Wails binding check coverage, runtime generic IPC block, and WebView smoke evidence with `miscRunBindingAvailable = true` plus `directBackendApiRequestCount = 0`. At this point multipart import was still the only MISC follow-up slice. |
| 17 | MISC ImportMiscModulePackageFromPath typed IPC | completed | `SelectMiscModulePackage` and `ImportMiscModulePackageFromPath` complete desktop native import: Wails carries a local zip path, DesktopApp forwards multipart to the existing backend import route, browser-dev keeps multipart HTTP, generic import IPC is blocked when typed import exists, and WebView smoke confirms `miscImportBindingAvailable = true` plus `directBackendApiRequestCount = 0`. |
| 18 | Generic IPC final compatibility audit | completed | `frontend/scripts/check-desktop-misc-compat-inventory.mjs` now reports a MISC transport inventory with no remaining MISC desktop compatibility routes; the plan/tracker distinguish desktop typed MISC runtime from browser-dev multipart upload, and remaining generic IPC compatibility is limited to upload/events/runtime identity/health plus guarded old generated binding exceptions. |
| 19 | Old generated binding exit planning | completed | `docs/desktop-ipc-old-binding-exit-plan.md` records the remaining approved old generated binding uses and the removal trigger for `InvokeBackendJSON/Blob/Text`; `frontend/scripts/check-desktop-old-binding-compat.mjs` now verifies both code-level compatibility exceptions and the exit-plan tokens. |
| 20 | Generic IPC adapter disablement experiment | completed | `VITE_DESKTOP_DISABLE_GENERIC_IPC=1` is now a default-off build-time experiment flag. When enabled, `createDesktopBridge` avoids `createIpcBackendTransport`; missing typed data-plane routes fail with `generic_ipc_disabled` instead of generic IPC or browser HTTP fallback, while typed overrides and Wails runtime event subscription stay active. `scripts/check-desktop-ipc-smoke.ps1 -DisableGenericIpcAdapterExperiment` validates the smoke was built with the flag and records `genericIpcDisableExperimentBuildFlag = true`; the disabled-adapter smoke passed with `directBackendApiRequestCount = 0` and browser-dev HTTP/SSE green. |
| 21 | Generic IPC adapter retirement readiness audit | completed | `frontend/scripts/check-desktop-generic-ipc-retirement-readiness.mjs` is now a CI guardrail. It keeps the disablement experiment default-off, requires source tokens for the disabled adapter and smoke switch, requires tracker smoke evidence with `genericIpcDisableExperimentBuildFlag = true`, `directBackendApiRequestCount = 0`, and browser-dev green, and verifies `frontend` CI runs the check. Production/default assets remain adapter-enabled; no adapter removal happened in this round. |
| 22 | Production-default generic IPC adapter disablement preflight | completed | `frontend/src/app/integrations/desktopGenericIpcPolicy.ts` adds an explicit policy resolver: default `compat`, `VITE_DESKTOP_GENERIC_IPC_POLICY=disabled` for preflight disablement, and legacy `VITE_DESKTOP_DISABLE_GENERIC_IPC=1` as the Round 20 alias. WebView smoke now records `genericIpcPolicy`. Normal smoke passed with `genericIpcPolicy=compat`; disabled-policy smoke passed with `genericIpcPolicy=disabled`, `directBackendApiRequestCount = 0`, and browser-dev green. Adapter code was not removed and default assets were restored to adapter-enabled. |
| 23 | Default-disabled release-candidate rollback guard | completed | `frontend/scripts/check-desktop-generic-ipc-rollback-guard.mjs` is now wired into `pnpm run ci`. It requires `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` to remain documented and tested as the adapter-enabled rollback/override path, including explicit compat overriding legacy `VITE_DESKTOP_DISABLE_GENERIC_IPC=1`. Default Wails smoke passed with `genericIpcPolicy=compat`, `directBackendApiRequestCount = 0`, and browser-dev green. Adapter code was not removed. |
| 24 | Default-disabled release-candidate decision | completed | `frontend/src/app/integrations/desktopGenericIpcPolicy.ts` now defaults to `disabled`; compatibility-only generic IPC fallback tests explicitly opt into `VITE_DESKTOP_GENERIC_IPC_POLICY=compat`. `frontend/scripts/check-desktop-generic-ipc-retirement-readiness.mjs` now requires the release-candidate default-disabled policy and tracker rollback evidence. Default-disabled smoke passed with `genericIpcPolicy=disabled`, `directBackendApiRequestCount = 0`, and browser-dev green; explicit compat rollback smoke passed with `genericIpcPolicy=compat`. Adapter code is still present and final assets were rebuilt as default-disabled. |
| 25 | Default-disabled observation guard | completed | `frontend/scripts/check-desktop-generic-ipc-retirement-readiness.mjs` now requires `genericIpcAdapterDefaultDisabledReleaseCandidate.observation` in the tracker, blocks adapter removal before three consecutive green default-disabled observation rounds, and verifies each counted round records default-disabled smoke, compat rollback smoke, `directBackendApiRequestCount = 0`, and browser-dev green. Observation round 1/3 is green: frontend CI passed with 234 files / 755 tests, default-disabled smoke passed with `genericIpcPolicy=disabled`, compat rollback smoke passed with `genericIpcPolicy=compat`, and final assets were rebuilt default-disabled. Adapter code is still present. |

## Next default slice

The next slice should continue post-migration compatibility governance rather than add another business binding. Desktop MISC runtime routes are typed; browser-dev multipart upload remains an HTTP debugging path, not a desktop generic IPC exception. Current generic IPC compatibility categories are limited to capture upload, events, runtime identity, health, ffmpeg/speech tool compatibility, approved shell/auth/dialog old-binding uses, and the single guarded generic IPC adapter.

Recommended next domain: default-disabled observation round 2. Do not remove the adapter code yet. The next automated decision must be based on CI, default-disabled Wails smoke, explicit `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` rollback smoke, rollback guard green, `desktopWebviewTyped.directBackendApiRequestCount = 0`, browser-dev green, and unchanged approved shell/auth/dialog old-binding uses.

## Development note 2026-05-25

- Author: Codex
- Time: 2026-05-25 00:28:09 +08:00
- Phase Audit result: Phase 1-5 are marked `completed` because `scripts/check-desktop-ipc-smoke.ps1` now includes a real Wails WebView typed harness. The harness opened `http.pcap`, verified 7074 packets, 119 HTTP streams, 177 TCP streams, 54 UDP streams, 205 objects, 205 object evidence records, industrial analysis, HTTP-login tooling, and `directBackendApiRequestCount = 0`.
- Follow-up guardrail: `createIpcBackendTransport` now rejects generic IPC for migrated routes when the matching typed binding exists, while preserving only explicit non-domain compatibility routes and browser-dev HTTP/SSE debugging.

## Development note 2026-05-25 media typed IPC

- Author: Codex
- Time: 2026-05-25 22:03:41 +08:00
- Round result: media typed IPC is complete for `GetMediaAnalysis`, `TranscribeMediaArtifact`, `StartMediaBatchTranscription`, `GetMediaBatchTranscriptionStatus`, `CancelMediaBatchTranscription`, `ExportMediaBatchTranscription`, `DownloadMediaArtifact`, and `GetMediaPlaybackBlob`.
- Transport policy: desktop typed media calls now use `desktopTypedBridgeMedia.ts`; matching `/api/analysis/media*` generic IPC paths are blocked when the typed binding exists. Browser-dev keeps HTTP/SSE fallback.
- Smoke evidence: real Wails WebView typed smoke opened `http.pcap`, verified 7074 packets, 119 HTTP streams, 177 TCP streams, 54 UDP streams, 205 objects, 205 object evidence records, and `directBackendApiRequestCount = 0`. The same smoke called `GetMediaAnalysis(false)` and recorded `mediaTotalPackets = 0`, `mediaSessionCount = 0`, which is treated as a valid business-empty sample result.

## Development note 2026-05-25 packet locate/read typed IPC

- Author: Codex
- Time: 2026-05-25 22:31:00 +08:00
- Round result: packet locate/full packet read typed IPC is complete for `LocatePacketPage` and `GetPacket`.
- Transport policy: desktop packet locate/detail calls now use `desktopTypedBridgePacket.ts`; matching `/api/packets/locate` and `/api/packet` generic IPC paths are blocked when the typed binding exists. Browser-dev keeps HTTP/SSE fallback.
- Smoke evidence: real Wails WebView typed smoke opened `http.pcap`, verified `sampledPacketId = 1`, `locatedPacketFound = true`, `locatedPacketCursor = 0`, `packetDetailProtocol = IGMPv3`, and `directBackendApiRequestCount = 0`.

## Development note 2026-05-25 hunting typed IPC

- Author: Codex
- Time: 2026-05-25 23:18:00 +08:00
- Round result: hunting typed IPC is complete for `ListThreatHits`, `GetHuntingRuntimeConfig`, and `UpdateHuntingRuntimeConfig`.
- Transport policy: desktop hunting calls now use `desktopTypedBridgeHunting.ts`; matching `/api/hunting` and `/api/hunting/config` generic IPC paths are blocked when the typed binding exists. Browser-dev keeps HTTP/SSE fallback.
- Diagnostics fix: YARA scan config now preflights executable/rule availability before building full stream scan targets. A host without `yara.exe` returns an explicit `YARA 扫描异常` warning instead of causing the desktop WebView smoke to wait for a long context deadline.
- Smoke evidence: real Wails WebView typed smoke opened `http.pcap`, verified `threatHitCount = 721`, `huntingPrefixCount = 2`, `huntingYaraEnabled = true`, and `directBackendApiRequestCount = 0`.

## Development note 2026-05-25 vehicle DBC typed IPC

- Author: Codex
- Time: 2026-05-25 23:50:00 +08:00
- Round result: vehicle DBC management typed IPC is complete for `ListVehicleDBCProfiles`, `AddVehicleDBC`, and `RemoveVehicleDBC`.
- Transport policy: desktop vehicle DBC calls now use `desktopTypedBridgeVehicleDbc.ts`; matching `/api/analysis/vehicle/dbc` generic IPC paths are blocked when the typed binding exists. Browser-dev keeps HTTP/SSE fallback.
- Smoke evidence: real Wails WebView typed smoke opened `http.pcap`, verified `vehicleDBCProfileCount = 0` as an acceptable business-empty result, retained `capturePackets = 7074`, `threatHitCount = 721`, `objectCount = 205`, and kept `directBackendApiRequestCount = 0`.

## Development note 2026-05-26 plugin management typed IPC

- Author: Codex
- Time: 2026-05-26 00:12:00 +08:00
- Round result: plugin management typed IPC is complete for `ListPlugins`, `GetPluginSource`, `SavePluginSource`, `AddPlugin`, `DeletePlugin`, `TogglePlugin`, and `SetPluginsEnabled`.
- Transport policy: desktop plugin management calls now use `desktopTypedBridgePlugin.ts`; matching `/api/plugins*` generic IPC paths are blocked when the typed binding exists. Browser-dev keeps HTTP/SSE fallback.
- Safety note: WebView smoke only reads plugin list to avoid mutating trusted local plugin state; source/save/add/delete/toggle/bulk route correctness is covered by Go contract and frontend integration tests.
- Smoke evidence: real Wails WebView typed smoke opened `http.pcap`, verified `pluginCount = 0` as an acceptable business-empty result, retained `capturePackets = 7074`, `threatHitCount = 721`, `objectCount = 205`, and kept `directBackendApiRequestCount = 0`.

## Development note 2026-05-26 generic IPC allowlist guardrail

- Author: Codex
- Time: 2026-05-26 01:53:12 +08:00
- Round result: generic IPC client route expansion is now guarded by `frontend/scripts/check-desktop-generic-ipc-allowlist.mjs` and CI script `desktop-generic-ipc:check`.
- Transport policy: client `/api` route literals under `src/app/integrations/clients` must be classified as already migrated typed routes or explicit compatibility routes. MISC modules/import/delete/invoke are now migrated typed desktop routes; new unclassified business routes fail the guardrail.
- Validation evidence: focused tests covered generic allowlist, desktop bridge, and IPC transport behavior; full gates passed through root dev/production Go tests, backend Go tests, frontend CI, `build:wails`, binding checks, transport policy checks, generic allowlist, desktop assets, and Wails smoke.
- Smoke evidence: real Wails WebView typed smoke opened `http.pcap`, retained `capturePackets = 7074`, `threatHitCount = 721`, `objectCount = 205`, `pluginCount = 0`, and kept `directBackendApiRequestCount = 0`; browser-dev HTTP/SSE remained green.

## Development note 2026-05-26 old generated binding compatibility guardrail

- Author: Codex
- Time: 2026-05-26 02:01:20 +08:00
- Round result: old generated DesktopApp binding compatibility is now guarded by `frontend/scripts/check-desktop-old-binding-compat.mjs` and CI script `desktop-old-binding:check`.
- Compatibility policy: direct old generated binding access is limited to `backendClients.ts` for `window.go.main.DesktopApp`, `httpBridge.ts` for `GetBackendAuthToken`, `ipcBackendTransport.ts` for `InvokeBackendJSON/Blob/Text`, `captureClient.ts` for `OpenCaptureDialog`, and `desktopClient.ts` for shell/update/DBC dialog methods. Typed data-plane calls remain owned by `desktopBridge.ts` and `desktopTypedBridge*.ts`.
- Validation evidence: focused tests passed for old-binding compatibility, generic allowlist, desktop bridge, and IPC transport; full gates passed through root dev/production Go tests, backend Go tests, frontend CI with 230 files / 723 tests, `build:wails`, binding checks, transport policy checks, generic allowlist, old-binding compatibility check, desktop assets, and Wails smoke.
- Smoke evidence: real Wails WebView typed smoke opened `http.pcap`, retained `capturePackets = 7074`, `threatHitCount = 721`, `objectCount = 205`, `pluginCount = 0`, and kept `directBackendApiRequestCount = 0`; browser-dev HTTP/SSE remained green.

## Development note 2026-05-26 generic IPC adapter disablement experiment

- Author: Codex
- Time: 2026-05-26 18:49:40 +08:00
- Round result: generic IPC adapter disablement is implemented as a default-off build-time experiment through `VITE_DESKTOP_DISABLE_GENERIC_IPC=1`.
- Transport policy: when the flag is enabled, `createDesktopBridge` does not create `createIpcBackendTransport`. Missing typed data-plane routes fail fast with `generic_ipc_disabled` and do not fall back to generic IPC or browser HTTP. Typed desktop overrides still work, and desktop event subscription continues through Wails runtime `EventsOn`.
- Smoke evidence: normal Wails smoke passed with `genericIpcDisableExperimentBuildFlag = false`; a second build with `VITE_DESKTOP_DISABLE_GENERIC_IPC=1` plus `scripts/check-desktop-ipc-smoke.ps1 -DisableGenericIpcAdapterExperiment` passed with `genericIpcDisableExperimentRequested = true`, `genericIpcDisableExperimentBuildFlag = true`, `directBackendApiRequestCount = 0`, 7074 packets, 119 HTTP streams, 205 objects, and browser-dev HTTP/SSE green.
- Safety note: final assets were rebuilt with the default `build:wails` after the experiment, so production/default desktop remains adapter-enabled until a later retirement audit explicitly removes it.

## Development note 2026-05-26 generic IPC adapter retirement readiness audit

- Author: Codex
- Time: 2026-05-26 19:02:28 +08:00
- Round result: generic IPC adapter retirement is now evidence-gated by `frontend/scripts/check-desktop-generic-ipc-retirement-readiness.mjs`, which is wired into `pnpm run ci` as `desktop-generic-ipc-retirement:check`.
- Guardrail policy: the check rejects default-on `VITE_DESKTOP_DISABLE_GENERIC_IPC` patterns, requires the disabled-adapter source/smoke/exit-plan tokens, and requires tracker evidence proving `genericIpcDisableExperimentBuildFlag = true`, `desktopWebviewDirectBackendApiRequestCount = 0`, and `browserDevOk = true`.
- Validation evidence: focused tests passed for readiness, generic allowlist, old-binding compatibility, desktop bridge, and IPC transport with 5 files / 58 tests. Full gates passed through root dev/production Go tests, backend Go tests, frontend CI with 232 files / 740 tests, `build:wails`, desktop assets, Wails binding, transport policy, generic allowlist, readiness, old-binding compatibility, MISC inventory, normal Wails smoke, and disabled-adapter experiment smoke.
- Safety note: the adapter was not removed and production/default desktop remains adapter-enabled. After the disabled-adapter smoke, default assets were restored with a normal `pnpm run build:wails`.

## Development note 2026-05-26 production-default generic IPC adapter disablement preflight

- Author: Codex
- Time: 2026-05-26 19:26:56 +08:00
- Round result: added `frontend/src/app/integrations/desktopGenericIpcPolicy.ts` as the explicit policy resolver for the desktop generic IPC adapter. Default remains `compat`; `VITE_DESKTOP_GENERIC_IPC_POLICY=disabled` is the Round 22 preflight switch; `VITE_DESKTOP_DISABLE_GENERIC_IPC=1` remains the legacy Round 20 experiment alias.
- Guardrail policy: `frontend/scripts/check-desktop-generic-ipc-retirement-readiness.mjs` now verifies the policy module tokens and rejects default-on disabled policy patterns. `desktopBridge` consumes the policy resolver, and WebView smoke records `genericIpcPolicy`.
- Validation evidence: focused tests passed for desktop policy, desktop bridge, retirement readiness, and old-binding compatibility with 4 files / 40 tests. Full gates passed through root dev/production Go tests, backend Go tests, frontend CI with 233 files / 747 tests, `build:wails`, desktop assets, Wails binding, transport policy, generic allowlist, retirement readiness, old-binding compatibility, MISC inventory, normal Wails smoke, and disabled-policy Wails smoke.
- Smoke evidence: normal smoke passed with `genericIpcPolicy = compat`, `genericIpcDisableExperimentBuildFlag = false`, `directBackendApiRequestCount = 0`, and browser-dev green. Disabled-policy smoke used `VITE_DESKTOP_GENERIC_IPC_POLICY=disabled`, passed with `genericIpcPolicy = disabled`, `genericIpcDisableExperimentBuildFlag = true`, `directBackendApiRequestCount = 0`, 7074 packets, 119 HTTP streams, 205 objects, and browser-dev green.
- Safety note: adapter code was not removed. After disabled-policy smoke, default assets were restored with a normal `pnpm run build:wails`.

## Development note 2026-05-26 default-disabled release-candidate rollback guard

- Author: Codex
- Time: 2026-05-26 19:39:00 +08:00
- Round result: added `frontend/scripts/check-desktop-generic-ipc-rollback-guard.mjs` and wired it into `pnpm run ci` as `desktop-generic-ipc-rollback:check`.
- Guardrail policy: the rollback guard requires `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` to remain documented and tested as the adapter-enabled rollback path, including explicit compat overriding legacy `VITE_DESKTOP_DISABLE_GENERIC_IPC=1`. `docs/desktop-ipc-old-binding-exit-plan.md` now treats that rollback path as an exit criterion before default-disabled release candidates or adapter retirement.
- Validation evidence: focused tests passed for rollback guard, retirement readiness, desktop generic IPC policy, and desktop bridge with 4 files / 40 tests. Full gates passed through root dev/production Go tests, backend Go tests, frontend CI with 234 files / 751 tests, `build:wails`, desktop assets, Wails binding, transport policy, generic allowlist, retirement readiness, rollback guard, old-binding compatibility, MISC inventory, and normal Wails smoke.
- Smoke evidence: normal smoke passed with `genericIpcPolicy = compat`, `genericIpcDisableExperimentBuildFlag = false`, `directBackendApiRequestCount = 0`, 7074 packets, 119 HTTP streams, 205 objects, and browser-dev green.
- Safety note: adapter code was not removed, and this round did not change default production behavior.

## Development note 2026-05-26 MISC native-binding design

- Author: Codex
- Time: 2026-05-26 02:08:54 +08:00
- Round result: MISC multipart/native binding migration now has a versioned design source at `docs/desktop-ipc-misc-native-binding-design.md`.
- Compatibility inventory: the remaining explicit generic IPC MISC routes are `GET /api/tools/misc/modules`, `POST /api/tools/misc/import`, `DELETE /api/tools/misc/packages/{id}`, and `POST /api/tools/misc/packages/{id}/invoke`. No new MISC generic route can be added without updating the design and guardrail.
- Proposed typed shape: `ListMiscModules`, `SelectMiscModulePackage`, `ImportMiscModulePackageFromPath`, `DeleteMiscModulePackage`, and `RunMiscModulePackage`. Runtime migration is deferred; the first safe implementation slice should start with non-mutating `ListMiscModules`.
- Validation evidence: focused tests passed for MISC inventory, generic allowlist, old-binding compatibility, tool client, and IPC transport; full gates passed through root dev/production Go tests, backend Go tests, frontend CI with 231 files / 726 tests, `build:wails`, binding checks, transport policy checks, generic allowlist, old-binding compatibility, MISC inventory, desktop assets, and Wails smoke.
- Smoke evidence: real Wails WebView typed smoke opened `http.pcap`, retained `capturePackets = 7074`, `threatHitCount = 721`, `objectCount = 205`, `pluginCount = 0`, and kept `directBackendApiRequestCount = 0`; browser-dev HTTP/SSE remained green.

## Development note 2026-05-26 MISC ListMiscModules typed IPC

- Author: Codex
- Time: 2026-05-26 02:24:08 +08:00
- Round result: the non-mutating MISC module list route is migrated to typed IPC through `ListMiscModules`.
- Transport policy: desktop MISC module listing now uses `desktopTypedBridgeMisc.ts`; matching `/api/tools/misc/modules` generic IPC is rejected when the typed binding exists. Browser-dev keeps the existing HTTP client path.
- Compatibility policy: MISC import/delete/invoke remain explicit generic IPC compatibility until temporary package-state isolation is available for mutating smoke. Multipart import is still deferred to a native file-path binding.
- Validation evidence: focused tests passed for desktop bridge, IPC transport, tool client, transport policy, generic allowlist, MISC inventory, and root Go contract tests; full gates passed through root dev/production Go tests, backend Go tests, frontend CI with 231 files / 727 tests, `build:wails`, binding checks, transport policy checks, generic allowlist, old-binding compatibility, MISC inventory, desktop assets, and Wails smoke.
- Smoke evidence: real Wails WebView typed smoke opened `http.pcap`, verified `miscModuleCount = 8`, retained `capturePackets = 7074`, `threatHitCount = 721`, `objectCount = 205`, `pluginCount = 0`, and kept `directBackendApiRequestCount = 0`; browser-dev HTTP/SSE remained green.

## Development note 2026-05-26 MISC mutating isolation boundary

- Author: Codex
- Time: 2026-05-26 02:43:13 +08:00
- Round result: the MISC mutating typed IPC prerequisite is complete. Smoke now allocates isolated package-state directories for desktop release, desktop WebView typed smoke, and browser-dev backend under `output/desktop-ipc-smoke/misc-packages`.
- Transport policy: no new mutating typed binding was added in this round. `ListMiscModules` remains the only migrated MISC method; `import/delete/invoke` remain explicit generic IPC compatibility until migrated one route per round.
- Diagnostics fix: backend `/api/runtime/identity` now exposes `misc_package_dir`, and `PingBackendDataPlane` returns it to the WebView smoke. The smoke asserts that the WebView-configured MISC directory matches the backend's actual MISC package directory.
- Validation evidence: focused tests passed for root dev Go, backend Go, and frontend typecheck; full gates passed through root dev/production Go tests, backend Go tests, frontend CI with 231 files / 727 tests, `build:wails`, binding checks, transport policy checks, generic allowlist, old-binding compatibility, MISC inventory, desktop assets, Wails smoke, and `git diff --check`.
- Smoke evidence: real Wails WebView typed smoke opened `http.pcap`, verified `miscModuleCount = 8`, retained `capturePackets = 7074`, `threatHitCount = 721`, `objectCount = 205`, `pluginCount = 0`, kept `directBackendApiRequestCount = 0`, and confirmed `miscPackageDir == backendMiscPackageDir == output/desktop-ipc-smoke/misc-packages/desktop-webview-*`; browser-dev used `output/desktop-ipc-smoke/misc-packages/browser-dev-*`.

## Development note 2026-05-26 MISC DeleteMiscModulePackage typed IPC

- Author: Codex
- Time: 2026-05-26 03:06:32 +08:00
- Round result: MISC package deletion is migrated to typed IPC through `DeleteMiscModulePackage`.
- Transport policy: desktop MISC deletion now uses `desktopTypedBridgeMisc.ts`; matching `DELETE /api/tools/misc/packages/{id}` generic IPC is rejected when the typed binding exists. Browser-dev keeps the HTTP client path.
- Type boundary cleanup: `DesktopTransportBinding` was split into focused shell/control/stream/tooling/analysis type fragments, and `check-wails-bindings.mjs` now checks the combined type surface without weakening grouped binding completeness checks.
- Validation evidence: focused tests passed for root dev Go, desktop bridge, IPC transport, tool client, transport policy, generic allowlist, and MISC inventory; full gates passed through root dev/production Go tests, backend Go tests, frontend CI with 231 files / 728 tests, `build:wails`, binding checks, transport policy checks, generic allowlist, old-binding compatibility, MISC inventory, desktop assets, Wails smoke, and `git diff --check`.
- Smoke evidence: real Wails WebView typed smoke opened `http.pcap`, verified `miscDeleteBindingAvailable = true` and `miscModuleCount = 8`, retained `capturePackets = 7074`, `threatHitCount = 721`, `objectCount = 205`, `pluginCount = 0`, kept `directBackendApiRequestCount = 0`, and confirmed isolated MISC package directories for desktop release, desktop WebView, and browser-dev.

## Development note 2026-05-26 MISC RunMiscModulePackage typed IPC

- Author: Codex
- Time: 2026-05-26 03:22:28 +08:00
- Round result: MISC package invocation is migrated to typed IPC through `RunMiscModulePackage`.
- Transport policy: desktop MISC invocation now uses `desktopTypedBridgeMisc.ts`; matching `POST /api/tools/misc/packages/{id}/invoke` generic IPC is rejected when the typed binding exists. Browser-dev keeps the HTTP client path.
- Safety note: WebView smoke only asserts binding availability and package-state isolation; it does not execute arbitrary user-provided MISC package code. Route/body correctness and mapper behavior are covered by root Go contract and frontend integration tests.
- Validation evidence: focused tests passed for root dev Go, frontend typecheck, desktop bridge, IPC transport, tool client, transport policy, generic allowlist, and MISC inventory; full gates passed through root dev/production Go tests, backend Go tests, frontend CI with 231 files / 729 tests, `build:wails`, binding checks, transport policy checks, generic allowlist, old-binding compatibility, MISC inventory, desktop assets, Wails smoke, and `git diff --check`.
- Smoke evidence: real Wails WebView typed smoke opened `http.pcap`, verified `miscRunBindingAvailable = true`, `miscDeleteBindingAvailable = true`, and `miscModuleCount = 8`, retained `capturePackets = 7074`, `threatHitCount = 721`, `objectCount = 205`, `pluginCount = 0`, kept `directBackendApiRequestCount = 0`, and confirmed isolated MISC package directories for desktop release, desktop WebView, and browser-dev.

## Development note 2026-05-26 MISC ImportMiscModulePackageFromPath typed IPC

- Author: Codex
- Time: 2026-05-26 03:45:51 +08:00
- Round result: MISC package import is migrated to desktop typed IPC through `SelectMiscModulePackage` plus `ImportMiscModulePackageFromPath`.
- Transport policy: desktop import uses a native file picker and passes a local zip path to DesktopApp; DesktopApp forwards that file as multipart to the existing backend import route, so existing `miscpkg` zip validation remains authoritative. Matching `POST /api/tools/misc/import` generic IPC is rejected when the typed import binding exists. Browser-dev keeps multipart HTTP upload.
- UI boundary: existing browser upload remains available as `导入模块 ZIP`; desktop typed environments additionally expose `桌面原生导入`.
- Validation evidence: focused tests passed for root dev Go, frontend typecheck, desktop bridge, IPC transport, tool client, MISC catalog/UI, transport policy, generic allowlist, and MISC inventory; full gates passed through root dev/production Go tests, backend Go tests, frontend CI with 231 files / 731 tests, `build:wails`, binding checks, transport policy checks, generic allowlist, old-binding compatibility, MISC inventory, desktop assets, Wails smoke, and `git diff --check`.
- Smoke evidence: real Wails WebView typed smoke opened `http.pcap`, verified `miscImportBindingAvailable = true`, `miscRunBindingAvailable = true`, `miscDeleteBindingAvailable = true`, and `miscModuleCount = 8`, retained `capturePackets = 7074`, `threatHitCount = 721`, `objectCount = 205`, `pluginCount = 0`, kept `directBackendApiRequestCount = 0`, and confirmed isolated MISC package directories for desktop release, desktop WebView, and browser-dev.
