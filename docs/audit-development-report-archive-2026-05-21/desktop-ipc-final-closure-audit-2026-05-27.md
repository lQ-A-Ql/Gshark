# Desktop IPC Final Closure Audit - 2026-05-27

## 迁移域与目标

- Round: 36
- Phase: post-phase-5
- Primary domain: final closure audit
- Goal: close the Desktop IPC migration with fresh full gates, Wails build, post-removal guardrails, and real desktop/browser smoke evidence after generic IPC adapter and backend/generated `InvokeBackend*` deletion.

## 修改面清单

- No data-plane runtime code change in this round.
- Updated `docs/desktop-ipc-iteration-status.json` to mark the final closure audit as completed.
- Updated `docs/desktop-ipc-migration-plan.md`.
- Updated `docs/desktop-ipc-old-binding-exit-plan.md`.
- Added this round report.
- Appended `docs/开发记录.md`.

## Focused Test 结果

Passed:

```text
cd frontend
pnpm exec vitest run src/app/integrations/desktopBridge.test.ts src/app/integrations/desktopDisabledGenericIpcTransport.test.ts src/app/integrations/desktopIpcControls.test.ts scripts/check-desktop-generic-ipc-post-removal-monitor.test.mjs scripts/check-desktop-generic-ipc-removal-preflight.test.mjs scripts/check-desktop-generic-ipc-binding-cleanup-preflight.test.mjs scripts/check-desktop-old-binding-compat.test.mjs
```

Result:

```text
7 files / 63 tests passed
```

## Full Gate 结果

Passed:

```text
go test -tags dev ./...
go test -tags production ./...
cd backend && go test ./...
cd frontend && pnpm run ci
cd frontend && pnpm run build:wails
```

Frontend CI result:

```text
238 files / 766 tests passed
```

Additional guardrails passed:

```text
node frontend/scripts/check-desktop-generic-ipc-post-removal-monitor.mjs
node frontend/scripts/check-desktop-generic-ipc-removal-preflight.mjs
node frontend/scripts/check-desktop-generic-ipc-binding-cleanup-preflight.mjs
node frontend/scripts/check-desktop-old-binding-compat.mjs
node frontend/scripts/check-wails-bindings.mjs
```

`build:wails` also ran the desktop asset check successfully.

## 桌面/浏览器行为差异说明

- Desktop release: typed IPC first, no frontend generic IPC adapter construction, no backend/generated `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`.
- Desktop WebView typed path: migrated data-plane routes stay on typed IPC; missing migrated coverage fails with `generic_ipc_disabled`.
- Browser dev: HTTP/SSE remains intentional debugging compatibility and is not removed.
- Shell/control-plane compatibility remains allowed for auth token, native dialogs, update APIs, and `window.go.main.DesktopApp` discovery. These are not data-plane migration debt unless they start carrying business-domain payloads.

## Smoke 结果

Passed:

```text
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1
```

Summary:

```text
output/desktop-ipc-smoke/desktop-ipc-smoke-summary.json
updatedAt = 2026-05-27T01:33:26.3887959+08:00
desktopRelease.ok = true
desktopWebviewTyped.ok = true
browserDev.ok = true
desktopWebviewTyped.directBackendApiRequestCount = 0
desktopWebviewTyped.totalInstrumentedNetworkRequests = 0
desktopWebviewTyped.genericIpcPolicy = disabled
desktopWebviewTyped.genericIpcDisableExperimentBuildFlag = true
desktopWebviewTyped.capturePackets = 7074
desktopWebviewTyped.httpStreams = 119
desktopWebviewTyped.tcpStreams = 177
desktopWebviewTyped.udpStreams = 54
desktopWebviewTyped.objectCount = 205
desktopWebviewTyped.objectEvidenceCount = 205
```

Browser-dev also verified HTTP/SSE with:

```text
browserDev.frontendStatus = 200
browserDev.health = ok
browserDev.sseFirstLine = event: ready
browserDev.capturePackets = 7074
browserDev.httpStreams = 119
browserDev.objectCount = 205
```

## 评分

Total: 99 / 100

- Contract Correctness: 25 / 25
- Desktop Policy Compliance: 20 / 20
- Regression Safety: 20 / 20
- Diagnostics and Failure Shape: 15 / 15
- Docs and Traceability: 10 / 10
- Dev/Browser Compatibility: 9 / 10

Dev/browser compatibility lost 1 point only because this was a scripted smoke rather than a human interactive exploratory smoke session. The automated browser-dev and desktop WebView evidence is green.

## 自迭代记录

- Round 35 recommended final closure audit after post-removal monitoring was wired into CI.
- Round 36 selected closure audit instead of shell compatibility wording cleanup because no blocker existed and shell/control-plane compatibility was already explicit enough for closure.
- All hard blocker gates passed.
- Tracker state is now final-closure-completed.

## Open Blockers

None.

## 下一轮自动建议

Maintenance-only unless explicitly scoped:

- Keep browser-dev HTTP/SSE.
- Keep shell/control-plane compatibility methods as compatibility, not data-plane debt.
- Keep post-removal monitor in CI.
- Do not restore generic IPC data-plane without a deliberate rollback plan.
