# Desktop IPC Generic IPC Post-Removal Monitor - 2026-05-27

## 迁移域与目标

- Round: 35
- Phase: post-phase-5
- Primary domain: generic IPC post-removal monitoring guardrail
- Goal: make the Round 34 backend/generated `InvokeBackend*` deletion continuously enforceable by CI, and fix stale current documentation that still described WebView data-plane traffic as `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`.

## 修改面清单

- Added `frontend/scripts/check-desktop-generic-ipc-post-removal-monitor.mjs`.
- Added `frontend/scripts/check-desktop-generic-ipc-post-removal-monitor.test.mjs`.
- Wired `desktop-generic-ipc-post-removal:check` into `frontend/package.json` and `pnpm run ci`.
- Updated `README.md` desktop IPC wording to the current post-removal contract:
  - typed IPC first
  - `generic_ipc_disabled` fail-fast for missing migrated data-plane coverage
  - browser-dev HTTP/SSE retained
  - Wails runtime events retained
  - no stale `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText` data-plane wording
- Updated `docs/desktop-ipc-iteration-status.json`.
- Updated `docs/desktop-ipc-migration-plan.md`.
- Updated `docs/desktop-ipc-old-binding-exit-plan.md`.

## Focused Test 结果

Passed:

```text
cd frontend
pnpm exec vitest run scripts/check-desktop-generic-ipc-post-removal-monitor.test.mjs scripts/check-desktop-generic-ipc-removal-preflight.test.mjs scripts/check-desktop-generic-ipc-binding-cleanup-preflight.test.mjs scripts/check-desktop-old-binding-compat.test.mjs
```

Result:

```text
4 files / 30 tests passed
```

Additional focused guardrails passed:

```text
node frontend/scripts/check-desktop-generic-ipc-post-removal-monitor.mjs
node frontend/scripts/check-desktop-generic-ipc-removal-preflight.mjs
node frontend/scripts/check-desktop-generic-ipc-binding-cleanup-preflight.mjs
node frontend/scripts/check-desktop-old-binding-compat.mjs
node frontend/scripts/check-wails-bindings.mjs
```

## Full Gate 结果

Passed:

```text
go test -tags dev ./...
go test -tags production ./...
cd backend && go test ./...
cd frontend && pnpm run ci
cd frontend && pnpm run build:wails
git diff --check
```

Frontend CI result:

```text
238 files / 766 tests passed
```

`build:wails` also ran the desktop asset check successfully.

## 桌面/浏览器行为差异说明

- Desktop release remains typed IPC first.
- The frontend generic IPC adapter remains removed.
- Backend/generated `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText` remain removed.
- Missing migrated desktop data-plane coverage still fails with `generic_ipc_disabled`.
- Browser-dev HTTP/SSE remains intentional debugging compatibility and is not treated as debt.
- Round 35 did not change runtime transport. It reused Round 34 post-removal Wails smoke evidence rather than rerunning smoke.

Round 34 smoke evidence reused:

```text
directBackendApiRequestCount = 0
totalInstrumentedNetworkRequests = 0
genericIpcPolicy = disabled
genericIpcDisableExperimentBuildFlag = true
browserDev.ok = true
capturePackets = 7074
httpStreams = 119
objectCount = 205
```

## 评分

Total: 97 / 100

- Contract Correctness: 25 / 25
- Desktop Policy Compliance: 20 / 20
- Regression Safety: 20 / 20
- Diagnostics and Failure Shape: 15 / 15
- Docs and Traceability: 10 / 10
- Dev/Browser Compatibility: 7 / 10

Dev/browser compatibility lost 3 points because this guardrail-only round did not rerun browser-dev/Wails smoke. The runtime path was unchanged, and Round 34 smoke remains the current runtime evidence.

## 自迭代记录

- Initial post-removal monitor failed on real tree because `README.md` did not contain the exact current post-removal Wails runtime events wording.
- The failure was a useful documentation drift signal, not a runtime regression.
- README was updated to remove stale `InvokeBackend*` wording and state the current typed IPC / browser-dev split explicitly.
- After the README fix, the monitor passed on the real tree and in frontend CI.

## Open Blockers

None.

## 下一轮自动建议

Recommended next slice:

- Final closure audit with full gates and Wails smoke.
- Optional shell compatibility wording cleanup before closure if old generated binding docs still read like data-plane debt.

Do not restore generic IPC data-plane without a deliberate rollback plan.
