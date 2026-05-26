# Desktop IPC old generated binding exit plan - 2026-05-26

Author: Codex

Timestamp: 2026-05-26 04:05:09 +08:00

## 迁移域与目标

- Round: 19
- Phase: post-phase-5
- Primary slice: Old generated binding exit planning
- Goal: define a versioned exit plan for old generated DesktopApp binding compatibility without removing the generic IPC adapter in this round.

## 修改面清单

- `docs/desktop-ipc-old-binding-exit-plan.md`
  - Added the approved old generated binding inventory.
  - Added the exit trigger for retiring `InvokeBackendJSON`, `InvokeBackendBlob`, and `InvokeBackendText`.
  - Recorded the removal sequence and non-goals.
- `frontend/scripts/check-desktop-old-binding-compat.mjs`
  - Now validates both code-level old binding exceptions and required exit-plan tokens.
- `frontend/scripts/check-desktop-old-binding-compat.test.mjs`
  - Added fixture-backed exit-plan validation tests.
- `docs/desktop-ipc-iteration-status.json`
  - Advanced `currentRound` to 19.
  - Recorded approved old binding uses and the next recommended slice.
- `docs/desktop-ipc-migration-plan.md`
  - Added Round 19 completion evidence.
  - Updated the next default slice to generic IPC adapter disablement experiment design.

## Focused test 结果

- `node frontend/scripts/check-desktop-old-binding-compat.mjs` - passed
- `cd frontend && pnpm exec vitest run scripts/check-desktop-old-binding-compat.test.mjs` - passed, 1 file / 4 tests
- `git diff --check` - passed

## Full gate 结果

- `go test -tags dev ./...` - passed
- `go test -tags production ./...` - passed
- `cd backend && go test ./...` - passed
- `cd frontend && pnpm run ci` - passed after formatting the new test file, including 231 frontend test files / 732 tests
- `cd frontend && pnpm run build:wails` - passed
- `powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1` - passed
- `node frontend/scripts/check-wails-bindings.mjs` - passed
- `node frontend/scripts/check-desktop-transport-policy.mjs` - passed
- `node frontend/scripts/check-desktop-generic-ipc-allowlist.mjs` - passed
- `node frontend/scripts/check-desktop-old-binding-compat.mjs` - passed
- `node frontend/scripts/check-desktop-misc-compat-inventory.mjs` - passed
- `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1 -TimeoutSeconds 180` - passed
- `git diff --check` - passed

## 桌面/浏览器行为差异说明

- Desktop release keeps typed IPC first for migrated domains.
- The old generated generic IPC adapter remains present but guarded; no production removal happened in this planning round.
- Browser-dev HTTP/SSE remains an explicit compatibility requirement and is named as a non-goal for removal.
- Shell/update/dialog/auth-token methods remain old-binding approved uses until each gets a separate typed shell contract or is intentionally retained as shell API.

## Smoke 证据

Source: `output/desktop-ipc-smoke/desktop-ipc-smoke-summary.json`

- `desktopRelease.ok = true`
- `desktopWebviewTyped.ok = true`
- `browserDev.ok = true`
- `desktopWebviewTyped.capturePackets = 7074`
- `desktopWebviewTyped.threatHitCount = 721`
- `desktopWebviewTyped.objectCount = 205`
- `desktopWebviewTyped.miscModuleCount = 8`
- `desktopWebviewTyped.miscImportBindingAvailable = true`
- `desktopWebviewTyped.miscDeleteBindingAvailable = true`
- `desktopWebviewTyped.miscRunBindingAvailable = true`
- `desktopWebviewTyped.directBackendApiRequestCount = 0`
- `browserDev.sseFirstLine = event: ready`

## 评分

Total: 97/100

- Contract Correctness: 24/25
  - The round did not change IPC method contracts; it codified the old generated binding exit contract and linked it to script validation.
- Desktop Policy Compliance: 20/20
  - Direct old generated data-plane calls remain blocked outside approved files; the generic adapter retirement trigger is now documented and checked.
- Regression Safety: 20/20
  - Focused tests, root Go dev/production tests, backend tests, frontend CI, Wails build, asset checks, binding checks, transport checks, and smoke passed.
- Diagnostics and Failure Shape: 14/15
  - Exit-plan token failures are explicit, but the actual adapter-disablement experiment is still a future slice.
- Docs and Traceability: 10/10
  - Tracker, plan, exit plan, round report, and development log were updated.
- Dev/Browser Compatibility: 9/10
  - Browser-dev remains green and explicitly protected. One point is withheld until the adapter-disablement experiment proves browser-dev is unaffected by release-only changes.

## Open blockers

- None.

## 自迭代记录

- Hard blocker check: none hit.
- Score threshold: 97 >= 90.
- Decision: advance to generic IPC adapter disablement experiment design.
- Reasoning: The old generated binding window now has a versioned exit plan and CI-backed token validation. The next safe step is designing a flag-gated adapter-disablement experiment, not removing production compatibility directly.

## 下一轮自动建议

Generic IPC adapter disablement experiment design:

- Do not remove production compatibility yet.
- Define a flag-gated or branch-local path that disables `createIpcBackendTransport` for desktop release.
- Run full gates plus Wails smoke with the adapter disabled.
- Only advance if `directBackendApiRequestCount = 0` and browser-dev HTTP/SSE remains green.
