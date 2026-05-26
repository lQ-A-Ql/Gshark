# Desktop IPC generic final compatibility audit - 2026-05-26

Author: Codex

Timestamp: 2026-05-26 03:56:47 +08:00

## 迁移域与目标

- Round: 18
- Phase: post-phase-5
- Primary slice: Generic IPC final compatibility audit
- Goal: close stale desktop generic IPC compatibility wording after MISC list/import/delete/invoke became typed IPC for desktop release, without adding another business binding in this round.

## 修改面清单

- `frontend/scripts/check-desktop-misc-compat-inventory.mjs`
  - Reworded the guardrail from "compatibility inventory" to "transport inventory".
  - Removed duplicate migrated route entries from the allowed route set.
  - The passing CLI message now states that no MISC desktop compatibility routes remain.
- `frontend/scripts/check-desktop-misc-compat-inventory.test.mjs`
  - Updated the violation expectation for new MISC desktop routes.
- `docs/desktop-ipc-iteration-status.json`
  - Advanced `currentRound` to 18.
  - Recorded the final compatibility audit score and evidence.
  - Replaced stale MISC multipart compatibility exit criteria with the current desktop typed/browser-dev HTTP split.
- `docs/desktop-ipc-migration-plan.md`
  - Updated Phase 5 and post-phase typed-cycle wording to state that MISC runtime routes are typed for desktop release.
  - Added Round 18 completion evidence.
  - Set the next default slice to old generated binding exit planning.
- `docs/desktop-ipc-misc-native-binding-design.md`
  - Closed the MISC desktop compatibility window.
  - Clarified that browser-dev multipart upload remains HTTP debugging compatibility, not a desktop generic IPC exception.

## Focused test 结果

- `node frontend/scripts/check-desktop-generic-ipc-allowlist.mjs` - passed
- `node frontend/scripts/check-desktop-old-binding-compat.mjs` - passed
- `node frontend/scripts/check-desktop-transport-policy.mjs` - passed
- `node frontend/scripts/check-desktop-misc-compat-inventory.mjs` - passed
- `cd frontend && pnpm exec vitest run scripts/check-desktop-generic-ipc-allowlist.test.mjs scripts/check-desktop-old-binding-compat.test.mjs scripts/check-desktop-misc-compat-inventory.test.mjs scripts/check-desktop-transport-policy.test.mjs` - passed, 4 files / 14 tests

## Full gate 结果

- `go test -tags dev ./...` - passed
- `go test -tags production ./...` - passed
- `cd backend && go test ./...` - passed
- `cd frontend && pnpm run ci` - passed, including 231 frontend test files / 731 tests
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

- Desktop release remains typed IPC first for migrated domains.
- MISC runtime routes (`modules`, `import`, `delete`, `invoke`) are typed for desktop release.
- Browser-dev keeps HTTP multipart upload and HTTP/SSE debugging behavior.
- Old generated bindings remain guarded compatibility, not the approved path for new data-plane features.

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

Total: 98/100

- Contract Correctness: 24/25
  - No new typed binding was added; this was a final compatibility audit. Existing route classification and guardrail semantics were verified.
- Desktop Policy Compliance: 20/20
  - MISC desktop routes are no longer classified as compatibility routes; generic IPC remains limited to explicit non-domain compatibility and the guarded adapter.
- Regression Safety: 20/20
  - Focused guardrails, root Go dev/production tests, backend tests, frontend CI, Wails build, asset checks, binding checks, and smoke passed.
- Diagnostics and Failure Shape: 15/15
  - Guardrail failure wording now distinguishes unclassified MISC desktop route expansion from compatibility fallback.
- Docs and Traceability: 10/10
  - Tracker, plan, MISC design, round report, and development log were updated.
- Dev/Browser Compatibility: 9/10
  - Browser-dev HTTP/SSE remains green. One point is withheld because browser-dev multipart upload is intentionally retained and must remain distinguished from desktop release policy in future reviews.

## Open blockers

- None.

## 自迭代记录

- Hard blocker check: none hit.
- Score threshold: 98 >= 90.
- Decision: advance to the next post-phase compatibility governance slice.
- Reasoning: The remaining issue is no longer a migrated business domain. The next highest-value slice is to plan the old generated binding exit criteria without prematurely removing the adapter.

## 下一轮自动建议

Old generated binding exit planning:

- Do not remove `InvokeBackendJSON/Blob/Text` yet.
- Document the intentional old-binding shell/update/dialog/auth-token uses.
- Define the multi-round green-smoke trigger for retiring the generic IPC adapter.
- Keep browser-dev HTTP/SSE untouched.
