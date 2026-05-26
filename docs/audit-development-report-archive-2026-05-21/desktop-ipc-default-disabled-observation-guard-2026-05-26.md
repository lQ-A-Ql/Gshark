# Desktop IPC Round 25 - default-disabled observation guard

Author: Codex  
Time: 2026-05-26 20:08:00 +08:00

## 迁移域与目标

本轮主域：generic IPC adapter default-disabled observation。

目标：

- 不删除 generic IPC adapter code。
- 不新增业务 typed binding。
- 将 “三轮 default-disabled 观察后才允许考虑 removal” 变成机器可判定的 tracker/guardrail。
- 继续保留 `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` rollback。

## 修改面清单

- `frontend/scripts/check-desktop-generic-ipc-retirement-readiness.mjs`
  - 新增 `genericIpcAdapterDefaultDisabledReleaseCandidate.observation` 校验。
  - 要求 `requiredConsecutiveGreenRoundsBeforeRemoval = 3`。
  - 要求当前 observation round 记录 `genericIpcPolicy = disabled`、`compatRollbackPolicy = compat`、`directBackendApiRequestCount = 0`、`browserDevOk = true`。
  - 若 `adapterRemoved = true` 且观察轮不足 3，直接判定违规。
- `frontend/scripts/check-desktop-generic-ipc-retirement-readiness.test.mjs`
  - 增加 premature adapter removal blocker 测试。
  - 增加 latest observation evidence 测试。
- `docs/desktop-ipc-iteration-status.json`
  - `currentRound = 25`。
  - `genericIpcAdapterDefaultDisabledReleaseCandidate.status = observation-round-1`。
  - 新增 observation 结构，记录当前 1/3 观察轮。
- `docs/desktop-ipc-old-binding-exit-plan.md`
  - Exit trigger 增加 three consecutive default-disabled observation rounds。
  - Removal sequence 明确每轮 observation 要写入 tracker，且不能在最终观察轮同轮移除 adapter。
- `docs/desktop-ipc-migration-plan.md`
  - post-phase typed cycles 增加 Round 25。

## Focused test 结果

已执行：

```powershell
cd frontend
pnpm exec vitest run scripts/check-desktop-generic-ipc-retirement-readiness.test.mjs scripts/check-desktop-generic-ipc-rollback-guard.test.mjs src/app/integrations/desktopGenericIpcPolicy.test.ts src/app/integrations/desktopBridge.test.ts
```

结果：

- Passed: 4 files / 44 tests

## Full gate 结果

已执行：

- `go test -tags dev ./...`
- `go test -tags production ./...`
- `cd backend && go test ./...`
- `cd frontend && pnpm run ci`
- `cd frontend && pnpm run build:wails`
- `node frontend/scripts/check-wails-bindings.mjs`
- `node frontend/scripts/check-desktop-transport-policy.mjs`
- `node frontend/scripts/check-desktop-generic-ipc-allowlist.mjs`
- `node frontend/scripts/check-desktop-generic-ipc-retirement-readiness.mjs`
- `node frontend/scripts/check-desktop-generic-ipc-rollback-guard.mjs`
- `node frontend/scripts/check-desktop-old-binding-compat.mjs`
- `node frontend/scripts/check-desktop-misc-compat-inventory.mjs`
- `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1`
- `git diff --check`

结果：

- Passed: root dev Go tests
- Passed: root production Go tests
- Passed: backend Go tests
- Passed: frontend CI, 234 files / 755 tests
- Passed: default-disabled `build:wails`
- Passed: compat rollback `build:wails`
- Passed: final default-disabled `build:wails`

Smoke：

- Default-disabled smoke: `output/desktop-ipc-smoke/desktop-ipc-smoke-summary.json`
- Default-disabled result: `genericIpcPolicy = disabled`，`genericIpcDisableExperimentBuildFlag = true`，`directBackendApiRequestCount = 0`，`browserDev.ok = true`，`capturePackets = 7074`，`httpStreams = 119`，`objectCount = 205`
- Compat rollback smoke: `output/desktop-ipc-smoke-compat-rollback/desktop-ipc-smoke-summary.json`
- Compat rollback result: `genericIpcPolicy = compat`，`genericIpcDisableExperimentBuildFlag = false`，`directBackendApiRequestCount = 0`，`browserDev.ok = true`，`capturePackets = 7074`，`httpStreams = 119`，`objectCount = 205`
- Final assets: 已重新无 env 执行 `cd frontend && pnpm run build:wails`，`frontend/dist` 保持 default-disabled。

## 桌面/浏览器行为差异说明

- Desktop release：继续 default-disabled generic IPC adapter routing。
- Desktop rollback：`VITE_DESKTOP_GENERIC_IPC_POLICY=compat` 仍恢复 adapter-enabled 行为。
- Browser dev：继续 HTTP/SSE，不受桌面 default-disabled 策略影响。

## 评分

总分：99/100

- Contract Correctness：25/25。Observation tracker schema、readiness guardrail 与测试一致，`compat` rollback contract 保持可验证。
- Desktop Policy Compliance：20/20。Desktop release default-disabled 观察通过，typed 域仍无 WebView 直接 `/api` 请求。
- Regression Safety：20/20。Focused tests、root dev/production Go、backend Go、frontend CI、`build:wails`、binding/policy/allowlist/compat guardrails 均通过。
- Diagnostics and Failure Shape：15/15。premature removal、缺失 observation evidence、错误 latest evidence 都会被 guardrail 明确拦截。
- Docs and Traceability：10/10。tracker、migration plan、old-binding exit plan、round report、开发记录同步。
- Dev/Browser Compatibility：9/10。browser-dev HTTP/SSE smoke 通过；扣 1 分是因为当前仍处于观察期，尚未完成 3/3 稳定窗口。

## 自迭代记录

- Round 24 score `99 >= 90` 且无硬阻塞，按 tracker 推荐进入 Round 25。
- 本轮只做一个主域切片：default-disabled observation guard。
- 本轮不删除 adapter code，因为当前仅记录 1/3 观察轮。

## Open blockers

无硬阻塞。

## 下一轮自动建议

下一轮进入：

`default-disabled observation round 2`

继续不删除 adapter code；只累计第二个 default-disabled 观察轮与 compat rollback 证据。自动推进条件仍为 CI、default-disabled Wails smoke、compat rollback smoke、rollback guard、`directBackendApiRequestCount = 0`、browser-dev green 全部通过。
