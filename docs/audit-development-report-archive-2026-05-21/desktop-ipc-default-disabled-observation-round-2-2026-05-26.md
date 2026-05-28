# Desktop IPC Round 26 - default-disabled observation round 2

Author: Codex  
Time: 2026-05-26 20:30:52 +08:00

## 迁移域与目标

本轮主域：generic IPC adapter default-disabled observation round 2。

目标：

- 不删除 generic IPC adapter code。
- 不新增业务 typed binding。
- 累计第二个 default-disabled green observation round。
- 补强 readiness guardrail，确保每个 counted observation round 都有有效证据，而不是只检查最新一轮。

## 修改面清单

- `frontend/scripts/check-desktop-generic-ipc-retirement-readiness.mjs`
  - 将 observation evidence 校验从 latest round 扩展为逐个 counted round 校验。
  - 每个 counted round 均要求 `genericIpcPolicy = disabled`、`compatRollbackPolicy = compat`、`directBackendApiRequestCount = 0`、`browserDevOk = true`、`adapterRemoved = false`。
- `frontend/scripts/check-desktop-generic-ipc-retirement-readiness.test.mjs`
  - 增加每个 counted round 都必须满足 direct backend request 为 0 的回归测试。
  - 更新 observation fixture，显式记录 `adapterRemoved = false`。
- `docs/desktop-ipc-iteration-status.json`
  - `currentRound = 27`。
  - `genericIpcAdapterDefaultDisabledReleaseCandidate.status = observation-round-2-completed`。
  - `currentConsecutiveGreenRounds = 2`。
  - 新增 Round 26 observation evidence。
- `docs/desktop-ipc-migration-plan.md`
  - post-phase typed cycles 增加 Round 26。
  - 下一轮建议更新为 default-disabled observation round 3。

## Focused test 结果

已执行：

```powershell
cd frontend
pnpm exec vitest run scripts/check-desktop-generic-ipc-retirement-readiness.test.mjs scripts/check-desktop-generic-ipc-rollback-guard.test.mjs src/app/integrations/desktopGenericIpcPolicy.test.ts src/app/integrations/desktopBridge.test.ts
```

结果：

- Passed: 4 files / 45 tests

## Full gate 结果

已执行：

- `go test -tags dev ./...`
- `go test -tags production ./...`
- `cd backend && go test ./...`
- `cd frontend && pnpm run ci`
- `cd frontend && pnpm run build:wails`

结果：

- Passed: root dev Go tests
- Passed: root production Go tests
- Passed: backend Go tests
- Passed: frontend CI, 234 files / 756 tests
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

- Contract Correctness：25/25。Observation evidence 由 latest-only 升级为 counted-rounds 全量校验。
- Desktop Policy Compliance：20/20。第二轮 default-disabled smoke 保持 `directBackendApiRequestCount = 0`。
- Regression Safety：20/20。Focused tests、root dev/production Go、backend Go、frontend CI、`build:wails` 均通过。
- Diagnostics and Failure Shape：15/15。任一 counted round 缺少 rollback、browser-dev、direct request 或 adapterRemoved=false 证据都会被明确报错。
- Docs and Traceability：10/10。tracker、migration plan、round report、开发记录同步。
- Dev/Browser Compatibility：9/10。browser-dev HTTP/SSE smoke 通过；扣 1 分是因为观察窗口仍未达到 3/3。

## 自迭代记录

- Round 25 score `99 >= 90` 且无硬阻塞，按 tracker 推荐进入 Round 26。
- 本轮只做一个主域切片：default-disabled observation round 2。
- 附带一个跨域收口任务：readiness guardrail 从 latest-only 改为每个 counted round 校验。
- 本轮不删除 adapter code，因为当前仅记录 2/3 观察轮。

## Open blockers

无硬阻塞。

## 下一轮自动建议

下一轮进入：

`default-disabled observation round 3`

继续不删除 adapter code；只累计第三个 default-disabled 观察轮与 compat rollback 证据。如果第三轮也通过，下一步只能安排单独的 adapter-removal preflight round，不能在 observation round 3 同轮删除 adapter。
