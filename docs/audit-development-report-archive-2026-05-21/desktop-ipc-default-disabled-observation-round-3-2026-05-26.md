# Desktop IPC Round 27 - default-disabled observation round 3

Author: Codex  
Time: 2026-05-26 21:09:38 +08:00

## 迁移域与目标

本轮主域：generic IPC adapter default-disabled observation round 3。

目标：

- 不删除 generic IPC adapter code。
- 不新增业务 typed binding。
- 累计第三个 default-disabled green observation round。
- 通过第三轮后，只允许进入单独的 adapter-removal preflight round，不在观察轮同轮删除 adapter。

## 修改面清单

- `docs/desktop-ipc-iteration-status.json`
  - `currentRound = 28`。
  - `genericIpcAdapterDefaultDisabledReleaseCandidate.status = observation-round-3-completed`。
  - `currentConsecutiveGreenRounds = 3`。
  - `removalAllowed = true` 仅表示可进入单独 preflight，不表示本轮已删除 adapter。
  - 新增 Round 27 observation evidence。
- `docs/desktop-ipc-migration-plan.md`
  - post-phase typed cycles 增加 Round 27。
  - 下一轮建议更新为 generic IPC adapter removal preflight。
- `docs/audit-development-report-archive-2026-05-21/desktop-ipc-default-disabled-observation-round-3-2026-05-26.md`
  - 记录本轮完整验证、自评和下一轮自动建议。
- `docs/开发记录.md`
  - 追加 Round 27 开发记录。

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
- Default-disabled result: `updatedAt = 2026-05-26T20:41:49+08:00`，`genericIpcPolicy = disabled`，`genericIpcDisableExperimentBuildFlag = true`，`directBackendApiRequestCount = 0`，`browserDev.ok = true`，`capturePackets = 7074`，`httpStreams = 119`，`objectCount = 205`
- Compat rollback smoke: `output/desktop-ipc-smoke-compat-rollback/desktop-ipc-smoke-summary.json`
- Compat rollback result: `updatedAt = 2026-05-26T21:07:11+08:00`，`genericIpcPolicy = compat`，`genericIpcDisableExperimentBuildFlag = false`，`directBackendApiRequestCount = 0`，`browserDev.ok = true`，`capturePackets = 7074`，`httpStreams = 119`，`objectCount = 205`
- Final assets: 已重新无 env 执行 `cd frontend && pnpm run build:wails`，`frontend/dist` 保持 default-disabled。

## 桌面/浏览器行为差异说明

- Desktop release：继续 default-disabled generic IPC adapter routing。
- Desktop rollback：`VITE_DESKTOP_GENERIC_IPC_POLICY=compat` 仍恢复 adapter-enabled 行为。
- Browser dev：继续 HTTP/SSE，不受桌面 default-disabled 策略影响。

## 评分

总分：99/100

- Contract Correctness：25/25。三个 counted observation rounds 均有 default-disabled、compat rollback、browser-dev、direct request 和 adapterRemoved 证据。
- Desktop Policy Compliance：20/20。第三轮 default-disabled smoke 保持 `directBackendApiRequestCount = 0`。
- Regression Safety：20/20。Focused tests、root dev/production Go、backend Go、frontend CI、`build:wails` 均通过。
- Diagnostics and Failure Shape：15/15。release candidate 与 rollback policy 均由 smoke 和 guardrail 区分。
- Docs and Traceability：10/10。tracker、migration plan、round report、开发记录同步。
- Dev/Browser Compatibility：9/10。browser-dev HTTP/SSE smoke 通过；扣 1 分是因为 adapter removal 仍需单独 preflight 验证。

## 自迭代记录

- Round 26 score `99 >= 90` 且无硬阻塞，按 tracker 推荐进入 Round 27。
- 本轮只做一个主域切片：default-disabled observation round 3。
- 本轮不删除 adapter code；三轮观察完成后，下一轮只能进入 adapter-removal preflight。
- `removalAllowed = true` 是调度信号，不是删除完成信号。

## Open blockers

无硬阻塞。

## 下一轮自动建议

下一轮进入：

`generic IPC adapter removal preflight`

要求：

- 先 inventory 所有 `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText` 与 `createIpcBackendTransport` 引用。
- 证明 browser-dev HTTP/SSE 与桌面 adapter removal 解耦。
- 保留并验证 `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` 回滚要求，除非 preflight 明确给出替代回滚路径。
- 形成可逆删除计划；如果发现 blocker，则停留在 governance，不删除 adapter。
