# Desktop IPC Round 28 - generic IPC adapter removal preflight

Author: Codex  
Time: 2026-05-26 21:18:43 +08:00

## 迁移域与目标

本轮主域：generic IPC adapter removal preflight。

目标：

- 不删除 generic IPC adapter code。
- 将删除前置条件机器化，避免 3/3 观察完成后直接进入无边界删除。
- 固定当前 adapter 引用清单。
- 明确 browser-dev HTTP/SSE、`VITE_DESKTOP_GENERIC_IPC_POLICY=compat`、可逆删除计划仍是候选删除轮的前提。

## 修改面清单

- `frontend/scripts/check-desktop-generic-ipc-removal-preflight.mjs`
  - 新增 removal preflight guardrail。
  - 要求 tracker 已记录 3/3 default-disabled observation。
  - 要求 preflight 阶段 `adapterRemoved = false`。
  - 固定 `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText` / `createIpcBackendTransport` 生产源码与 generated binding 引用清单。
  - 要求 migration plan、old-binding exit plan、package CI 均包含 preflight 约束。
- `frontend/scripts/check-desktop-generic-ipc-removal-preflight.test.mjs`
  - 覆盖 3/3 观察、preflight 不允许删除、引用扩散、rollback/可逆计划、CI 接入。
- `frontend/package.json`
  - 新增 `desktop-generic-ipc-removal-preflight:check`。
  - `pnpm run ci` 接入该 guardrail。
- `docs/desktop-ipc-iteration-status.json`
  - 新增 `genericIpcAdapterRemovalPreflight`。
  - `currentRound = 29`。
  - `lastRound` 更新为 Round 28 preflight。
- `docs/desktop-ipc-migration-plan.md`
  - post-phase typed cycles 增加 Round 28。
  - 下一轮建议改为 generic IPC adapter removal candidate。
- `docs/desktop-ipc-old-binding-exit-plan.md`
  - 增加 adapter removal preflight 与 reversible deletion plan。
- `docs/开发记录.md`
  - 追加 Round 28 开发记录。

## Focused test 结果

已执行：

```powershell
cd frontend
pnpm exec vitest run scripts/check-desktop-generic-ipc-removal-preflight.test.mjs scripts/check-desktop-generic-ipc-retirement-readiness.test.mjs scripts/check-desktop-generic-ipc-rollback-guard.test.mjs src/app/integrations/desktopGenericIpcPolicy.test.ts src/app/integrations/desktopBridge.test.ts
```

结果：

- Passed: 5 files / 51 tests

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
- Passed: frontend CI, 235 files / 762 tests
- Passed: default-disabled `build:wails`

本轮没有重新运行 Wails smoke，因为 preflight 不改运行时 adapter 行为；沿用 Round 27 的双 smoke 事实作为进入 preflight 的前置证据。候选删除轮必须重新运行 default-disabled Wails smoke。

## 桌面/浏览器行为差异说明

- Desktop release：继续 default-disabled generic IPC adapter routing。
- Desktop rollback：`VITE_DESKTOP_GENERIC_IPC_POLICY=compat` 仍是候选删除轮必须处理的 rollback 契约。
- Browser dev：继续 HTTP/SSE，不允许被桌面 adapter removal 影响。

## 评分

总分：98/100

- Contract Correctness：25/25。Preflight guardrail 固定 adapter 引用面和删除前置条件。
- Desktop Policy Compliance：20/20。3/3 default-disabled observation 已被机器校验。
- Regression Safety：20/20。Focused tests、root dev/production Go、backend Go、frontend CI、`build:wails` 均通过。
- Diagnostics and Failure Shape：15/15。preflight 缺少观察、rollback、引用清单、可逆计划或 CI 接入会明确失败。
- Docs and Traceability：10/10。tracker、migration plan、exit plan、round report、开发记录同步。
- Dev/Browser Compatibility：8/10。browser-dev 契约被 guardrail 和文档约束；扣 2 分是因为本轮未重跑 smoke，候选删除轮必须补真实行为证据。

## 自迭代记录

- Round 27 score `99 >= 90` 且无硬阻塞，按 tracker 推荐进入 Round 28。
- 本轮只做一个主域切片：adapter removal preflight。
- 本轮不删除 adapter code。
- 下一轮只有在重新读取 preflight 后，才允许尝试一个 bounded candidate removal slice。

## Open blockers

无硬阻塞。

## 下一轮自动建议

下一轮进入：

`generic IPC adapter removal candidate`

要求：

- 只做一个 bounded removal slice。
- 先决定 `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` 是保留 source-level rollback，还是降级为 documented no-op。
- 保持 browser-dev HTTP/SSE 不变。
- 跑 focused tests、frontend CI、`build:wails`、default-disabled Wails smoke、final guardrails。
- 任一 gate 失败时恢复 adapter，停留 governance。
