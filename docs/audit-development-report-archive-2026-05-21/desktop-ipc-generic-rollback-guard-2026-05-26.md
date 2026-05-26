# Desktop IPC Round 23 - Default-disabled release-candidate rollback guard

- Author: Codex
- Time: 2026-05-26 19:39:00 +08:00
- Phase: post-phase-5
- Primary domain: generic IPC adapter rollback guard

## 迁移域与目标

本轮不删除 generic IPC adapter，也不改变默认生产策略。目标是在后续考虑 default-disabled release candidate 前，把回滚路径机器化：

- `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` 必须作为 adapter-enabled rollback/override 路径保留。
- 显式 `compat` 必须能覆盖 legacy `VITE_DESKTOP_DISABLE_GENERIC_IPC=1`。
- CI 必须防止 exit plan 或测试删除这个回滚路径。

## 修改面清单

- `frontend/scripts/check-desktop-generic-ipc-rollback-guard.mjs`
  - 新增 rollback guard。
  - 校验策略模块、策略测试、desktopBridge 测试、exit plan、package CI 脚本。
- `frontend/scripts/check-desktop-generic-ipc-rollback-guard.test.mjs`
  - 覆盖有效 contract、缺少 explicit compat 测试、exit plan 缺少 compat 回滚开关、CI 未挂载等场景。
- `frontend/package.json`
  - 新增 `desktop-generic-ipc-rollback:check`。
  - `pnpm run ci` 新增 rollback guard。
- `docs/desktop-ipc-old-binding-exit-plan.md`
  - Exit trigger 增加 release-candidate rollback path。
  - Removal sequence 明确 `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` 是回滚/override switch。
- `docs/desktop-ipc-iteration-status.json`
  - `currentRound` 更新为 23。
  - 记录 rollback guard 和本轮证据。
- `docs/desktop-ipc-migration-plan.md`
  - Post-phase typed cycles 追加 Round 23。
  - Next default slice 改为 default-disabled release-candidate decision。
- `docs/开发记录.md`
  - 追加本轮记录。

## Focused test 结果

第一次 frontend CI 在 `format:check` 失败，原因是新增 rollback guard 测试文件未按 Prettier 格式。已执行 Prettier 修复并重新验证。

最终 focused tests 已通过：

```powershell
cd frontend
pnpm exec vitest run scripts/check-desktop-generic-ipc-rollback-guard.test.mjs scripts/check-desktop-generic-ipc-retirement-readiness.test.mjs src/app/integrations/desktopGenericIpcPolicy.test.ts src/app/integrations/desktopBridge.test.ts
```

结果：4 files / 40 tests passed。

## Full gate 结果

已通过：

```powershell
go test -tags dev ./...
go test -tags production ./...
cd backend && go test ./...
cd frontend && pnpm run ci
cd frontend && pnpm run build:wails
node frontend/scripts/check-wails-bindings.mjs
node frontend/scripts/check-desktop-transport-policy.mjs
node frontend/scripts/check-desktop-generic-ipc-allowlist.mjs
node frontend/scripts/check-desktop-generic-ipc-retirement-readiness.mjs
node frontend/scripts/check-desktop-generic-ipc-rollback-guard.mjs
node frontend/scripts/check-desktop-old-binding-compat.mjs
node frontend/scripts/check-desktop-misc-compat-inventory.mjs
```

Frontend CI 结果：234 files / 751 tests passed。

## 桌面/浏览器行为差异说明

- Desktop default build: `genericIpcPolicy = compat`，adapter 保持 enabled。
- Desktop disabled-policy path: 未在本轮重跑；沿用 Round 22 证据，且本轮仅增加 rollback guard。
- Browser dev: HTTP/SSE 继续 green。
- Adapter code: 未删除 `InvokeBackendJSON/Blob/Text` 和 `createIpcBackendTransport`。

## Smoke 结果

普通 Wails smoke 已通过：

- `genericIpcPolicy = compat`
- `genericIpcDisableExperiment = false`
- `genericIpcDisableExperimentBuildFlag = false`
- `desktopWebviewTyped.directBackendApiRequestCount = 0`
- `browserDev.ok = true`
- `capturePackets = 7074`
- `httpStreams = 119`
- `objectCount = 205`

## 评分

总分：98/100

- Contract Correctness: 25/25
  - rollback guard 约束了策略模块、测试、exit plan 和 CI contract。
- Desktop Policy Compliance: 20/20
  - 默认仍为 `compat`，没有误改生产默认；回滚路径进入 exit criteria。
- Regression Safety: 20/20
  - 修复 format 后 focused tests、full gates、static checks、build:wails、normal smoke 均通过。
- Diagnostics and Failure Shape: 14/15
  - 本轮没有新增 failure shape，只守住回滚策略；扣 1 分。
- Docs and Traceability: 10/10
  - tracker、plan、exit plan、round report、开发记录同步。
- Dev/Browser Compatibility: 9/10
  - browser-dev green；本轮未重跑 disabled-policy smoke，沿用 Round 22 证据，扣 1 分。

硬阻塞：无。已处理 transient format blocker。

## 自迭代记录

本轮评分 `98 >= 90`，可推进下一轮。自动决策：进入 default-disabled release-candidate decision，但仍不得删除 adapter code。下一轮如果要改默认策略，必须保留 `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` 作为回滚路径，并重跑 normal smoke + disabled-policy smoke。

## 下一轮自动建议

下一轮主切片：Default-disabled release-candidate decision。

边界：

- 不删除 adapter code。
- 保留 `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` rollback。
- 保留 browser-dev HTTP/SSE。
- 保留 shell/auth/dialog old-binding 例外。

验收：

- frontend CI 含 rollback guard green。
- normal smoke green。
- disabled-policy smoke green。
- `desktopWebviewTyped.directBackendApiRequestCount = 0`。
- browser-dev green。
- tracker 记录 default-disabled decision 的事实与回滚路径。
