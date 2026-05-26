# Desktop IPC Round 22 - Production-default generic IPC adapter disablement preflight

- Author: Codex
- Time: 2026-05-26 19:26:56 +08:00
- Phase: post-phase-5
- Primary domain: generic IPC adapter policy preflight

## 迁移域与目标

本轮不删除 generic IPC adapter，不改变默认生产资产。目标是把“禁用 adapter”从单一实验 flag 升级为显式策略：

- 默认策略仍是 `compat`，生产/default build 保持 adapter-enabled。
- 新增 `VITE_DESKTOP_GENERIC_IPC_POLICY=disabled` 作为 Round 22 preflight switch。
- 保留 `VITE_DESKTOP_DISABLE_GENERIC_IPC=1` 作为 Round 20 legacy experiment alias。
- WebView smoke 记录实际 `genericIpcPolicy`，让策略状态成为可归档事实。

## 修改面清单

- `frontend/src/app/integrations/desktopGenericIpcPolicy.ts`
  - 新增 `resolveDesktopGenericIpcPolicy()`、`isDesktopGenericIpcDisabled()`、legacy alias 判断。
  - 默认返回 `compat`。
  - `VITE_DESKTOP_GENERIC_IPC_POLICY=disabled` 返回 `disabled`。
  - 显式 `compat` 可覆盖 legacy disable alias。
- `frontend/src/app/integrations/desktopGenericIpcPolicy.test.ts`
  - 覆盖默认 compat、显式 disabled、legacy alias、显式 compat 覆盖 legacy alias。
- `frontend/src/app/integrations/desktopBridge.ts`
  - `createDesktopBridge` 改为消费 `isDesktopGenericIpcDisabled()`。
  - 保留 `isDesktopGenericIpcDisableExperimentEnabled()` 兼容旧实验语义。
- `frontend/src/app/integrations/desktopBridge.test.ts`
  - 增加显式 disabled policy fail-fast 测试。
  - 增加 explicit compat 覆盖 legacy alias 测试。
- `frontend/src/app/desktopWebviewSmoke.ts`
  - smoke result 增加 `genericIpcPolicy`。
- `scripts/check-desktop-ipc-smoke.ps1`
  - summary 中输出 `desktopWebviewTyped.genericIpcPolicy`。
- `frontend/scripts/check-desktop-generic-ipc-retirement-readiness.mjs`
  - 新增策略模块 token 检查。
  - 拒绝 default-on `VITE_DESKTOP_GENERIC_IPC_POLICY=disabled` 模式。
- `docs/desktop-ipc-old-binding-exit-plan.md`
  - 记录 `VITE_DESKTOP_GENERIC_IPC_POLICY=disabled` 作为 Round 22 preflight switch。

## Focused test 结果

已通过：

```powershell
cd frontend
pnpm exec vitest run src/app/integrations/desktopGenericIpcPolicy.test.ts src/app/integrations/desktopBridge.test.ts scripts/check-desktop-generic-ipc-retirement-readiness.test.mjs scripts/check-desktop-old-binding-compat.test.mjs
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
node frontend/scripts/check-desktop-old-binding-compat.mjs
node frontend/scripts/check-desktop-misc-compat-inventory.mjs
```

Frontend CI 结果：233 files / 747 tests passed。

## 桌面/浏览器行为差异说明

- Desktop default build: `genericIpcPolicy = compat`，adapter 保持 enabled。
- Desktop disabled-policy preflight: `VITE_DESKTOP_GENERIC_IPC_POLICY=disabled` 构建后，generic IPC adapter 禁用，缺 typed data-plane route 以 `generic_ipc_disabled` 快速失败。
- Legacy experiment: `VITE_DESKTOP_DISABLE_GENERIC_IPC=1` 仍可触发 disabled policy，避免 Round 20 smoke/脚本失效。
- Browser dev: HTTP/SSE 调试链路仍 green，不受桌面策略影响。

## Smoke 结果

普通 Wails smoke 已通过：

- `genericIpcPolicy = compat`
- `genericIpcDisableExperiment = false`
- `genericIpcDisableExperimentBuildFlag = false`
- `desktopWebviewTyped.directBackendApiRequestCount = 0`
- `browserDev.ok = true`

显式 disabled-policy Wails smoke 已通过：

- 构建环境：`VITE_DESKTOP_GENERIC_IPC_POLICY=disabled`
- smoke 参数：`-DisableGenericIpcAdapterExperiment`
- `genericIpcPolicy = disabled`
- `genericIpcDisableExperimentRequested = true`
- `genericIpcDisableExperimentBuildFlag = true`
- `desktopWebviewTyped.directBackendApiRequestCount = 0`
- `browserDev.ok = true`
- `capturePackets = 7074`
- `httpStreams = 119`
- `objectCount = 205`

disabled-policy smoke 后已重新执行默认 `cd frontend && pnpm run build:wails`，恢复 adapter-enabled assets。

## 评分

总分：99/100

- Contract Correctness: 25/25
  - 策略解析、旧 alias、显式 compat 覆盖、bridge 消费路径都有测试覆盖。
- Desktop Policy Compliance: 20/20
  - 默认生产策略未被偷偷改成 disabled；显式 disabled policy smoke 通过且无 WebView direct backend API。
- Regression Safety: 20/20
  - Focused tests、full gates、static guardrails、normal smoke、disabled-policy smoke、default asset restore 均通过。
- Diagnostics and Failure Shape: 15/15
  - disabled policy 下仍以 `generic_ipc_disabled` 区分 transport policy failure。
- Docs and Traceability: 10/10
  - tracker、plan、exit-plan、round report、开发记录同步。
- Dev/Browser Compatibility: 9/10
  - browser-dev green；扣 1 分是因为本轮仍未把 disabled 设为生产默认，也未移除 adapter。

硬阻塞：无。

## 自迭代记录

本轮评分 `99 >= 90`，可进入下一轮。自动决策：继续 post-phase-5 governance，不删除 adapter；下一轮应补“default-disabled release-candidate rollback guard”，即在考虑生产默认 disabled 前，先定义可恢复到 `compat` 的开关与验收证据。

## 下一轮自动建议

下一轮主切片：Default-disabled release-candidate rollback guard。

边界：

- 不删除 `InvokeBackendJSON/Blob/Text`。
- 不移除 `createIpcBackendTransport`。
- 不移除 browser-dev HTTP/SSE。
- 不改变 shell/auth/dialog old-binding 例外。

验收：

- CI 继续 green。
- normal smoke 继续 `genericIpcPolicy = compat`。
- disabled-policy smoke 继续 `genericIpcPolicy = disabled`。
- `desktopWebviewTyped.directBackendApiRequestCount = 0`。
- browser-dev HTTP/SSE green。
- 文档明确默认 disabled 的回滚/override 策略。
