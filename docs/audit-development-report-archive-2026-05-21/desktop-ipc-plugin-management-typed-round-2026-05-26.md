# Desktop IPC plugin management typed round

- Author: Codex
- Time: 2026-05-26 00:12:00 +08:00
- Round: 9
- Phase: post-phase-5
- Primary domain: plugin management typed IPC

## 迁移域与目标

本轮只迁移 plugin management，不并行迁移 MISC multipart import/invoke/delete/list。

目标：

- 新增 `ListPlugins` typed DesktopApp binding，覆盖 `GET /api/plugins`。
- 新增 `GetPluginSource` typed DesktopApp binding，覆盖 `GET /api/plugins/source?id=...`。
- 新增 `SavePluginSource` typed DesktopApp binding，覆盖 `POST /api/plugins/source`。
- 新增 `AddPlugin` typed DesktopApp binding，覆盖 `POST /api/plugins/add`。
- 新增 `DeletePlugin` typed DesktopApp binding，覆盖 `POST /api/plugins/delete?id=...`。
- 新增 `TogglePlugin` typed DesktopApp binding，覆盖 `POST /api/plugins/toggle?id=...`。
- 新增 `SetPluginsEnabled` typed DesktopApp binding，覆盖 `POST /api/plugins/bulk`。
- 桌面模式优先 typed IPC；typed binding 存在时，匹配的 generic IPC path 不得继续兜底。
- 浏览器 dev 保留 HTTP/SSE 调试链路。

## 修改面清单

- `desktop_backend_proxy.go`
  - 新增 plugin item/source/bulk typed request DTO。
  - 新增 `ListPlugins`、`GetPluginSource`、`SavePluginSource`、`AddPlugin`、`DeletePlugin`、`TogglePlugin`、`SetPluginsEnabled`。
- `desktop_typed_bindings_test.go`
  - 新增 plugin management typed binding route contract test，覆盖 list/source/save/add/delete/toggle/bulk。
- `frontend/src/app/integrations/desktopTypedBridgePlugin.ts`
  - 新增 plugin typed overrides。
  - 复用 `asPluginItem`、`asPluginItems`、`asPluginSource` 和现有 request mapper，保持 DTO 归一化一致。
- `frontend/src/app/integrations/clients/pluginClient.ts`
  - 导出 `toPluginItemRequest`，避免 typed path 重新实现 add plugin request shape。
- `frontend/src/app/integrations/desktopTypedBridge.ts`
  - 组合 plugin typed override。
- `frontend/src/app/integrations/desktopTypedBridgeCore.ts`
  - 加入 plugin route 到 typed method 映射。
- `frontend/src/app/integrations/desktopTransportBinding.ts`
  - 声明 plugin management typed binding。
- `frontend/src/app/integrations/ipcBackendTransport.ts`
  - `/api/plugins*` generic IPC 路径映射到对应 typed binding。
- `frontend/src/app/integrations/desktopBridge.test.ts`
  - 覆盖 plugin management typed calls，验证不落 generic IPC 或 browser HTTP fallback。
- `frontend/src/app/integrations/ipcBackendTransport.test.ts`
  - 覆盖 migrated plugin routes 的 `typed_binding_required` 阻断。
- `frontend/scripts/check-wails-bindings.mjs`
  - 新增 `typed-plugin` binding group。
- `frontend/scripts/check-desktop-transport-policy.mjs`
  - 将 plugin typed override 与 route policy 纳入静态检查。
- `frontend/scripts/check-desktop-transport-policy.test.mjs`
  - 增加 plugin typed override fixture。
- `frontend/wailsjs/go/main/DesktopApp.{js,d.ts}`
  - 增加 plugin management generated binding 声明与调用包装。
- `frontend/src/app/desktopWebviewSmoke.ts`
  - WebView typed smoke 覆盖 `ListPlugins`。
- `scripts/check-desktop-ipc-smoke.ps1`
  - summary 记录 `pluginCount`。
- `docs/desktop-ipc-migration-plan.md`
- `docs/desktop-ipc-iteration-status.json`

## Focused Test 结果

已通过：

```powershell
go test -tags dev ./...
cd frontend
pnpm exec vitest run src/app/integrations/desktopBridge.test.ts src/app/integrations/bridgeFactory.test.ts src/app/integrations/ipcBackendTransport.test.ts src/app/integrations/clients/pluginClient.test.ts scripts/check-desktop-transport-policy.test.mjs
node scripts/check-wails-bindings.mjs
node scripts/check-desktop-transport-policy.mjs
```

Focused frontend result：

- 5 test files passed。
- 52 tests passed。

Root Go contract：

- `go test -tags dev ./...` passed。
- `TestDesktopPluginTypedBindingsProxyExpectedBackendRoutes` 覆盖 plugin management list/source/save/add/delete/toggle/bulk route contract。

## Full Gate 结果

已通过：

```powershell
go test -tags dev ./...
go test -tags production ./...
cd backend && go test ./...
cd frontend && pnpm run typecheck
cd frontend && pnpm run lint
cd frontend && pnpm run format:check
cd frontend && pnpm run size:check
cd frontend && pnpm run ci
cd frontend && pnpm run build:wails
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1
node frontend/scripts/check-wails-bindings.mjs
node frontend/scripts/check-desktop-transport-policy.mjs
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1
git diff --check
```

Full gate evidence：

- Frontend CI：228 test files passed，718 tests passed。
- `build:wails`：passed，Desktop asset check ok。
- Wails binding check：ok。
- Desktop transport policy check：passed。
- `git diff --check`：passed。
- Desktop IPC smoke：passed。

Desktop IPC smoke evidence：

- `desktopRelease.ok = true`
- `desktopWebviewTyped.ok = true`
- `browserDev.ok = true`
- `capturePackets = 7074`
- `packetPageTotal = 7074`
- `pluginCount = 0`
- `vehicleDBCProfileCount = 0`
- `threatHitCount = 721`
- `huntingPrefixCount = 2`
- `objectCount = 205`
- `objectEvidenceCount = 205`
- `directBackendApiRequestCount = 0`

## 桌面/浏览器行为差异说明

- Desktop release / desktop dev: plugin management typed binding 存在时，`/api/plugins*` 不允许 generic IPC silent fallback；typed IPC 错误应作为 desktop IPC/typed endpoint failure 暴露。
- Browser dev: 无 Wails binding 时继续使用 HTTP/SSE；本轮 smoke 验证 `browserDev.ok = true`，SSE 首行是 `event: ready`。
- 业务空结果：当前本机插件目录返回 `pluginCount = 0`，这是 valid business-empty result，不是 IPC transport failure。
- 本轮 WebView smoke 只读取 plugin list，不执行 save/add/delete/toggle/bulk，避免修改用户本机可信插件状态。

## 评分

总分：95 / 100

- Contract Correctness：25 / 25
  - plugin management list/source/save/add/delete/toggle/bulk typed binding、route mapping、DTO mapper 和 Go route contract 已覆盖。
- Desktop Policy Compliance：20 / 20
  - typed binding 存在时 `/api/plugins*` generic IPC path 被 runtime guard 拒绝。
  - WebView smoke 记录 `directBackendApiRequestCount = 0`。
- Regression Safety：20 / 20
  - focused tests、root dev/production、backend full、frontend CI、build:wails、binding/policy checks、desktop smoke 全部通过。
- Diagnostics and Failure Shape：13 / 15
  - plugin list 业务空结果与 IPC failure 可区分。
  - 扣 2 分：save/add/delete/toggle/bulk 的真实桌面 smoke 未执行，避免修改本地插件状态；错误形态主要由 contract test 覆盖。
- Docs and Traceability：10 / 10
  - tracker、migration plan、round report 已同步。
- Dev/Browser Compatibility：7 / 10
  - browser-dev HTTP/SSE smoke 通过。
  - 扣 3 分：未做人工打开 UI 逐页点击，只做脚本化 smoke。

## Open Blockers

无硬阻塞。

Residual risk：

- WebView smoke 只验证 plugin list，不实际 mutate 插件；source/save/add/delete/toggle/bulk route correctness 由 Go contract test 与 frontend integration test 覆盖。

## 自迭代记录

自动决策：advance-to-next-remaining-domain。

原因：

- 本轮总分 95，超过 `>= 90` 阈值。
- 无硬阻塞。
- `docs/desktop-ipc-iteration-status.json` 已更新。
- 真实 Wails WebView typed smoke 通过，并证明 WebView 未直接请求 backend `/api/...`。

## 下一轮自动建议

推荐下一轮：MISC multipart compatibility audit and guardrail。

理由：

- plugin management 已完成，remaining generic IPC category 只剩 MISC multipart package import/invoke/delete/list 与 old generated binding compatibility。
- MISC multipart 当前涉及上传/导入语义，不应在没有 native upload binding 设计时强行迁移成普通 JSON typed IPC。
- 下一轮应先证明 generic IPC 只允许 MISC multipart compatibility 和旧兼容路径，防止非 MISC 业务 route 再次扩散到 generic IPC。
