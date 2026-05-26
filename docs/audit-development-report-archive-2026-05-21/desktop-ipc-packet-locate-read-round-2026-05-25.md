# Desktop IPC Packet Locate/Read Typed Round

- Author: Codex
- Time: 2026-05-25 22:31:00 +08:00

## 迁移域与目标

本轮按 `docs/desktop-ipc-iteration-status.json` 上一轮 `recommendedNextSlice` 自动进入 packet locate/full packet read 域，只做一个主域迁移：

- packet locate 优先走 typed Wails IPC。
- packet detail read 优先走 typed Wails IPC。
- 当 matching typed binding 已存在时，desktop generic IPC 禁止继续代理 `/api/packets/locate` 和 `/api/packet`。
- browser-dev HTTP/SSE 调试链路保持不变。

不纳入本轮：

- 不迁移 `/api/packets` full list。
- 不迁移 hunting、plugin、DBC、MISC multipart routes。
- 不改变 packet raw hex/layers 的既有 typed 路径。

## 修改面清单

- `desktop_backend_proxy.go`
  - 新增 `LocatePacketPage`。
  - 新增 `GetPacket`。
- `desktop_typed_bindings_test.go`
  - 新增 packet locate/read typed binding route contract test，校验 query 编码与 detail route。
- `frontend/src/app/integrations/desktopTypedBridgePacket.ts`
  - 新增 packet typed overrides，复用现有 packet mapper。
- `frontend/src/app/integrations/desktopTypedBridge.ts`
  - 合并 packet typed overrides。
- `frontend/src/app/integrations/desktopTypedBridgeCore.ts`
  - 将 packet locate/read bridge method 加入 `typedBindingRequirements`。
- `frontend/src/app/integrations/desktopTransportBinding.ts`
  - 声明 `LocatePacketPage` 和 `GetPacket` DesktopApp binding。
- `frontend/src/app/integrations/ipcBackendTransport.ts`
  - 将 `/api/packets/locate` 映射到 `LocatePacketPage`。
  - 将 `/api/packet` 映射到 `GetPacket`。
  - typed binding 存在时拒绝 matching generic IPC。
- `frontend/src/app/integrations/desktopBridge.test.ts`
  - 验证 packet locate/read 调用走 typed Wails IPC，不落 generic IPC。
- `frontend/src/app/integrations/ipcBackendTransport.test.ts`
  - 验证 packet locate/read route 的 `typed_binding_required` 阻断。
- `frontend/scripts/check-wails-bindings.mjs`
  - 将 packet locate/read 纳入 typed control-plane binding check。
- `frontend/scripts/check-desktop-transport-policy.mjs`
  - 将 `desktopTypedBridgePacket.ts` 纳入 static policy scan。
- `frontend/scripts/check-desktop-transport-policy.test.mjs`
  - 增加 packet typed bridge fixture。
- `frontend/src/app/desktopWebviewSmoke.ts`
  - WebView typed smoke 增加 sampled packet locate/detail 覆盖。
- `scripts/check-desktop-ipc-smoke.ps1`
  - summary 增加 sampled packet locate/detail 字段与断言。
- `frontend/scripts/check-size.mjs`
  - 小幅上调 typed binding/requirements 文件预算，反映 typed surface 增长。
- `docs/desktop-ipc-migration-plan.md`
- `docs/desktop-ipc-iteration-status.json`

## Focused Test 结果

已通过：

```powershell
go test -tags dev ./...
cd frontend
pnpm exec vitest run src/app/integrations/desktopBridge.test.ts src/app/integrations/bridgeFactory.test.ts src/app/integrations/ipcBackendTransport.test.ts src/app/integrations/clients/captureClient.test.ts scripts/check-desktop-transport-policy.test.mjs
node scripts/check-wails-bindings.mjs
node scripts/check-desktop-transport-policy.mjs
```

Focused result：

- root Go dev passed。
- `desktopBridge.test.ts`：22 tests passed。
- `bridgeFactory.test.ts`：4 tests passed。
- `ipcBackendTransport.test.ts`：14 tests passed。
- `captureClient.test.ts`：4 tests passed。
- `check-desktop-transport-policy.test.mjs`：6 tests passed。
- 合计 focused frontend：50 tests passed。

Root Go contract：

- `desktop_typed_bindings_test.go` 覆盖 `LocatePacketPage(42, 50, "http && tcp")`。
- 预期 backend route：`GET /api/packets/locate?id=42&limit=50&filter=http+%26%26+tcp`。
- `desktop_typed_bindings_test.go` 覆盖 `GetPacket(42)`。
- 预期 backend route：`GET /api/packet?id=42`。

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

- Frontend CI：228 test files passed，715 tests passed。
- `build:wails`：passed，Desktop asset check ok。
- Wails binding check：ok。
- Desktop transport policy check：passed。
- `git diff --check`：passed。
- Desktop IPC smoke：passed on first run for this round。

Desktop IPC smoke evidence：

- `desktopRelease.ok = true`
- `desktopWebviewTyped.ok = true`
- `browserDev.ok = true`
- `capturePackets = 7074`
- `packetPageTotal = 7074`
- `sampledPacketId = 1`
- `locatedPacketFound = true`
- `locatedPacketCursor = 0`
- `packetDetailProtocol = IGMPv3`
- `httpStreams = 119`
- `tcpStreams = 177`
- `udpStreams = 54`
- `sampledHttpStream = 29`
- `sampledHttpStreamChunks = 2`
- `objectCount = 205`
- `objectEvidenceCount = 205`
- `directBackendApiRequestCount = 0`

## 桌面/浏览器行为差异说明

- 桌面 Wails：packet locate 通过 `DesktopApp.LocatePacketPage`。
- 桌面 Wails：packet detail read 通过 `DesktopApp.GetPacket`。
- 桌面 Wails：当 typed packet binding 存在，`createIpcBackendTransport` 对 `/api/packets/locate` 和 `/api/packet` generic IPC 直接抛 `DesktopIpcRequestError(code="typed_binding_required")`。
- Browser dev：继续通过 HTTP/SSE 调试，不受 desktop typed guardrail 影响。
- 业务结果：`http.pcap` sampled packet 为 `id=1`，locate 命中 cursor `0`，detail protocol 为 `IGMPv3`，属于有效业务结果。

## 评分

总分：96 / 100

- Contract Correctness：24 / 25
  - packet locate/read typed binding 与现有 HTTP route 语义一致。
  - Go contract test 覆盖 locate query 编码与 detail route。
  - 扣 1 分：typed binding 仍复用 backend proxy 调现有 `/api/...`，尚未直接调用服务层。
- Desktop Policy Compliance：20 / 20
  - `/api/packets/locate` 与 `/api/packet` 在 typed binding 存在时不再允许 generic IPC 静默兜底。
- Regression Safety：20 / 20
  - focused tests、root Go dev/production、backend tests、frontend CI、build:wails、asset check、binding check、policy check、desktop/browser smoke 均通过。
- Diagnostics and Failure Shape：15 / 15
  - locate miss、packet detail transport failure、typed binding missing/failure 可通过现有 mapper 与 `typed_binding_required` guardrail 区分。
- Docs and Traceability：10 / 10
  - tracker、plan、round report 已同步。
- Dev/Browser Compatibility：7 / 10
  - browser-dev HTTP/SSE smoke 通过。
  - 扣 3 分：仍未做真实 UI 点击式手工 smoke；当前证据来自机器 WebView smoke。

## 自迭代记录

自评后结论：

- 总分 >= 90。
- 无硬阻塞。
- 本轮主域 packet locate/full packet read 可以标记 completed。
- 可进入下一 remaining generic compatibility domain。

下一轮自动优先级：

1. 若后续出现 hard blocker，先修 blocker。
2. 否则继续 post-phase typed IPC cycle。
3. 推荐下一主域：hunting typed IPC。

选择 hunting typed IPC 的理由：

- hunting 属于主线检测工作流。
- 范围比 plugin/DBC management 更窄。
- packet locate/read 完成后，剩余 generic IPC 中 hunting 的用户价值和主线相关度高于管理类路由。
- MISC multipart package routes 仍应作为 explicit generic IPC compatibility，留到单独 upload/import round。

## Open Blockers

无硬阻塞。

Residual risk：

- 本轮 packet typed binding 仍通过 desktop backend proxy 复用现有 HTTP route，不是直接 service-layer binding。
- 真实 UI 点击式手工 smoke 尚未执行；机器 WebView smoke 已覆盖真实 Wails WebView typed path。

## 下一轮自动建议

迁移 hunting typed IPC，建议先做一个窄切片：

- `RunHunt`
- `GetHuntSummary`

测试建议：

- `frontend/src/app/integrations/desktopBridge.test.ts`
- `frontend/src/app/integrations/ipcBackendTransport.test.ts`
- hunting client 对应测试文件，若不存在则先补最小 focused coverage。
- root Go contract test 增补 hunting routes。
- `frontend/scripts/check-wails-bindings.mjs`
- `frontend/scripts/check-desktop-transport-policy.mjs`
- `scripts/check-desktop-ipc-smoke.ps1`
