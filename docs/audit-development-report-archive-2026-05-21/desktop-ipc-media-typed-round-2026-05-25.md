# Desktop IPC Media Typed Round

- Author: Codex
- Time: 2026-05-25 22:03:41 +08:00

## 迁移域与目标

本轮按 `docs/desktop-ipc-iteration-status.json` 上一轮 `recommendedNextSlice` 自动进入 media 域，只做一个主域迁移：

- media analysis 优先走 typed Wails IPC。
- media 单条转写、批量转写 start/status/cancel/export 优先走 typed Wails IPC。
- media artifact download 与 playback blob 优先走 typed Wails IPC。
- 当 matching typed binding 已存在时，desktop generic IPC 禁止继续代理 `/api/analysis/media*`。
- browser-dev HTTP/SSE 调试链路保持不变。

不纳入本轮：

- 不做 media blob 流式化。
- 不改变 50MB desktop blob 上限。
- 不迁移 MISC multipart、plugin、DBC、packet locate/full packet read。

## 修改面清单

- `desktop_backend_proxy.go`
  - 新增 `GetMediaAnalysis`。
  - 新增 `TranscribeMediaArtifact`。
  - 新增 `StartMediaBatchTranscription`。
  - 新增 `GetMediaBatchTranscriptionStatus`。
  - 新增 `CancelMediaBatchTranscription`。
  - 新增 `ExportMediaBatchTranscription`。
  - 新增 `DownloadMediaArtifact`。
  - 新增 `GetMediaPlaybackBlob`。
- `desktop_typed_bindings_test.go`
  - 增补 media typed binding route contract test，校验 query、POST body、blob base64 封装。
- `frontend/src/app/integrations/desktopTypedBridgeMedia.ts`
  - 新增 media typed overrides，复用现有 mapper 与 `typedBlobCall`。
- `frontend/src/app/integrations/desktopTypedBridge.ts`
  - 合并 media typed overrides。
- `frontend/src/app/integrations/desktopTypedBridgeCore.ts`
  - 将 media bridge method 加入 `typedBindingRequirements`。
- `frontend/src/app/integrations/desktopTransportBinding.ts`
  - 声明 media DesktopApp binding。
- `frontend/src/app/integrations/ipcBackendTransport.ts`
  - 将 `/api/analysis/media*` route 映射到 media typed binding，binding 存在时拒绝 generic IPC。
- `frontend/src/app/integrations/desktopBridge.test.ts`
  - 验证 media JSON 和 blob 调用走 typed Wails IPC，不落 generic IPC。
- `frontend/src/app/integrations/ipcBackendTransport.test.ts`
  - 验证 media JSON/blob route 的 `typed_binding_required` 阻断。
- `frontend/scripts/check-wails-bindings.mjs`
  - 新增 `typed-media` binding group。
- `frontend/scripts/check-desktop-transport-policy.mjs`
  - 将 `desktopTypedBridgeMedia.ts` 纳入 static policy scan。
- `frontend/src/app/desktopWebviewSmoke.ts`
  - WebView typed smoke 增加 `GetMediaAnalysis(false)` 覆盖，记录 media 空结果。
- `scripts/check-desktop-ipc-smoke.ps1`
  - summary 增加 `mediaTotalPackets` 和 `mediaSessionCount` 字段。
- `docs/desktop-ipc-migration-plan.md`
- `docs/desktop-ipc-iteration-status.json`

## Focused Test 结果

已通过：

```powershell
cd frontend
pnpm exec vitest run src/app/integrations/desktopBridge.test.ts src/app/integrations/bridgeFactory.test.ts src/app/integrations/ipcBackendTransport.test.ts src/app/integrations/clients/mediaClient.test.ts scripts/check-desktop-transport-policy.test.mjs
node scripts/check-wails-bindings.mjs
node scripts/check-desktop-transport-policy.mjs
```

Focused result：

- `desktopBridge.test.ts`：22 tests passed。
- `bridgeFactory.test.ts`：4 tests passed。
- `ipcBackendTransport.test.ts`：13 tests passed。
- `mediaClient.test.ts`：3 tests passed。
- `check-desktop-transport-policy.test.mjs`：6 tests passed。
- 合计 focused frontend：48 tests passed。

Root Go contract：

```powershell
go test -tags dev ./...
go test -tags production ./...
```

结果：

- `github.com/gshark/sentinel/desktop` passed。
- media typed binding route contract 覆盖通过。

说明：

- 首次 `go test -tags dev ./...` 在本轮中因 `frontend/dist/sentinel-backend.exe` 缺失失败。原因是上一轮 `pnpm run ci` 结束于普通 `vite build`，不是 media 代码失败。
- 执行 `cd frontend && pnpm run build:wails` 后，root Go dev/production tests 均通过。

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

- Frontend CI：228 test files passed，714 tests passed。
- `build:wails`：passed，Desktop asset check ok。
- Wails binding check：ok。
- Desktop transport policy check：passed。
- `git diff --check`：passed。
- Desktop IPC smoke：passed on rerun。

Desktop IPC smoke evidence：

- `desktopRelease.ok = true`
- `desktopWebviewTyped.ok = true`
- `browserDev.ok = true`
- `capturePackets = 7074`
- `packetPageTotal = 7074`
- `httpStreams = 119`
- `tcpStreams = 177`
- `udpStreams = 54`
- `sampledHttpStream = 29`
- `sampledHttpStreamChunks = 2`
- `objectCount = 205`
- `objectEvidenceCount = 205`
- `directBackendApiRequestCount = 0`
- `mediaTotalPackets = 0`
- `mediaSessionCount = 0`

Smoke caveat：

- 第一次 `scripts/check-desktop-ipc-smoke.ps1` 在 WebView typed phase 出现 “did not write result file before timeout”。
- 复跑通过并生成 `output/desktop-ipc-smoke/wails-webview-typed-smoke-result.json`。
- 日志显示第一次已经完成 capture、stream typed 路径后退出，未写 result；未复现为稳定 blocker。
- 本轮不把该偶发问题列为 open blocker，但下一轮若再次出现，应先增强 smoke harness 的阶段性 result 写出。

## 桌面/浏览器行为差异说明

- 桌面 Wails：media 调用通过 `DesktopApp.GetMediaAnalysis` 等 typed binding。
- 桌面 Wails：当 typed media binding 存在，`createIpcBackendTransport` 对 `/api/analysis/media*` generic IPC 直接抛 `DesktopIpcRequestError(code="typed_binding_required")`。
- 桌面 Wails：media blob 仍受 50MB desktop IPC blob 上限保护。
- Browser dev：继续通过 HTTP/SSE 调试，不受 desktop typed guardrail 影响。
- 业务空结果：`http.pcap` 没有媒体会话，`GetMediaAnalysis(false)` 返回 `mediaTotalPackets = 0`、`mediaSessionCount = 0`，这是 valid business-empty result，不是 IPC transport failure。

## 评分

总分：95 / 100

- Contract Correctness：24 / 25
  - media JSON/blob typed binding 与现有 HTTP route 语义一致。
  - Go contract test 覆盖 query、body、blob base64。
  - 扣 1 分：typed binding 仍复用 backend proxy 调现有 `/api/...`，尚未直接调用服务层。
- Desktop Policy Compliance：20 / 20
  - `/api/analysis/media*` 在 typed binding 存在时不再允许 generic IPC 静默兜底。
- Regression Safety：20 / 20
  - focused tests、root Go dev/production、backend tests、frontend CI、build:wails、asset check、binding check、policy check、desktop/browser smoke 均通过。
- Diagnostics and Failure Shape：14 / 15
  - 业务空结果与 IPC failure 已区分，media 空样本不误判为 transport failure。
  - 扣 1 分：首次 WebView smoke timeout 未写阶段性 result，诊断仍依赖 stdout/stderr 日志。
- Docs and Traceability：10 / 10
  - tracker、plan、round report 已同步。
- Dev/Browser Compatibility：7 / 10
  - browser-dev HTTP/SSE smoke 通过。
  - 扣 3 分：media typed round 仍未做真实 UI 交互式手工点击，只做机器 smoke；样本无 media session，未覆盖真实 artifact 下载/播放成功路径。

## 自迭代记录

自评后结论：

- 总分 >= 90。
- 无硬阻塞。
- 本轮主域 media 可以标记 completed。
- 可进入下一 remaining generic compatibility domain。

下一轮自动优先级：

1. 若 WebView smoke timeout 再次复现，先修 smoke harness 阶段性 result 写出。
2. 否则继续 post-phase typed IPC cycle。
3. 推荐下一主域：packet locate/full packet read typed IPC。

选择 packet locate/full packet read 的理由：

- 属于主线 packet investigation workflow。
- 范围比 plugin/DBC management 更窄，适合单 round。
- 可与现有 packet page、packet raw/layers typed 方法形成完整 packet 读取闭环。
- MISC multipart package routes 仍应作为 explicit generic IPC compatibility，留到单独 upload/import round。

## Open Blockers

无硬阻塞。

Residual risk：

- WebView typed smoke 第一次出现 timeout，复跑通过；下一轮若复现，应先增强 smoke harness 诊断，而不是推进新域。
- `http.pcap` 不含 media session，因此本轮真实 smoke 覆盖了 media business-empty typed result，没有覆盖真实 artifact download/playback 成功路径。

## 下一轮自动建议

迁移 packet locate/full packet read typed IPC，建议范围：

- `LocatePacketPage`
- `GetPacket`

测试建议：

- `frontend/src/app/integrations/desktopBridge.test.ts`
- `frontend/src/app/integrations/ipcBackendTransport.test.ts`
- `frontend/src/app/integrations/clients/captureClient.test.ts`
- root Go contract test 增补 packet locate/read routes。
- `frontend/scripts/check-wails-bindings.mjs`
- `frontend/scripts/check-desktop-transport-policy.mjs`
- `scripts/check-desktop-ipc-smoke.ps1`
