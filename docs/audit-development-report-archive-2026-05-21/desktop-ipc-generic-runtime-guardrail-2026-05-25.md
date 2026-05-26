# Desktop IPC Generic Runtime Guardrail

- Author: Codex
- Time: 2026-05-25 00:28:09 +08:00

## 迁移域与目标

本轮按 Phase Audit 自评后的自动建议继续迭代，主域为 Phase 5 后续收口：

- 防止已迁移 typed route 重新回流到 generic `InvokeBackend*`。
- 保留 MISC/import、media、hunting、plugin、DBC、packet locate/full packet 等尚未 typed 的兼容路径。
- 不改变 browser-dev HTTP/SSE 调试链路。

## 修改面清单

- `frontend/src/app/integrations/ipcBackendTransport.ts`
  - 新增 `typed_binding_required` 错误码。
  - generic IPC 在构造 `desktopBackendRequest` 后检查当前路径是否已有匹配 typed DesktopApp binding。
  - 若 typed binding 存在，拒绝调用 `InvokeBackendJSON`、`InvokeBackendBlob`、`InvokeBackendText`。
  - MISC routes 和未 typed routes 继续允许走 generic IPC。
- `frontend/src/app/integrations/ipcBackendTransport.test.ts`
  - 新增 MISC compatibility 允许测试。
  - 新增已 typed JSON route 阻断测试。
  - 新增已 typed blob route 阻断测试。
- `frontend/src/app/integrations/desktopBridge.test.ts`
  - 更新旧预期：typed fast runtime snapshot 失败后，不再允许通过 generic desktop IPC 静默兜底。
- `docs/desktop-ipc-migration-plan.md`
- `docs/desktop-ipc-iteration-status.json`
  - 记录 runtime generic IPC blocklist 成为 Phase 5 guardrail 的一部分。

## Focused Test 结果

已通过：

```powershell
cd frontend
pnpm exec tsc --noEmit --noUnusedLocals --noUnusedParameters
pnpm exec vitest run src/app/integrations/ipcBackendTransport.test.ts src/app/integrations/desktopBridge.test.ts src/app/integrations/bridgeFactory.test.ts
pnpm exec vitest run scripts/check-desktop-transport-policy.test.mjs
node scripts/check-desktop-transport-policy.mjs
node scripts/check-wails-bindings.mjs
```

Focused result：

- `ipcBackendTransport.test.ts`：12 tests passed。
- `desktopBridge.test.ts`：21 tests passed。
- `bridgeFactory.test.ts`：4 tests passed。
- `check-desktop-transport-policy.test.mjs`：5 tests passed。

## Full Gate 结果

本轮文档写入前已通过：

- `go test -tags dev ./...`
- `go test -tags production ./...`
- `cd frontend && pnpm run build:wails`
- `powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1`

文档写入后会继续执行完整 gate。

## 桌面/浏览器行为差异说明

- 桌面 Wails：当 matching typed binding 已存在，generic IPC 不能再代理同一路径，直接抛 `DesktopIpcRequestError(code="typed_binding_required")`。
- 桌面 Wails：MISC/import 和未 typed 兼容路径继续允许 generic IPC。
- Browser dev：不使用 `createIpcBackendTransport`，HTTP/SSE 调试路径保持不变。

## 评分

总分：94 / 100

- Contract Correctness：24 / 25
  - route-to-binding blocklist 覆盖当前已迁移 typed 域。
  - 扣 1 分：blocklist 是手写映射，后续新增 typed binding 时仍需同步。
- Desktop Policy Compliance：20 / 20
  - typed binding 存在时不允许 generic IPC 静默兜底。
- Regression Safety：18 / 20
  - focused tests、binding check、transport policy check 通过。
  - 扣 2 分：本轮报告写入时完整 gate 尚待最终重跑。
- Diagnostics and Failure Shape：14 / 15
  - 新错误码 `typed_binding_required` 能区分 policy block 与 backend/IPC failure。
  - 扣 1 分：错误提示暂未带建议 typed method 参数形态。
- Docs and Traceability：10 / 10
  - tracker、plan、round report 已同步。
- Dev/Browser Compatibility：8 / 10
  - browser-dev 不受 runtime guardrail 影响。
  - 扣 2 分：browser UI 自动化仍未纳入本 round。

## 自迭代记录

自评后结论：

- 分数 >= 90，无硬阻塞，可进入下一轮。
- 下一轮不得扩大成多个域并行，默认选择一个剩余 generic IPC 域。
- 推荐下一轮主域：media typed IPC。

## Open Blockers

无硬阻塞。

## 下一轮自动建议

迁移 media 域 typed IPC：

- `GetMediaAnalysis`
- `TranscribeMediaArtifact`
- `StartMediaBatchTranscription`
- `GetMediaBatchTranscriptionStatus`
- `CancelMediaBatchTranscription`
- `ExportMediaBatchTranscription`
- `DownloadMediaArtifact`
- `GetMediaPlaybackBlob`

测试建议：

- `frontend/src/app/integrations/clients/mediaClient.test.ts`
- `frontend/src/app/integrations/desktopBridge.test.ts`
- `frontend/src/app/integrations/ipcBackendTransport.test.ts`
- root Go contract test 增补 media binding routes。
- `frontend/scripts/check-wails-bindings.mjs`
- `frontend/scripts/check-desktop-transport-policy.mjs`
