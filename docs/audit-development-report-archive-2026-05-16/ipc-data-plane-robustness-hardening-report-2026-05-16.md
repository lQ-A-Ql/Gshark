# IPC 数据面健壮性加固报告

署名：Codex  
时间：2026-05-16 23:52:13 +08:00（Asia/Shanghai）

## 1. 本轮目标

本轮针对全 IPC 数据面迁移后的剩余健壮性短板做加固，重点修复：

- typed IPC 控制面 promise 悬挂导致页面无限 loading。
- IPC method typo 被静默归一为 GET。
- blob/base64 响应无限读取导致桌面 WebView 内存放大。
- 桌面 SSE event bridge 使用默认 HTTP client，连接阶段缺少明确 timeout。
- browser HTTP fallback 与 Wails fallback 的 401/token 文案混淆。

## 2. 基线与文档评审

开发前 `git status --short` 为空，本轮没有需要保护的未提交用户改动。

已复读文档：

- `README.md`：已包含 Wails 全 IPC 数据面、首屏轻量解析、runtime fast/full 探测等最新说明；本轮追加 typed IPC timeout、50MB blob guard 和事件桥连接策略说明。
- `docs/README.md`：作为文档索引检查，未发现与本轮健壮性加固冲突的约束。
- `docs/audit-development-report-archive-2026-05-16/wails-full-ipc-data-plane-migration-report-2026-05-16.md`：确认上一轮架构边界是 WebView 不直接 HTTP，桌面壳内部仍代理本地后端 HTTP。本轮在该边界内加固，不改公开 HTTP wire shape。

## 3. 根因与风险

本轮审计确认的风险点：

- `desktopBridge.ts` 中 `GetCaptureStatus`、`ListPacketsPage`、`StartCapture`、TLS、runtime 等 typed IPC 直接 await Wails binding；若 binding promise 悬挂，页面状态可一直停留在 loading。
- `ipcBackendTransport.ts` 中未知 method 会归一为 GET，存在 PUT/PATCH/typo 误读成 GET 的协议安全风险。
- `InvokeBackendBlob` 之前会无限 `io.ReadAll`，再 base64 返回给 WebView；对象 ZIP、媒体导出等大响应可能造成内存尖峰。
- `desktop_event_bridge.go` 使用 `http.DefaultClient`，SSE 建连阶段没有专用 dial/header timeout，断线后 backoff 也不会因为成功事件及时重置。
- `httpBridge.ts` 的裸 401 文案默认提示 Wails dev，在普通浏览器模式下会误导排查方向。

## 4. 修改摘要

### 4.1 Frontend IPC transport

文件：

- `frontend/src/app/integrations/ipcBackendTransport.ts`
- `frontend/src/app/integrations/ipcBackendTransport.test.ts`

变更：

- 新增 `DesktopIpcErrorCode`、`DesktopIpcRequestError.code`、`transport="desktop-ipc"`。
- 新增 `withDesktopIpcControls()`，统一处理 IPC timeout、AbortSignal、endpoint、duration。
- `normalizeMethod()` 现在只接受 `GET | POST | DELETE`；未知 method 直接抛 `invalid_request`，不会调用 Wails binding。
- `__backendRequestMeta` 补充 `responseKind` 和 `timeoutMs`。
- `requestBlobViaIPC` 在 base64 decode 前校验 `size` 和 base64 估算大小，超过 50MB 抛 `blob_too_large`。

### 4.2 Frontend typed IPC calls

文件：

- `frontend/src/app/integrations/desktopBridge.ts`
- `frontend/src/app/integrations/desktopBridge.test.ts`

变更：

- typed IPC 方法统一接入 `withDesktopIpcControls()`：
  - `GetCaptureStatus`
  - `ListPacketsPage`
  - `StartCapture`
  - `StopCapture`
  - `PrepareCaptureReplacement`
  - `CloseCapture`
  - `GetTLSConfig`
  - `UpdateTLSConfig`
  - runtime snapshot/config update
  - `SetTSharkPath`
- timeout 策略：
  - status/page/TLS/stop/close/prepare/runtime full/config update：10s。
  - start capture：15s。
  - runtime fast：2s。
- `listPacketsPage(..., signal)` 现在会尊重 caller AbortSignal，并保留 `AbortError`。
- generic IPC 存在时 typed IPC 失败不 fallback browser HTTP；generic IPC 缺失时仍允许旧 HTTP fallback。

### 4.3 Backend blob guard

文件：

- `desktop_backend_proxy.go`
- `desktop_backend_proxy_test.go`

变更：

- 新增 `desktopBackendBlobMaxBytes = 50 * 1024 * 1024`。
- 新增 `doRawLimited()`，blob 代理使用 `io.LimitReader(max+1)`。
- 超限返回中文错误：`桌面 IPC blob 响应过大：/api/... 超过 50MB，请使用原生导出或缩小选择范围。`
- 增加 exact-limit allowed 与 over-limit rejected 测试。

### 4.4 Desktop event bridge

文件：

- `desktop_event_bridge.go`
- `desktop_event_bridge_test.go`

变更：

- 使用专用 HTTP client/transport：
  - `DialContext` timeout：3s。
  - `TLSHandshakeTimeout`：3s。
  - `ResponseHeaderTimeout`：5s。
  - 不设置总 request timeout，避免正常 SSE 长连接被切断。
- `readBackendEvents()` 返回 `sawEvent`，成功收到 ready/status/packet/error 等事件后将 reconnect backoff 重置为 1s。
- 抽出 `parseDesktopBackendEvent()`，覆盖 ready/status/error/packet 与 malformed data fallback。

### 4.5 HTTP/Wails fallback 诊断分流

文件：

- `frontend/src/app/integrations/httpBridge.ts`
- `frontend/src/app/integrations/httpBridge.test.ts`

变更：

- 401 裸错误按环境生成文案：
  - Wails fallback：提示 Wails token、旧 binding、清理缓存、重新 `build:wails` 或重启 Wails dev。
  - Browser mode：提示 `VITE_BACKEND_TOKEN`、`GSHARK_BACKEND_TOKEN`、Origin 与 `127.0.0.1:17891` 后端端口。
- 保留结构化后端错误优先展示。

## 5. 验证记录

Focused tests：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec vitest run src/app/integrations/ipcBackendTransport.test.ts src/app/integrations/desktopBridge.test.ts src/app/integrations/httpBridge.test.ts src/app/integrations/clients/toolClient.test.ts
```

结果：通过，4 files / 43 tests。

Root focused：

```powershell
cd C:\Users\QAQ\Desktop\gshark
go test -tags dev .
```

结果：通过。

Full regression：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run typecheck
pnpm run lint
pnpm run ci
pnpm run build:wails
```

结果：全部通过；`pnpm run ci` 为 220 files / 677 tests，通过；`build:wails` 完成并通过 desktop asset check。

```powershell
cd C:\Users\QAQ\Desktop\gshark\backend
gofmt -l .
go test ./...
```

结果：`gofmt -l .` 无输出；backend tests 通过。

```powershell
cd C:\Users\QAQ\Desktop\gshark
go test -tags dev ./...
go test -tags production ./...
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1
git diff --check
```

结果：全部通过；desktop asset check ok；`git diff --check` 无输出。

## 6. 回归与兼容性

- 后端公开 HTTP API wire shape 未改。
- Wails generic IPC binding wire shape 未改。
- browser HTTP fallback 保留，且 401/token 文案更贴合浏览器环境。
- 旧 binding 缺少 generic IPC 时，桌面 bridge 仍可走 HTTP fallback 兼容路径。
- typed IPC 增加的是前端本地 timeout/abort 包装，不改变 Go binding 方法签名。
- blob 小文件行为保持不变，超过 50MB 才阻断。

## 7. 评分

总分：96 / 100，等级：Gold。

| Phase | 分值 | 本轮得分 | 说明 |
|---|---:|---:|---|
| Typed IPC timeout/abort | 24 | 24 | typed IPC 关键控制面均接入本地控制；packet page 覆盖 AbortSignal。 |
| IPC request shape safety | 14 | 14 | unknown method 显式 `invalid_request`，测试锁定不调用 binding。 |
| Blob guard | 18 | 17 | 前后端双侧 50MB guard 完成；未做真实 >50MB GUI 导出 smoke。 |
| Event bridge hardening | 18 | 17 | 专用 client、建连 timeout、backoff reset、parser tests 完成；未做手工断线重连 smoke。 |
| Error diagnostics split | 10 | 10 | Wails/browser 401 文案分流完成。 |
| Tests/regression | 12 | 10 | focused 与 full regression 通过；未运行 Wails GUI smoke。 |
| Docs/report | 4 | 4 | README 与本报告已更新。 |

未计奖励：本轮没有执行 DevTools Network 截图、Wails 逐页 GUI smoke、大 blob GUI 压测或事件桥手工断线验证，因此不申报 Platinum。

## 8. 剩余风险

- 50MB blob guard 是防崩溃保护，不是最终的大文件传输方案。对象 ZIP、媒体导出等大文件后续应迁移到原生保存对话框或流式 IPC。
- Wails GUI smoke 尚未执行；当前交付依赖单元、集成、CI、build 与资产检查。
- event bridge 的 header timeout 与 parser 已测试，实际后端重启/网络断线后的 runtime event 表现仍建议做一次手工验证。
- typed IPC 本地 timeout 无法真正取消已经进入 Wails/Go 的调用，只能释放前端等待并给出明确错误；后端侧仍依赖已有 context timeout 收敛。
