# Wails 全 IPC 数据面迁移开发报告

署名：Codex  
时间：2026-05-16 21:12:00 +08:00（Asia/Shanghai）

## 背景与结论

本轮承接“分析页显示超时，HTTP 服务不可用，需要全量迁移 IPC”的修补计划。根因不是后端所有 handler 同时失效，而是 Wails 桌面端此前只把 runtime、capture、packet page、TLS 等少数控制面绑定到 Wails IPC，C2、工控、车机、USB、APT、证据、对象、流、媒体、插件、狩猎、MISC 等页面数据仍继承浏览器 HTTP bridge。一旦 WebView 侧 HTTP token、Origin、端口、fetch 或 readiness 出问题，页面会表现为“后端正常但所有数据功能失效”。

本轮已把 Wails 桌面数据面改为：

```text
React WebView -> Wails IPC -> DesktopApp backend proxy -> 127.0.0.1:17891 后端 HTTP
```

普通浏览器开发模式仍保留 HTTP fallback。后端公开 HTTP API wire shape 未改变。

## Docs 评审

- `README.md`：原说明仍写着 Wails 不是全量 IPC，页面数据主要走本地 HTTP；本轮已更新为 Wails 桌面页面数据走 generic IPC，浏览器模式继续 HTTP fallback。
- `docs/README.md`：文档归档结构仍有效，本轮报告追加到 `docs/audit-development-report-archive-2026-05-16/`。
- `ipc-http-data-plane-hardening-report-2026-05-16.md`：其中 HTTP token hardening 仍保留，作为普通浏览器和旧 binding fallback 的兜底能力；本轮没有回滚这些改动，而是在 Wails 桌面端上层增加全 IPC 数据面。

## 主要修改

- `desktop_backend_proxy.go`：新增 `InvokeBackendJSON`、`InvokeBackendBlob`、`InvokeBackendText`、`PingBackendDataPlane`。通用代理会校验 method/path，只允许 `/health` 和 `/api/...`，拒绝绝对 URL、反斜杠、`..` 和未知 method；支持 JSON、multipart、blob、text，自动注入后端 token，并按 endpoint 类型设置默认 timeout。
- `desktop_event_bridge.go`、`app.go`：新增桌面事件桥。DesktopApp 内部连接后端 `/api/events`，带 token 读取 SSE，再通过 Wails runtime events 转发 `gshark:backend:*`；Shutdown 和 stopBackend 会取消 event bridge。
- `frontend/src/app/integrations/backendBridgeTransport.ts`：抽出共享 BackendBridge builder，让 HTTP transport 和 IPC transport 复用同一套 typed clients。
- `frontend/src/app/integrations/ipcBackendTransport.ts`：新增 Wails generic IPC transport，覆盖 JSON/blob/text/multipart，并附加非枚举 `__backendRequestMeta.transport="desktop-ipc"`。
- `frontend/src/app/integrations/desktopBridge.ts`：Wails generic IPC binding 存在时，以 IPC bridge 作为完整数据面底座；typed IPC 方法继续覆盖高频控制面。IPC 失败不再静默 fallback 浏览器 HTTP；只有旧 binding 缺少 generic IPC 时才使用 HTTP fallback。
- `frontend/src/app/integrations/clients/toolClient.ts`：WinRM text/blob export 改为使用 transport 注入的 `requestText` / `requestBlob`，不再在 client 内部直接 `fetch(apiBase)`。
- `frontend/wailsjs/go/main/DesktopApp.d.ts`、`DesktopApp.js`、`frontend/scripts/check-wails-bindings.mjs`、`desktopTransportBinding.ts`：同步新增 binding，binding drift 检查会覆盖 generic IPC 方法。
- `README.md`：更新 Wails 全 IPC 数据面、runtime events、browser fallback 和 DevTools 验证说明。

## 测试与运行证据

Focused tests：

- `pnpm exec vitest run src/app/integrations/ipcBackendTransport.test.ts src/app/integrations/desktopBridge.test.ts src/app/integrations/clients/toolClient.test.ts`
  - 3 files passed，25 tests passed。
- `pnpm exec vitest run src/app/integrations/desktopBridge.test.ts src/app/integrations/ipcBackendTransport.test.ts src/app/integrations/httpBridge.test.ts src/app/integrations/bridgeFactory.test.ts`
  - 5 files passed，40 tests passed。
- `go test -tags dev ./...`
  - desktop module passed。

Full regression：

- `pnpm run lint`：passed。
- `pnpm run ci`：passed；220 frontend test files，670 tests passed；Vite production build passed。
- `pnpm run build:wails`：passed；Vite build、backend binary build、desktop asset check passed。
- `cd backend; gofmt -l .; go test ./...`：gofmt 输出为空；backend tests passed。
- `go test -tags dev ./...`：passed。
- `go test -tags production ./...`：passed。
- `powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1`：Desktop asset check passed。
- `frontend/scripts/check-wails-bindings.mjs`：Wails binding check passed。

## 回归边界

- 普通浏览器模式仍通过 `httpBridge` 使用 HTTP / EventSource。
- Wails generic IPC binding 存在时，页面数据不再直接从 WebView fetch 后端 `/api/...`。
- 旧 generated binding 缺少 `InvokeBackendJSON` 时，`createDesktopBridge` 仍能退回 HTTP fallback，避免旧桌面资源完全不可用。
- 后端 token 不暴露给页面数据请求；由 DesktopApp backend proxy 注入。
- `/api/capture/start`、`/api/capture/status`、`/api/packets/page` 等后端 wire shape 未改变。

## 评分

| Phase | 分值 | 得分 | 说明 |
|---|---:|---:|---|
| Phase 0：基线与覆盖矩阵 | 8 | 7 | 已固定 dirty worktree、docs、bridge 覆盖缺口；未输出完整逐 endpoint 表格到独立文件 |
| Phase 1：Generic IPC 后端代理 | 20 | 20 | JSON/blob/text/multipart、安全 allowlist、timeout、probe 均完成 |
| Phase 2：Frontend transport 重构 | 22 | 22 | 共享 builder + IPC transport + desktopBridge IPC 底座完成 |
| Phase 3：SSE/Event 全 IPC | 10 | 9 | Desktop SSE reader + runtime events 完成；未做 Wails GUI 事件可视化 smoke |
| Phase 4：Readiness 与诊断 | 12 | 10 | `PingBackendDataPlane` 和 IPC endpoint 错误完成；未新增完整 UI 诊断面板 |
| Phase 5：全页面迁移验收 | 14 | 12 | BackendBridge 长尾 clients 已通过 generic IPC 覆盖；未做逐页面手工 smoke |
| Phase 6：测试、build、smoke | 10 | 8 | Focused/full regression/build:wails 通过；未执行长驻 Wails GUI smoke |
| Phase 7：文档与报告 | 4 | 4 | README 与本报告完成 |

最终评分：92 / 100，Gold。

## 剩余风险

- 大文件 blob 当前经 base64 IPC 返回，>50MB 对象 ZIP / 媒体导出仍建议后续做原生保存或流式传输优化。
- Wails runtime event bridge 已实现，但本轮未进行 DevTools Network 截图验证；后续 smoke 应确认 Wails 页面不再出现 `/api/events` 和页面数据 `/api/...` 的直接浏览器请求。
- Desktop SSE reader 使用重连退避；如果后端长时间未启动，用户会收到事件桥断开提示，但页面数据调用仍以 `PingBackendDataPlane` / IPC request 错误为准。
- 当前保留旧 binding HTTP fallback 是为了兼容未重新 build 的桌面资源；正式发版应确保 `build:wails` 后 `check-wails-bindings` 通过。

## 自迭代记录

1. Probe：确认当前 desktopBridge 仍以 HTTP fallback 为底座，typed IPC 只覆盖少量方法。
2. Patch：先补 Go generic proxy helper，恢复 root compile；再抽前端 shared builder；随后接入 IPC transport；最后迁移 SSE 到 runtime events。
3. Focused Verify：逐步跑 IPC transport、desktopBridge、toolClient、httpBridge、bridgeFactory focused tests。
4. Classify：发现 CI 首次失败为 Prettier 格式问题，格式化后重跑通过。
5. Regression Gate：frontend CI、backend tests、root dev/production、build:wails、desktop asset check 全部通过。
