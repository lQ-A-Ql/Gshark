# 四项安全缺陷加固开发报告

署名：Codex

时间：2026-05-19 19:05:00 +08:00（Asia/Shanghai）

## 本轮目标

落地四项审计缺陷修复：

- 移除 `wails.localhost` Origin 单独绕过后端 token 的认证路径。
- 为 `/api/capture/upload` 增加硬上传上限与落盘限流。
- 为 MISC zip 模块 `manifest.json` 读取增加大小限制。
- 为更新中心 Release Markdown 链接增加协议白名单。

## 文档评审

- `docs/README.md`：当前事实仍以治理登记表、接口文档和归档报告为准；本轮报告按规则写入 `docs/audit-development-report-archive-2026-05-19/`。
- `docs/governance-defect-register.json`：当前唯一 open 项仍为 `P2-6` schema/codegen feasibility，本轮四项加固属于审计补强，不改变该 open 项状态。
- `docs/misc-module-interface.md`：MISC 模块仍是本地可信扩展模型，本轮只收紧 zip 读取边界，不改变模块接口。
- 2026-05-16 IPC 数据面报告：本轮认证收紧保持 Wails IPC 由桌面代理注入 token 的方向，不回退全 IPC 数据面。

## 修改摘要

### 后端认证边界

- `backend/internal/transport/http_server.go`
  - `authToken` 非空时，除 `/health` 外不再因 `Origin: http://wails.localhost` 直接放行。
  - 保留 Bearer、`X-GShark-Auth`、query `access_token` 鉴权路径。
  - 保留 CORS 对 `wails.localhost` 的允许语义，但不再把 Origin 当作认证凭据。

- `backend/internal/transport/http_server_test.go`
  - 更新 trusted desktop origin 测试：无 token 返回 `401`，带 Bearer token 返回 `200`。

### PCAP 上传限流

- `backend/internal/transport/http_capture.go`
  - 新增 2GB 上传硬上限。
  - 请求体使用 `http.MaxBytesReader`。
  - multipart 内存预算降为 64MB。
  - 落盘复制使用 limit helper，超限返回 `413 Request Entity Too Large` 并清理临时文件。

- `backend/internal/transport/http_capture_test.go`
  - 覆盖小文件上传成功。
  - 覆盖超限上传返回 `413` 且不遗留临时抓包文件。

### MISC manifest 读取限制

- `backend/internal/miscpkg/manager.go`
  - `readPackageManifest()` 使用 `io.LimitReader(maxModuleZipFileBytes+1)`。
  - 超过限制时返回明确的 `manifest.json exceeds size limit` 错误。

- `backend/internal/miscpkg/manager_test.go`
  - 覆盖 oversized manifest 拒绝路径。

### Release Markdown 链接安全

- `frontend/src/app/features/update/UpdateReleaseMarkdown.tsx`
  - 新增 Release Markdown href 规范化。
  - 仅允许 `http:`, `https:`, `mailto:` 和站内相对路径。
  - 拒绝 `javascript:`, `data:`, `vbscript:`, 控制字符、空 href 和解析失败协议。
  - 危险链接降级为不可点击文本。
  - 保持 `react-markdown + remark-gfm`，未启用 raw HTML。

- `frontend/src/app/features/update/UpdateReleaseMarkdown.test.tsx`
  - 覆盖安全绝对链接、相对链接、危险协议、大小写混淆、空 href。

## 验证记录

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\backend
go test ./internal/transport -run "TestWithAuthRequiresTokenForTrustedDesktopOrigin|TestWithAuthRequiresMatchingToken|TestHandlerAllowsEventStreamAccessTokenAndRejectsWrongToken|TestHandleCaptureUpload" -count=1
go test ./internal/miscpkg -run "TestImportZipBytesRejectsOversizedManifest|TestImportZipBytesRejectsOversizedFile" -count=1
go test ./internal/transport ./internal/miscpkg -count=1
go test ./...
gofmt -l internal\transport\http_server.go internal\transport\http_server_test.go internal\transport\http_capture.go internal\transport\http_capture_test.go internal\miscpkg\manager.go internal\miscpkg\manager_test.go

cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm test:run -- src/app/features/update/UpdateReleaseMarkdown.test.tsx
pnpm typecheck
pnpm lint
pnpm run ci
pnpm run build:wails

cd C:\Users\QAQ\Desktop\gshark
go test -tags dev ./...
go test -tags production ./...
git diff --check
```

最终结果：全部通过。根目录带 `dev` / `production` 标签测试依赖 `frontend/dist/sentinel-backend.exe`，已通过 `pnpm run build:wails` 生成并校验桌面嵌入资产。

## 自审结论

- 四项缺陷均已按计划落地。
- 后端 token 认证语义更严格，Wails IPC 数据面仍通过桌面代理注入 token。
- 上传限流同时覆盖 request body 与落盘 copy。
- MISC manifest 读取不再绕过 zip 单文件限制。
- Release Markdown 链接不再直接透传危险协议。

## 剩余风险

- 2GB 限制作用于 multipart 请求整体；实际可上传文件会略小于 2GB，因为 multipart envelope 也占体积。
- MISC 模块执行仍是本地可信扩展模型，本轮只限制导入读取资源消耗。
- Markdown 链接安全目前只应用在更新中心 Release notes；若未来新增外部 Markdown 渲染入口，应复用同一套 href 规范化规则。
