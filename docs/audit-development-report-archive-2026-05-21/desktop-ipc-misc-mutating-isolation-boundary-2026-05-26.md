# Desktop IPC MISC mutating isolation boundary round

- Author: Codex
- Time: 2026-05-26 02:43:13 +08:00
- Round: 14
- Phase: post-phase-5
- Primary slice: MISC mutating typed IPC isolation boundary

## 迁移域与目标

本轮不迁移新的 mutating typed binding。目标是先建立可验证的 MISC 临时包状态边界，避免后续 `DeleteMiscModulePackage` 或 `RunMiscModulePackage` smoke 触碰用户真实 MISC 包目录。

完成后的边界：

- 桌面 release smoke 使用 `output/desktop-ipc-smoke/misc-packages/desktop-release-*`。
- 桌面 WebView typed smoke 使用 `output/desktop-ipc-smoke/misc-packages/desktop-webview-*`。
- 浏览器 dev backend smoke 使用 `output/desktop-ipc-smoke/misc-packages/browser-dev-*`。
- WebView smoke 同时记录配置目录和后端 runtime identity 实际目录，并断言二者一致。

## 修改面清单

- `backend/internal/transport/http_server.go`
  - `Server` 记录解析后的 `miscPackageDir`。
  - `/api/runtime/identity` 增加 `misc_package_dir`，用于 smoke 和诊断确认后端实际包目录。
- `backend/internal/transport/http_server_test.go`
  - `TestHandleRuntimeIdentityReportsServiceAndAuthState` 断言 `misc_package_dir` 等于测试隔离目录。
- `desktop_backend_proxy.go`
  - `PingBackendDataPlane` 返回 `misc_package_dir`，让 WebView smoke 可以确认后端实际目录。
- `app.go`
  - `GetDesktopWebviewSmokeConfig` 暴露 `misc_package_dir`，优先读取 `GSHARK_DESKTOP_WEBVIEW_SMOKE_MISC_PACKAGE_DIR`，否则读取 `GSHARK_MISC_PACKAGE_DIR`。
- `frontend/src/app/desktopWebviewSmoke.ts`
  - WebView smoke 要求 MISC 隔离目录非空。
  - WebView smoke 断言后端 `misc_package_dir` 与配置目录一致。
  - WebView smoke 结果写入 `miscPackageIsolationDir` 和 `backendMiscPackageDir`。
- `scripts/check-desktop-ipc-smoke.ps1`
  - 为 desktop release、desktop WebView、browser-dev 创建独立 MISC 包目录。
  - 设置并恢复 `GSHARK_MISC_PACKAGE_DIR` / `GSHARK_DESKTOP_WEBVIEW_SMOKE_MISC_PACKAGE_DIR`。
  - 断言所有 MISC 包目录位于 smoke 输出根目录下。
  - 在 summary 中记录三个运行模式的 MISC 包目录。
- `docs/desktop-ipc-iteration-status.json`
  - Round 14 状态、评分、证据和下一轮建议已更新。
- `docs/desktop-ipc-migration-plan.md`
  - 增加 Round 14 状态和开发记录。
- `docs/desktop-ipc-misc-native-binding-design.md`
  - 标记 `mutating-isolation-ready`，允许下一轮单独迁移一个 mutating route。

## Focused test 结果

- `go test -tags dev ./...`
  - 通过。
- `cd backend && go test ./...`
  - 通过。
- `cd frontend && pnpm run typecheck`
  - 通过。
- `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1 -SkipDesktop -TimeoutSeconds 120`
  - 通过。
  - Browser-dev backend 使用 `output/desktop-ipc-smoke/misc-packages/browser-dev-*`。

## Full gate 结果

- `go test -tags dev ./...`
  - 通过。
- `go test -tags production ./...`
  - 通过。
- `cd backend && go test ./...`
  - 通过。
- `cd frontend && pnpm run ci`
  - 通过，231 个 test files / 727 个 tests。
- `cd frontend && pnpm run build:wails`
  - 通过。
- `powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1`
  - 通过。
- `node frontend/scripts/check-wails-bindings.mjs`
  - 通过。
- `node frontend/scripts/check-desktop-transport-policy.mjs`
  - 通过。
- `node frontend/scripts/check-desktop-generic-ipc-allowlist.mjs`
  - 通过。
- `node frontend/scripts/check-desktop-old-binding-compat.mjs`
  - 通过。
- `node frontend/scripts/check-desktop-misc-compat-inventory.mjs`
  - 通过。
- `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1 -TimeoutSeconds 180`
  - 通过。
- `git diff --check`
  - 通过。

## 桌面/浏览器行为差异说明

- Desktop release:
  - 继续启动嵌入后端。
  - 本轮 smoke 设置 `GSHARK_MISC_PACKAGE_DIR` 到 smoke-owned 临时目录。
  - 不使用用户真实 MISC package 目录。
- Desktop WebView:
  - 继续 typed IPC 优先。
  - WebView smoke 仍调用 typed `ListMiscModules`。
  - `directBackendApiRequestCount = 0`。
  - `miscPackageDir` 与 `backendMiscPackageDir` 均指向同一个 `desktop-webview-*` 隔离目录。
- Browser dev:
  - 继续 HTTP/SSE。
  - backend 使用 `browser-dev-*` 隔离目录。
  - HTTP/SSE 不受桌面 typed IPC 策略误伤。

## Smoke evidence

本轮最终 summary:

- `output/desktop-ipc-smoke/desktop-ipc-smoke-summary.json`
- `desktopRelease.ok = true`
- `desktopWebviewTyped.ok = true`
- `browserDev.ok = true`
- `desktopRelease.miscPackageDir = output/desktop-ipc-smoke/misc-packages/desktop-release-*`
- `desktopWebviewTyped.miscPackageDir = output/desktop-ipc-smoke/misc-packages/desktop-webview-*`
- `desktopWebviewTyped.backendMiscPackageDir = output/desktop-ipc-smoke/misc-packages/desktop-webview-*`
- `browserDev.miscPackageDir = output/desktop-ipc-smoke/misc-packages/browser-dev-*`
- `desktopWebviewTyped.capturePackets = 7074`
- `desktopWebviewTyped.packetPageTotal = 7074`
- `desktopWebviewTyped.miscModuleCount = 8`
- `desktopWebviewTyped.threatHitCount = 721`
- `desktopWebviewTyped.objectCount = 205`
- `desktopWebviewTyped.directBackendApiRequestCount = 0`

## 评分

Total: 97/100

- Contract Correctness: 24/25
  - 后端 runtime identity、desktop data-plane probe、WebView smoke config 的目录语义一致。
  - 扣 1 分：本轮不是新业务 binding 迁移，mutating method 合约仍待下一轮实现。
- Desktop Policy Compliance: 20/20
  - 已迁移 MISC list 仍 typed IPC 优先。
  - 没有新增 generic IPC 扩散。
  - WebView 直接 backend `/api` 请求仍为 0。
- Regression Safety: 20/20
  - Focused tests、full gates、Wails build、desktop/browser smoke 均通过。
- Diagnostics and Failure Shape: 15/15
  - smoke 能明确区分“未配置隔离目录”“隔离目录不在 smoke root”“后端实际目录与配置目录不一致”。
- Docs and Traceability: 10/10
  - tracker、plan、MISC native binding design 和 round report 均已更新。
- Dev/Browser Compatibility: 8/10
  - Browser-dev HTTP/SSE 保持可用。
  - 扣 2 分：browser-dev 仍通过环境变量隔离 MISC 目录，尚未覆盖 multipart import 的 typed/native 替代路径。

## Open blockers

无硬阻塞。

显式保留项：

- `DeleteMiscModulePackage` 尚未迁移到 typed IPC。
- `RunMiscModulePackage` 尚未迁移到 typed IPC。
- `POST /api/tools/misc/import` 仍保留为 explicit generic IPC compatibility，等待 native file-path import binding。

## 自迭代记录

自动决策：本轮 score 为 97，且无硬阻塞，允许进入下一 round。

本轮曾发现一次 smoke 失败：

- 现象：完整 smoke 读取到旧 `frontend/dist` bundle，结果缺少 `miscPackageIsolationDir`，脚本路径断言失败。
- 处理：明确执行 `pnpm run build:wails` 后重跑完整 smoke；同时脚本增加空路径诊断，避免非法路径异常吞掉真实原因。
- 结论：full gate 中必须保持 `pnpm run ci` 后再执行 `pnpm run build:wails`，然后再跑 Wails smoke。

## 下一轮自动建议

下一轮只做一个主域切片：

- Preferred: `DeleteMiscModulePackage` typed IPC。
- 范围：
  - 添加 root `DesktopApp.DeleteMiscModulePackage(id string)`。
  - 前端 MISC typed bridge 覆盖 delete 路径。
  - runtime generic IPC 对 `DELETE /api/tools/misc/packages/{id}` 在 binding 存在时拒绝。
  - root Go contract test 使用临时 MISC package dir。
  - frontend desktopBridge/ipcBackendTransport/toolClient 测试覆盖 delete typed path 与 missing-binding fallback。
  - smoke 可以只断言隔离目录存在，不必删除真实用户包。
- 不做：
  - 不同时迁移 `RunMiscModulePackage`。
  - 不迁移 multipart import。
  - 不改变 browser-dev HTTP multipart。
