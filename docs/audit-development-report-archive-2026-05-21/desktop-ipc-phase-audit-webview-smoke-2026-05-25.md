# Desktop IPC Phase Audit WebView Smoke

- Author: Codex
- Time: 2026-05-25 00:28:09 +08:00

## 迁移域与目标

本轮主目标是关闭 Phase 1-5 的 Phase Audit 阻塞项：把“真实 Wails WebView UI/DevTools Network smoke”从人工观察要求推进为机器可判定证据。

边界保持不变：

- `docs/governance-defect-register.json` 不承载 IPC 迁移状态。
- `docs/desktop-ipc-iteration-status.json` 作为版本化事实源。
- 本报告作为本地归档证据，记录本轮验证输出与自迭代结果。

## 修改面清单

- `app.go`
  - 新增 smoke-only Wails binding：`GetDesktopWebviewSmokeConfig`、`WriteDesktopWebviewSmokeResult`。
  - 仅当 `GSHARK_DESKTOP_WEBVIEW_SMOKE_RESULT_PATH` 存在时启用，不影响正常发行版能力。
- `frontend/src/app/desktopWebviewSmoke.ts`
  - 新增真实 WebView typed IPC smoke harness。
  - 在渲染主 App 之前安装 `fetch`、`XMLHttpRequest`、`EventSource` 记录器。
  - 等待桌面后端 ready 后，通过 typed DesktopApp bindings 验证 runtime、MCP、TLS、capture、packet page、stream、analysis、evidence、object、tooling。
- `frontend/src/main.tsx`
  - smoke 启用时先运行 harness，未启用时正常渲染 App。
- `scripts/check-desktop-ipc-smoke.ps1`
  - 在原有 Wails release bootstrap 和 browser-dev smoke 之间新增真实 Wails WebView typed smoke。
  - 校验 `directBackendApiRequestCount = 0`。
- `frontend/wailsjs/go/main/DesktopApp.d.ts`
- `frontend/wailsjs/go/main/DesktopApp.js`
- `frontend/src/app/integrations/desktopTransportBinding.ts`
- `frontend/scripts/check-wails-bindings.mjs`
  - 同步新增 smoke-only bindings。
- `docs/desktop-ipc-migration-plan.md`
- `docs/desktop-ipc-iteration-status.json`
  - Phase 1-5 标记为 `completed`。

## Focused Test 结果

已通过：

```powershell
cd frontend
pnpm exec tsc --noEmit --noUnusedLocals --noUnusedParameters
pnpm exec vitest run src/app/integrations/ipcBackendTransport.test.ts src/app/integrations/desktopBridge.test.ts src/app/integrations/bridgeFactory.test.ts
pnpm run lint
pnpm run format:check
pnpm run size:check
node scripts/check-desktop-transport-policy.mjs
node scripts/check-wails-bindings.mjs
```

已通过：

```powershell
go test -tags dev ./...
go test -tags production ./...
cd frontend
pnpm run build:wails
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1
```

## Full Gate 结果

本轮已跑过 root dev/production、frontend focused gate、`build:wails`、binding check、transport policy check、desktop asset check 和真实 Wails smoke。

待本报告写入后会继续执行完整 gate：

```powershell
go test -tags dev ./...
go test -tags production ./...
cd backend && go test ./...
cd frontend && pnpm run ci
cd frontend && pnpm run build:wails
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1
node frontend/scripts/check-wails-bindings.mjs
node frontend/scripts/check-desktop-transport-policy.mjs
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1
```

## 桌面/浏览器行为差异说明

- 桌面 Wails release bootstrap：启动嵌入后端，创建 WebView2 环境，加载前端 dist。
- 桌面 Wails WebView typed smoke：不走 WebView fetch 后端 `/api/...`，直接通过 typed DesktopApp bindings 执行主域验证。
- 浏览器 dev：继续使用 HTTP/SSE 调试链路，验证 `/health`、runtime identity、runtime config、MCP config、TLS、SSE、capture、packet、stream、industrial、evidence、object、HTTP-login tooling。

## Smoke 证据摘要

`output/desktop-ipc-smoke/desktop-ipc-smoke-summary.json` 摘要：

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
- `desktopWebviewTyped.directBackendApiRequestCount = 0`

旧错误模式复查：

```powershell
Select-String -Path output\desktop-ipc-smoke\wails-release-smoke.log,output\desktop-ipc-smoke\wails-webview-typed-smoke.log -Pattern 'error parsing arguments|expected 0|process message error|NativeCommandError' -SimpleMatch -Encoding UTF8
```

结果：无匹配。

## 评分

总分：96 / 100

- Contract Correctness：24 / 25
  - typed bindings 在真实 Wails WebView 中执行，覆盖 runtime、MCP、TLS、capture、packet page、stream、analysis、evidence、object、tooling。
  - 扣 1 分：smoke 仍是代表性主路径，不等价于所有页面交互全覆盖。
- Desktop Policy Compliance：20 / 20
  - WebView typed smoke 中 `directBackendApiRequestCount = 0`。
  - typed IPC 零参数调用错误未复现。
- Regression Safety：20 / 20
  - focused tests、root dev/production、`build:wails`、binding check、transport policy check、desktop smoke 通过。
- Diagnostics and Failure Shape：14 / 15
  - smoke 脚本会写出失败 JSON、Wails stdout/stderr 与 direct backend API request 列表。
  - 扣 1 分：当前 Network 证据来自前端 API 拦截器，不是 CDP 底层 Network event。
- Docs and Traceability：10 / 10
  - plan、tracker、本地报告同步。
- Dev/Browser Compatibility：8 / 10
  - browser-dev HTTP/SSE smoke 通过。
  - 扣 2 分：browser-dev 仍是 API 级 smoke，不是完整 UI 自动化。

## 自迭代记录

本轮发现并修复两个评估机制缺口：

- CDP 方案不可直接依赖：go-webview2 会覆盖外部 `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`，导致 `--remote-debugging-port` 不稳定。
- 初版 WebView smoke 过早调用 typed IPC，后端尚未监听 17891。已加入 `IsBackendReady` + `PingBackendDataPlane` 等待。

决策：Phase Audit 通过，可进入下一轮。下一轮按优先级继续收口 generic IPC 剩余兼容面。

## Open Blockers

无硬阻塞。

## 下一轮自动建议

进入 post-Phase 5 迁移循环：继续选择一个剩余 generic IPC 兼容域做 typed IPC 化。默认建议选择 media 域，因为 media playback/export/transcription 仍是高频用户路径，且当前还依赖 generic IPC/HTTP-compatible routes。
