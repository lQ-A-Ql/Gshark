# Backend Bridge Runtime Audit Report - 2026-05-15

Author: Codex

Timestamp: 2026-05-15 22:10:23 +08:00 (Asia/Shanghai)

## 本轮目标

按《GShark-Sentinel 后端与桥接层运行可靠性优化 Spec》实施桌面运行链路修复，重点解决后端已可连接但桌面启动不稳的问题。目标不是重写业务能力，而是把启动页、TShark 探测、Wails 桥接、桌面资源、MISC 运行目录和 release smoke 串成可复现、可验收的交付门槛。

## 读取的文档

- `README.md`
- `AGENTS.md`
- `docs/README.md`
- `docs/governance-defect-register.json`
- `docs/backend-engineering-audit-spec-2026-05-14.md`
- `docs/frontend-engineering-audit-spec-2026-05-15.md`
- `docs/misc-module-interface.md`
- `docs/plugin-interface.md`
- `docs/audit-development-report-archive-2026-05-15/frontend-engineering-report-2026-05-15.md`
- `docs/audit-development-report-archive-2026-05-15/frontend-layout-mock-report-2026-05-15.md`
- `docs/audit-development-report-archive-2026-05-15/global-select-route-motion-report-2026-05-15.md`

## 文档评审

- `README.md` 的前端/后端分工仍准确；本轮已补充 `pnpm run build` 与 `pnpm run build:wails` 的区别，避免把纯 Vite build 误认为桌面运行验收。
- `docs/misc-module-interface.md` 原先描述的 MISC 安装目录倾向 cwd/runtime 目录，和本轮发现的源码污染风险有关；本轮已改成用户配置目录优先，并记录 `GSHARK_MISC_PACKAGE_DIR` 覆盖方式。
- `docs/backend-engineering-audit-spec-2026-05-14.md` 对后端可靠性和 API 合约风险的判断仍成立；本轮处理的是桌面 bootstrap 与桥接一致性，不关闭 `P2-6` schema/codegen 总议题。
- `docs/frontend-engineering-audit-spec-2026-05-15.md` 是当前最新前端工程审计，和本轮新增的 Wails binding check、StartupGate 测试方向一致。
- `docs/governance-defect-register.json` 当前仍应保留 `P2-6` open；本轮没有修改治理登记状态。

## 保护现场

实施前后均检查了 `git status --short`。本轮保留已有用户/前序改动，没有回滚 `.gitignore`、前端 UI 改动、`http_tools.go`、静态 mock、前端工程审计文档和若干前端测试。

既有或并行改动中仍可见：

- `frontend/src/app/components/ui/select.tsx`、`MainLayout.tsx`、`theme.css` 等前端 UI/动效相关文件。
- `frontend/mock.html`、`docs/frontend-engineering-audit-spec-2026-05-15.md`。
- `backend/internal/transport/http_tools.go` 为未跟踪文件，但本轮未删除或改写其所有权。

本轮明确删除的是 `backend/internal/transport/plugins/misc/*` 下被跟踪的 echo-demo 测试产物；这些文件属于运行目录污染，示例模块保留在 `examples/misc-modules/echo-demo`。

## 根因结论

真实根因：

1. `frontend/dist` 可能只有 Vite 静态产物，缺少 `sentinel-backend.exe` 和 `rules/yara/default.yar`，导致桌面内嵌后端启动链路断裂。
2. Wails 生成绑定陈旧，`DesktopApp.d.ts/js` 只暴露 `BackendStatus()`，和实际前端桥接调用面不一致。
3. `StartupGate` 把 TShark 可用性当成进入主界面的硬条件；当 TShark 缺失或 `-G fields` 能力探测较慢时，后端已连接也会卡在启动页。
4. 启动 runtime 检查优先执行 update 配置，触发完整 runtime snapshot 和 TShark 能力探测；前端 timeout 原先只是 `Promise.race`，没有取消底层请求。
5. MISC 默认运行目录和 cwd 绑定，测试或本地运行会把 zip 模块解压到源码树并进入版本控制。
6. 原有检查链偏向编译/单测，不能证明 Wails 桌面产物可以拉起内嵌后端。

非根因：

- `pnpm` 不缺失。本机 `pnpm --version` 为 `10.31.0`。
- `corepack` 不是本项目硬依赖；前端包管理依赖 pnpm lockfile 与 package manager 检查，不应把 corepack 缺失列为运行失败原因。

## 工具链确认

- `pnpm --version` -> `10.31.0`
- `go version` -> `go version go1.26.0 windows/amd64`
- `wails doctor` -> Wails `v2.11.0`，系统 ready for Wails development
- `tshark -v` -> `TShark (Wireshark) 4.6.5`

## 修改文件

核心启动/TShark：

- `frontend/src/app/App.tsx`
- `frontend/src/app/App.test.tsx`
- `frontend/src/app/state/hooks/backendLifecycleStartup.ts`
- `frontend/src/app/state/hooks/backendLifecycleTLSStartup.ts`
- `frontend/src/app/state/hooks/backendLifecycleToolRuntimeStartup.ts`
- `frontend/src/app/state/hooks/useBackendLifecycle.test.tsx`
- `frontend/src/app/integrations/bridgeTypes.ts`
- `frontend/src/app/integrations/clients/toolRuntimeClient.ts`
- `frontend/src/app/integrations/desktopBridge.ts`
- `frontend/src/app/integrations/desktopBridge.test.ts`
- `frontend/src/app/utils/asyncControl.ts`
- `frontend/src/app/utils/asyncControl.test.ts`
- `backend/internal/tshark/config.go`
- `backend/internal/tshark/config_test.go`
- `backend/internal/engine/tool_runtime.go`
- `backend/internal/transport/services.go`
- `backend/internal/transport/http_server.go`
- `backend/internal/transport/misc_package_handlers.go`

桌面资源/Wails/release：

- `scripts/check-desktop-assets.ps1`
- `scripts/check-all.ps1`
- `scripts/build-release-package.ps1`
- `frontend/package.json`
- `frontend/package.json.md5`
- `frontend/scripts/check-wails-bindings.mjs`
- `frontend/wailsjs/go/main/DesktopApp.d.ts`
- `frontend/wailsjs/go/main/DesktopApp.js`
- `desktop_assets_test.go`
- `app.go`

MISC 运行目录：

- `.gitignore`
- `backend/internal/transport/http_server.go`
- `backend/internal/transport/http_server_test.go`
- `backend/internal/transport/http_contract_test.go`
- `backend/internal/transport/plugins/misc/*` 删除
- `docs/misc-module-interface.md`

文档：

- `README.md`
- `docs/audit-development-report-archive-2026-05-15/backend-bridge-runtime-audit-report-2026-05-15.md`

## TShark 加载页阻塞专项结论

已将进入主界面的必要条件改成后端连接成功。TShark 缺失、慢探测或能力 degraded 不再阻塞整个 UI；启动页仍显示 TShark 状态，但文案改为“未检测到 TShark，可在设置中配置”这类可恢复警告。

启动 runtime 检查改为优先 `getToolRuntimeSnapshot(signal)`。只有本地保存配置和后端 snapshot 不一致时，才异步执行 `updateToolRuntimeConfig(config, signal)`。前端新增 `withAbortableTimeout`，timeout 后通过 `AbortController` 取消底层 HTTP fallback 请求；桌面 Wails runtime 调用在需要 abort signal 时走 HTTP fallback，避免 IPC 请求继续挂在 UI 生命周期里。

后端新增 context-aware TShark/runtime 方法：`CurrentStatusWithContext(ctx)`、`ToolRuntimeSnapshotWithContext(ctx)`、`TSharkStatusWithContext(ctx)`、`SetTSharkPathWithContext(ctx,path)`。HTTP handlers 现在把 `r.Context()` 传入服务层，request cancel 能停止 TShark 能力探测。Windows GUI PATH 缺 Wireshark 时，会额外尝试 `C:\Program Files\Wireshark\tshark.exe` 和 `C:\Program Files (x86)\Wireshark\tshark.exe`。

## 桌面资源修复结论

新增 `scripts/check-desktop-assets.ps1`，强制检查：

- `frontend/dist/sentinel-backend.exe`
- `frontend/dist/rules/yara/default.yar`

`frontend/package.json` 的 `build:wails` 现在执行 Vite build、后端二进制复制和桌面资源检查。`scripts/check-all.ps1` 增加桌面资源构建/检查和 production tag root 测试。新增 `desktop_assets_test.go`，在 `dev || production` build tag 下验证嵌入资源存在且非空。

`README.md` 已明确：`pnpm run build` 只是前端静态构建，不能作为桌面验收；`pnpm run build:wails` 才会生成 Wails 桌面需要的后端 exe 与 YARA 规则资源。

## Wails 桥接修复结论

`frontend/wailsjs/go/main/DesktopApp.d.ts` 和 `.js` 已包含以下桥接面：

- `BackendStatus`
- `GetBackendAuthToken`
- `OpenCaptureDialog`
- `OpenDBCDialog`
- `IsBackendReady`
- `GetToolRuntimeSnapshot`
- `UpdateToolRuntimeConfig`
- `SetTSharkPath`
- `StartCapture`
- `StopCapture`
- `PrepareCaptureReplacement`
- `CloseCapture`
- `GetCaptureStatus`
- `GetTLSConfig`
- `UpdateTLSConfig`
- `CheckAppUpdate`
- `InstallAppUpdate`

新增 `frontend/scripts/check-wails-bindings.mjs` 和 `pnpm run wails-binding:check`，并接入前端 CI。前端仍保留动态 `window.go` 策略，不强制改成静态 import generated binding；当桌面 runtime 方法缺失或需要 abort signal 时，桥接层可以回退 HTTP bridge。

## MISC 与桥接可靠性结论

新增 `ServerOptions` 和 `NewServerWithOptions`，测试可注入临时 MISC package dir。运行时新增 `GSHARK_MISC_PACKAGE_DIR` 覆盖；默认目录改成用户配置目录 `gshark-sentinel/plugins/misc`，获取失败时才回退到 temp 目录。

Transport 测试覆盖 MISC dir override/env/default 解析、SSE query token 鉴权。`/health` 仍免鉴权；受保护 API 与 SSE 错误 token 返回 401。

源码树下被跟踪的 `backend/internal/transport/plugins/misc/echo-demo-*` 已删除，`.gitignore` 增加 `.gocache/` 和 `backend/internal/transport/plugins/misc/`，避免后续运行产物继续污染工作区。

## 验证命令和结果

通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\backend
gofmt -l .
go test ./...
```

结果：backend 全量测试通过。

通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark
go test -tags dev ./...
go test -tags production ./...
```

结果：root dev/production tag 测试通过，嵌入桌面资源测试通过。

通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run ci
```

结果：package-manager、typecheck、lint、format、size、boundary、client/mapper/wire any、Wails binding check、Vitest、Vite build 全部通过；观测到 `213` 个 test files、`616` 个 tests 通过。

通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run build:wails
```

结果：Vite build、后端二进制复制、桌面资源检查全部通过，输出 `Desktop asset check: ok`。

通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1
```

结果：`Desktop asset check: ok`。

通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark
powershell -ExecutionPolicy Bypass -File .\scripts\build-release-package.ps1 -Version local-smoke-20260515 -OutputDir $env:TEMP\gshark-release-smoke-20260515-final -NoRepoManifestUpdate
```

结果：Wails build 完成，桌面资源检查通过，release asset/manifest 生成成功，release smoke 明确输出 `release smoke check: ok`。

通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run wails-binding:check
```

结果：`Wails binding check: ok`。

## 评分

| 阶段 | 分值 | 得分 | 说明 |
|---|---:|---:|---|
| Phase 0 | 8 | 8 | 完成工具链、docs、git status 和根因/非根因确认。 |
| Phase 1 | 18 | 18 | TShark 不再阻塞主界面，启动 snapshot 优先，abort/context 和默认路径兜底已实现。 |
| Phase 2 | 18 | 18 | 桌面资源检查、build:wails、check-all、嵌入资源测试和 README 说明已完成。 |
| Phase 3 | 14 | 14 | Wails 绑定再生成，桥接类型校准，漂移检查接入 CI。 |
| Phase 4 | 14 | 14 | MISC 默认目录迁移，env override，测试注入，源码污染清理，鉴权/SSE smoke 覆盖。 |
| Phase 5 | 20 | 18 | 自动化验收、release smoke 均通过；未做真实小型 PCAP 手动冒烟，扣 2。 |
| Phase 6 | 8 | 8 | README、MISC 文档和本报告完成，含 docs 评审与评分。 |

基础分：98/100。

奖励项：

- +2 干净工作区守卫：`.gocache/` 与 MISC runtime 目录加入忽略，测试可注入临时目录，源码 MISC 污染产物已清理。
- +1 用户可读故障提示优化：TShark 不可用降级为可配置警告，release smoke 失败会保留 stdout/stderr 文本。

最终计分：101/110。按分值达到 Platinum 区间，但本轮未完成真实 Browser/Wails 可视化冒烟、专用 fake slow TShark 二进制测试和冷启动性能记录，因此交付等级按 Gold 完成定义收口。

## 遗留风险

1. 未执行真实 Wails 可视化路径：启动页、欢迎页、设置侧栏和打开抓包按钮已由 jsdom/脚本覆盖主要状态，但还没有人工或浏览器截图确认真实 WebView 表现。
2. 未执行真实小型 PCAP 冒烟：后端、资源、release bootstrap 已通过，但没有在 UI 中打开样本并核对 packet count。
3. TShark 慢探测主要由 StartupGate 慢 promise、abort timeout 和后端 context cancellation 测试覆盖；未额外创建 fake `tshark.exe` 模拟 `-G fields` 慢响应，因此不领取该奖励项。
4. 工作区仍有前序/用户改动和未跟踪文件，本轮没有回滚；后续提交前应按归属拆分提交。
5. `P2-6` schema/codegen 治理议题仍未解决，不应因本轮桥接可靠性修复而关闭。

## 自评

本轮已把“单项检查能过但桌面启动不稳”的主要断点转为可检查的构建和 smoke 门槛。最关键的行为变化是：后端连上即可进入主界面，TShark 降级只影响抓包/解析能力；Wails dist 必须带后端 exe 与 YARA 规则；release smoke 必须验证内嵌后端 bootstrap。剩余风险主要集中在真实可视化和真实 PCAP 操作冒烟，属于下一轮手动/端到端 UI 验收范围。
