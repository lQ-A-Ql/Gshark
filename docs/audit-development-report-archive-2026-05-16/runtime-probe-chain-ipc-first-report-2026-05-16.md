# 运行时工具探测链路 IPC 优先修复报告

- 作者：Codex
- 时间：2026-05-16 03:18:40 +08:00（Asia/Shanghai）
- 工作区：`C:\Users\QAQ\Desktop\gshark`

## 本轮目标

按“运行时工具探测链路全量审计与修复计划”实施修复，重点解决 Wails dev 下后端已启动但设置页长期显示 TShark、FFmpeg、Python、YARA 全部“未检测 / 等待检测”的链路分裂问题。

本轮结论：`usbms.scsi.opcode` 不是 TShark 不可读。当前源码日志已经改为 `tshark capability degraded ... optional fields missing ... (tshark remains available)`；如果仍看到旧文案 `tshark capability: ... missing optional fields ...`，优先判断为旧后端进程、旧二进制或 Wails/Go 缓存。

## 读取与评审的 docs

- `README.md`：已包含运行时环境变量、Wails dev 和 `build:wails` 说明；本轮继续补充 Wails IPC 优先、HTTP fallback 边界、runtime identity provenance 和旧日志诊断。
- `docs/README.md`：确认本地 archive 只作为逐轮记录，当前事实需要沉淀到 README、接口文档或治理登记表。
- `docs/audit-development-report-archive-2026-05-16/wails-dev-runtime-probe-report-2026-05-16.md`：前轮对 Wails dev 旧缓存和 `tshark capability degraded` 语义的判断正确，但还缺少桥接层 IPC 优先和 snapshot failure UI 状态机。
- `docs/audit-development-report-archive-2026-05-15/runtime-tool-detection-migration-report-2026-05-15.md`：旧 localStorage 空配置污染和 resolver 结论仍成立，本轮没有回滚该修复。
- `docs/audit-development-report-archive-2026-05-15/runtime-env-config-audit-report-2026-05-15.md`：env 被前端空配置覆盖的根因已由前轮修复，本轮关注 Wails/HTTP bridge 和 UI snapshot 状态。

评审结论：现有文档方向正确，但用户当前遇到的问题已经从“后端无法探测工具”演变为“Wails 桥接和前端状态无法可靠拿到 snapshot”。本轮已把该事实写回 README。

## 基线与保护现场

开发前后均未回滚用户或前序工作。当前工作区已有前序运行时、MISC、Wails 绑定和 UI 治理改动；本轮只追加桥接层、状态机、诊断、测试和文档修复。

`rg "tshark capability:" -n .` 只在 README 和 `scripts/start-wails-dev.ps1` 的诊断提示中命中，源码运行路径中不再包含旧日志文案。

## 根因结论

1. Wails 桥接层曾在 `getToolRuntimeSnapshot(signal)` 和 `updateToolRuntimeConfig(config, signal)` 收到 `AbortSignal` 时强制走 HTTP fallback。startup runtime check 正好传入 signal，因此 Wails 桌面环境会绕开 IPC，进入可能受 token、origin、端口复用影响的 HTTP 链路。
2. `createBridge()` 早期一次性读取 `window.go.main.DesktopApp`。React 模块初始化早于 Wails binding 注入时，会永久退化为 HTTP bridge。
3. 前端只有 `toolRuntimeSnapshot === null`，但 UI 把 null snapshot 渲染得像“所有工具缺失”，没有展示“等待探测 / 探测失败 / 探测链路 / 最近错误”。
4. dev 仍出现旧 `tshark capability:` 文案时，说明运行的后端不是当前源码构建产物，或旧进程仍占用端口。

## 修改文件

后端与桌面壳：

- `app.go`
- `desktop_backend_probe.go`
- `desktop_backend_proxy.go`
- `backend/internal/transport/http_server.go`
- `backend/internal/transport/http_server_test.go`
- `scripts/start-wails-dev.ps1`
- `README.md`

前端桥接与状态：

- `frontend/src/app/integrations/bridgeFactory.ts`
- `frontend/src/app/integrations/desktopBridge.ts`
- `frontend/src/app/integrations/httpBridge.ts`
- `frontend/src/app/state/toolRuntimeProbeState.ts`
- `frontend/src/app/state/toolRuntimeSnapshotMutations.ts`
- `frontend/src/app/state/hooks/backendLifecycleStartup.ts`
- `frontend/src/app/state/hooks/backendLifecycleStartupTypes.ts`
- `frontend/src/app/state/hooks/backendLifecycleToolRuntimeStartup.ts`
- `frontend/src/app/state/hooks/backendUnavailableStatus.ts`
- `frontend/src/app/state/hooks/useBackendLifecycle.ts`
- `frontend/src/app/state/hooks/useBackendLifecycleStartupEffect.ts`
- `frontend/src/app/state/hooks/useToolRuntime.ts`
- `frontend/src/app/state/SentinelContext.tsx`
- `frontend/src/app/state/sentinelTypes.ts`

前端 UI 与测试拆分：

- `frontend/src/app/App.tsx`
- `frontend/src/app/components/RuntimeSettingsHeader.tsx`
- `frontend/src/app/components/RuntimeSettingsShell.tsx`
- `frontend/src/app/components/RuntimeSettingsSidebar.tsx`
- `frontend/src/app/components/useRuntimeSettingsSidebarModel.ts`
- `frontend/src/app/components/RuntimeSettingsSectionShell.tsx`
- `frontend/src/app/components/RuntimeToolStatusLine.tsx`
- `frontend/src/app/components/runtimeTSharkStatus.ts`
- `frontend/src/app/components/RuntimeSettingsSpeechIssues.ts`
- `frontend/src/app/components/CaptureSettingsSection.tsx`
- `frontend/src/app/components/MediaSettingsSection.tsx`
- `frontend/src/app/components/YaraSettingsSection.tsx`
- `frontend/src/app/components/SpeechSettingsSection.tsx`
- `frontend/src/app/components/RuntimeSettingsSidebarParts.tsx`

测试：

- `frontend/src/app/integrations/desktopBridge.test.ts`
- `frontend/src/app/integrations/bridgeFactory.test.ts`
- `frontend/src/app/integrations/httpBridge.test.ts`
- `frontend/src/app/state/hooks/useBackendLifecycle.test.tsx`
- `frontend/src/app/App.test.tsx`
- `frontend/src/app/components/RuntimeSettingsShell.test.tsx`
- `frontend/src/app/components/RuntimeSettingsSidebarParts.test.tsx`
- `backend/internal/transport/http_server_test.go`

## 关键行为变化

- Wails 桌面环境下，只要 `DesktopApp.GetToolRuntimeSnapshot` 存在，runtime snapshot 始终走 Wails IPC；`AbortSignal` 只影响 HTTP fallback。
- Wails 桌面环境下，只要 `DesktopApp.UpdateToolRuntimeConfig` 存在，startup sync 和用户保存配置始终走 Wails IPC。
- Bridge factory 改为懒解析 Wails binding，避免 React 初始化时 binding 尚未注入导致永久 HTTP fallback。
- 新增 `ToolRuntimeProbeState = idle/probing/ready/failed`、`ToolRuntimeProbeTransport = desktop-ipc/http-fallback/unknown` 和 `lastToolRuntimeProbeError`。
- 后端 ready 后自动触发一次 runtime snapshot 探测；失败时进入 `failed`，但不把工具全部渲染为缺失。
- 设置侧栏固定显示“重新探测工具”，footer/header 展示最近一次探测链路和失败原因。
- TShark compat 被展示为“部分降级”，不禁用抓包。
- `/api/runtime/identity` 增加 `build_id`、`executable_path`、`working_dir`、`started_at`，用于定位旧二进制、旧进程和端口复用。
- 桌面启动后端时注入 `GSHARK_BACKEND_BUILD_ID`，并在 stdout 打印后端命令、工作目录和 build id。
- `start-wails-dev.ps1` 启动前输出端口探针摘要，启动时提示 IPC 优先和旧日志诊断。

## 验证命令与结果

通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec vitest run src/app/integrations/desktopBridge.test.ts src/app/integrations/bridgeFactory.test.ts src/app/state/hooks/useBackendLifecycle.test.tsx src/app/App.test.tsx src/app/components/RuntimeSettingsShell.test.tsx
```

结果：5 files / 29 tests 通过。

通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run typecheck
pnpm run lint
pnpm run ci
```

结果：前端 package-manager、typecheck、lint、format、size、boundary、client/mapper/wire any、Wails binding check、Vitest 和 Vite build 全部通过；Vitest 汇总为 215 files / 637 tests 通过。

通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\backend
gofmt -l .
go test ./...
```

结果：`gofmt -l .` 无输出；后端全部 package 测试通过。

通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run build:wails
```

结果：Vite build、后端二进制构建/复制和桌面资产检查通过，输出 `Desktop asset check: ok`。

通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1
go test -tags dev ./...
go test -tags production ./...
```

结果：桌面资产检查通过；root dev/production tag 测试均通过。

受控 smoke：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start-wails-dev.ps1 -CleanGoCache
```

结果摘要：

- 启动前 34115 和 17891 均为空闲。
- 脚本清理了 `frontend/dist/sentinel-backend.exe`、`build/bin/sentinel-backend.exe`，并执行 Go build cache 清理。
- Wails 生成 binding、编译前端和编译桌面应用均成功。
- 桌面壳启动后端：`C:\Users\QAQ\Desktop\gshark\build\bin\sentinel-backend.exe serve 127.0.0.1:17891`，build id 为 `sha256:47aea1dc79139e9f`。
- 后端监听 `127.0.0.1:17891`。
- 日志为 `tshark capability degraded: ... optional fields missing: usbms.scsi.opcode (tshark remains available)`，说明自动探测已发生且 TShark 可用但兼容降级。
- smoke 后已清理 34115/17891 监听进程；随后重新执行 `build:wails` 恢复桌面 dist 资产。

说明：两次 root tag 测试曾与 `build:wails` 并行执行，撞到 `frontend/dist` 清理/重建窗口并临时失败；`build:wails` 完成后串行复跑均通过。该失败是验证命令竞态，不是最终产物问题。

## Phase 评分

| Phase | 分值 | 得分 | 结论 |
|---|---:|---:|---|
| Phase 0：基线、文档与二进制溯源 | 8 | 8 | 完成 git/docs/旧日志/source provenance 审计。 |
| Phase 1：桥接层控制面收束 | 22 | 22 | Wails IPC 优先、signal 不再强制 HTTP、late binding 测试覆盖。 |
| Phase 2：探测状态机与 UI 语义修复 | 18 | 18 | idle/probing/ready/failed、transport、error、重探测按钮和 compat 降级 UI 完成。 |
| Phase 3：后端 identity、日志与缓存可观测性 | 14 | 14 | identity provenance、backend build id、dev script 探针和旧日志诊断完成。 |
| Phase 4：测试补齐与断点复现 | 18 | 18 | bridge、late binding、lifecycle、settings、identity、compat 相关测试覆盖。 |
| Phase 5：端到端验收与 dev smoke | 14 | 14 | 前端 CI、后端测试、root tag、build:wails、资产检查和 dev smoke 通过。 |
| Phase 6：文档、报告与治理 | 6 | 6 | README 与本报告完成。 |

基础分：100 / 100。

奖励分：

- 双通道诊断面板：+2。UI 展示 Wails IPC / HTTP fallback 和最近错误。
- 旧二进制自动识别：+2。后端 identity、desktop build id 和 dev script 诊断已落地。
- 用户可读错误文案：+1。HTTP 401/token、IPC/HTTP/timeout、旧缓存、compat 降级均有中文提示。

未计奖励：

- Wails 可视化截图：未执行截图，不加分。
- fake slow TShark：未新增慢探测模拟，不加分。

最终得分：105 / 110，Platinum。

## 自迭代记录

1. Probe：focused tests 锁定 `AbortSignal` 下仍应 IPC 优先、late binding、snapshot failure 状态。
2. Patch：修改 `desktopBridge` 和 `bridgeFactory`，增加 probe state 与 UI 诊断。
3. Focused Verify：5 个 focused test 文件、29 个测试通过。
4. Classify：发现前端 CI 卡在 size budget，归类为 UI 诊断拆分问题，不是业务回归。
5. Iterate：把 runtime settings header、section shell、status line、sidebar model、startup options 和 speech issues 拆出小文件，保持职责边界。
6. Regression Gate：前端 CI、后端全量、root dev/production、build:wails、资产检查全部通过。
7. Evidence Log：`start-wails-dev.ps1 -CleanGoCache` smoke 证明当前源码后端已启动，旧日志不存在，新日志明确 `tshark remains available`。

## 剩余风险

- 本轮未新增 fake slow TShark 测试；目前通过 bridge/lifecycle timeout 测试覆盖探测失败路径。
- 本轮未做真实截图；dev smoke 已证明 Wails 编译、后端启动和 TShark 自动探测发生。
- Vosk 中文模型目录仍可能缺失；这会让 `speech.available=false`，但 UI 会拆开显示 Python/Vosk/model 的真实子状态。
- `pnpm run ci` 最后会执行纯 Vite build，可能清掉桌面 dist 里的后端资产；交付前必须补跑 `pnpm run build:wails`，本轮已补跑并通过。

## 最终结论

本轮已把 Wails dev 到前端设置页的运行时工具探测链路收束为 IPC 优先、HTTP fallback 可诊断、snapshot 状态可见、后端二进制来源可追踪。后端已连接时不应再长期显示全量“未检测”且无原因；点击“重新探测工具”后，要么填充真实工具状态，要么显示具体 IPC/HTTP/timeout/token 失败原因。
