# Wails Dev 运行时工具探测复核报告

- 作者：Codex
- 时间：2026-05-16 01:09:59 +08:00（Asia/Shanghai）
- 工作区：`C:\Users\QAQ\Desktop\gshark`

## 本轮目标

复核 `scripts/start-wails-dev.ps1` 启动 dev 后仍看到 `tshark capability ... missing optional fields: usbms.scsi.opcode` 的现象，并修复“缺少工具探测按钮 / 似乎不会自主探测 / 测试文件缺口”的可见问题。

## 读取与评审的 docs

- `README.md`：已包含运行时环境变量、TShark compat 和 `build:wails` 说明；本轮补充 Wails dev 缓存清理、重新探测工具入口和新日志语义。
- `docs/README.md`：确认当前事实应沉淀到版本化 README / 接口文档 / 治理登记表；本地 archive 只作为逐轮记录。
- `docs/audit-development-report-archive-2026-05-15/runtime-tool-detection-migration-report-2026-05-15.md`：前轮关于旧 localStorage 空配置、TShark compat、FFmpeg/Python resolver 的判断仍然成立。

评审结论：最新文档方向正确；本轮新增的 Wails dev 缓存清理和手动探测入口已补入 README。

## 根因与专项结论

1. 用户看到的 `usbms.scsi.opcode` 不是 TShark 不可读；它是 TShark 4.6.5 缺少可选字段导致的兼容降级。后端仍应返回 `tshark.available=true`。
2. 旧启动页只展示 TShark 单项状态，缺少明显的全量工具探测入口；设置侧栏按钮文案为“刷新状态”，不够明确。
3. 启动同步和手动刷新时，前端把 `ToolRuntimeSnapshot.tshark` 转成 `tsharkStatus` 时丢弃了 `fieldProfile/missingOptionalFields/capabilityCheckDegraded`，导致 UI 无法解释 compat 降级。
4. `start-wails-dev.ps1` 仍未处理 Wails dev 后端二进制缓存；如果 `frontend/dist/sentinel-backend.exe`、`build/bin/sentinel-backend.exe` 或 `%TEMP%\gshark-sentinel\backend` 里有旧产物，dev 可能复用旧后端。
5. 测试文件并非整体缺失；`App.test.tsx` 和运行时 storage/lifecycle/component tests 均存在。本轮补的是启动页“重新探测工具”和 TShark compat 元数据保留的测试覆盖。

## 修改文件

- `scripts/start-wails-dev.ps1`
- `scripts/start-dev.ps1`
- `frontend/src/app/App.tsx`
- `frontend/src/app/App.test.tsx`
- `frontend/src/app/components/RuntimeSettingsShell.tsx`
- `frontend/src/app/state/tsharkStatusState.ts`
- `frontend/src/app/state/hooks/backendLifecycleToolRuntimeStartup.ts`
- `frontend/src/app/state/hooks/useToolRuntime.ts`
- `frontend/src/app/state/hooks/useBackendLifecycle.test.tsx`
- `backend/internal/tshark/capabilities.go`
- `README.md`
- `docs/audit-development-report-archive-2026-05-16/wails-dev-runtime-probe-report-2026-05-16.md`

## 行为变化

- `start-wails-dev.ps1` 默认清理：
  - `frontend/dist/sentinel-backend.exe`
  - `build/bin/sentinel-backend.exe`
  - `%TEMP%\gshark-sentinel\backend`
- `start-wails-dev.ps1` 新增 `-NoClean` 和 `-CleanGoCache`。
- `start-dev.ps1` 透传 `-NoClean` / `-CleanGoCache`。
- 启动页新增“重新探测工具”按钮，调用 `refreshToolRuntimeSnapshot()`。
- 启动页展示 FFmpeg 和 Speech 的基础探测状态。
- 设置侧栏按钮文案从“刷新状态”改为“重新探测工具”。
- TShark compat 降级在启动页显示为“可用，部分分析降级”，并显示缺少的可选字段。
- 前端 `tsharkStatus` 同步保留 capability 元数据，不再只保留 path/message。
- 后端日志从：
  - `tshark capability: ... missing optional fields ...`
  改为：
  - `tshark capability degraded: ... optional fields missing ... (tshark remains available)`

## 验证命令与结果

- `cd frontend && pnpm exec vitest run src/app/App.test.tsx src/app/state/hooks/useBackendLifecycle.test.tsx src/app/state/toolRuntimeStorage.test.ts src/app/components/RuntimeSettingsSidebarParts.test.tsx src/app/components/RuntimeSettingsSections.test.tsx src/app/components/TSharkCapabilityDetails.test.tsx`：通过，6 files / 34 tests。
- `cd backend && go test ./internal/tshark ./internal/engine ./internal/transport`：通过。
- `cd frontend && pnpm run typecheck`：通过。
- `cd frontend && pnpm run lint`：通过。
- `powershell` scriptblock syntax check for `scripts/start-wails-dev.ps1` and `scripts/start-dev.ps1`：通过。
- `cd backend && gofmt -l .`：无输出。
- `cd backend && go test ./...`：通过。
- `go test -tags dev ./...`：通过。
- `go test -tags production ./...`：通过。
- `cd frontend && pnpm run ci`：通过，214 files / 630 tests。
- `cd frontend && pnpm run build:wails`：通过，并输出 `Desktop asset check: ok`。
- `powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1`：通过。
- `powershell -ExecutionPolicy Bypass -File .\scripts\start-wails-dev.ps1`：通过；34115 和 17891 均进入 listen，随后已主动停止进程。

说明：一次 `check-desktop-assets.ps1` 与 `build:wails` 并行执行时先于资源复制完成而失败；`build:wails` 完成后单独复查通过。最终有效结果为通过。

## Wails dev 冒烟摘要

`start-wails-dev.ps1` 实际启动日志确认：

- Wails 生成绑定成功。
- 前端依赖安装步骤成功。
- 前端编译成功。
- dev application 编译成功。
- 桌面壳使用 `C:\Users\QAQ\Desktop\gshark\build\bin\sentinel-backend.exe` 启动后端。
- 后端监听 `127.0.0.1:17891`。
- Wails dev server 监听 `http://localhost:34115`。
- 前端/后端启动后触发了 TShark 能力探测，日志为：
  - `tshark capability degraded: ... optional fields missing: usbms.scsi.opcode (tshark remains available)`

该日志说明“自动探测已经发生”，且 TShark 处于可用但可选字段降级状态。

## 剩余风险

- 本轮没有安装 Vosk 中文模型；如果 Speech 仍显示不可用，优先检查模型目录，而不是 Python 本身。
- `start-wails-dev.ps1` 默认不执行 `go clean -cache`，避免每次 dev 启动过慢；怀疑 Go 缓存时使用 `-CleanGoCache`。
- `compat` 日志仍会保留一次，但文案已明确 `tshark remains available`，并且 UI 会显示“部分分析降级”。

## 最终结论

本轮确认 `usbms.scsi.opcode` 是 optional field 降级而非 TShark 不可读；修复了 Wails dev 旧后端缓存、启动页缺少手动探测入口、TShark capability 元数据丢失和测试覆盖不足的问题。`start-wails-dev.ps1` 已通过实际 dev 启动验证。
