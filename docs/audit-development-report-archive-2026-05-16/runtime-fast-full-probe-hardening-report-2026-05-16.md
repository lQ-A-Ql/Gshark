# 运行时工具探测 fast/full 拆分加固报告

- 作者：Codex
- 时间：2026-05-16 17:41:09 +08:00（Asia/Shanghai）
- 工作区：`C:\Users\QAQ\Desktop\gshark`

## 本轮目标

用户反馈“又无法探测环境工具”，并要求按《运行时工具探测链路全量审计与修补 Spec》实施。目标是把启动和设置页的运行时组件探测从“同步聚合慢快照”改成“快速状态先返回，完整能力后台补齐”，避免 TShark `-G fields`、Python `import vosk`、YARA 规则检查等慢操作超过 3500ms 后把 TShark、FFmpeg、Python/Vosk 统统显示成不可探测。

本轮同时延续前序未提交的首屏 active load、Wails page/status IPC、runtime IPC fallback 等改动，不回滚已有链路修复。

## 读取与评审的 docs

- `README.md`：已有 Wails dev、runtime probe、首屏 active load 的说明。本轮补充了 `probe=fast/full`、后台完整能力探测、Wails IPC fast timeout 后 HTTP fallback、组件耗时与失败原因展示。
- `docs/README.md`：确认逐轮开发报告归档在 `docs/audit-development-report-archive-*`，当前事实应沉淀到 README 或接口文档。本轮按要求追加本报告。
- `docs/audit-development-report-archive-2026-05-16/runtime-probe-fallback-hardening-report-2026-05-16.md`：前序结论已修复 IPC 调用失败 fallback，但仍保留单次同步聚合快照模型。本轮在该基础上拆分 fast/full。
- `docs/audit-development-report-archive-2026-05-16/capture-first-screen-load-chain-hardening-report-2026-05-16.md`：确认首屏数据链路修复与 runtime tool probe 是相邻但不同链路；本轮未将首屏解析状态误归因为工具不可读。

评审结论：前序文档方向准确，但 runtime 探测链路还缺少“慢能力后台化”和“Wails IPC timeout 后继续保留 fast 状态”的机制；这正是本轮补齐点。

## 根因结论

本轮真实根因不是本机缺少工具，也不是 TShark optional field 缺失：

- `STARTUP_TOOL_RUNTIME_TIMEOUT_MS = 3500` 被用于启动和手动刷新。
- 后端旧 `ToolRuntimeSnapshot()` 是单次同步聚合：TShark、FFmpeg、Speech/Python/Vosk、YARA 一起探测。
- TShark full capability 会跑 `tshark -G fields`；Speech 会探测 Python 并执行 `import vosk`；这些操作叠加后容易超过 3500ms。
- Wails IPC 调用无法被前端 `AbortSignal` 真正取消；前端先标记 failed/timeout，后端慢探测仍在跑。
- Vosk 默认模型目录缺失只应让 `speech.modelAvailable=false`，不应被显示成 Python、FFmpeg 或 TShark 不可读。

因此修补策略是：启动和设置页先请求 fast snapshot，快速显示路径、解释器、模型目录和基础可用性；full probe 后台补齐 TShark 字段能力、Python `vosk` 包、YARA rules 等慢诊断。

## 修改摘要

### 后端

- `backend/internal/model/types.go`
  - `ToolRuntimeSnapshot` 增加可选诊断字段：`probe_mode`、`probe_state`、`probe_timings`、`probe_errors`、`cached`、`updated_at`。
  - 增加 `ToolRuntimeProbeOptions`。
- `backend/internal/engine/tool_runtime.go`
  - 新增 `ToolRuntimeSnapshotWithOptions(ctx, opts)`。
  - 支持 `fast` / `full` 两种 probe mode。
  - fast 模式跳过 TShark capability heavy scan 和 Python `import vosk`。
  - full 模式保留旧完整能力探测语义，并用 mutex 避免多个 full probe 并发堆叠。
  - snapshot 记录组件耗时和错误。
- `backend/internal/tshark/config.go`
  - 新增 `CurrentStatusWithOptions(ctx, StatusOptions{ProbeCapabilities})`。
  - fast 模式只确认 TShark 路径与可启动性，不跑 `-G fields`。
  - optional fields 缺失继续标记 degraded，不覆盖 `available=true`。
- `backend/internal/engine/speech_to_text.go`
  - 新增 `SpeechToTextStatusWithContext(ctx, SpeechStatusOptions)`。
  - Python resolver 支持 context cancel。
  - Python 解释器与 `import vosk` 结果增加 TTL cache。
  - fast 模式只确认 Python 可启动和模型目录，不强制 import vosk。
  - runtime snapshot 内复用 FFmpeg 状态，避免 Speech 二次探测 FFmpeg。
- `backend/internal/transport/http_server.go`
  - `/api/tools/runtime-config` 增加兼容 query：`?probe=fast|full`。
  - 默认仍为 full，保持旧调用语义；前端启动和手动刷新显式使用 fast。
- `desktop_backend_proxy.go`
  - 新增 Wails 方法：`GetToolRuntimeSnapshotFast`、`GetToolRuntimeSnapshotFull`、`UpdateToolRuntimeConfigFast`、`UpdateToolRuntimeConfigFull`。
  - 旧方法保留并委托 full，避免破坏旧 binding。

### 前端

- `frontend/src/app/integrations/clients/toolRuntimeClient.ts`
  - `getToolRuntimeSnapshot(signal, mode)` 与 `updateToolRuntimeConfig(config, signal, mode)` 支持 fast/full query。
- `frontend/src/app/integrations/desktopBridge.ts`
  - Wails 桌面环境按 mode 调用 fast/full IPC。
  - fast IPC 使用 2s 预算；超时或失败后尝试 HTTP fast fallback，并保留 IPC 原始错误。
- `frontend/src/app/core/types/tools.ts`、`runtimeWireDtos.ts`、`runtimeMapper.ts`
  - 补齐 probe diagnostics 的 TS 类型和 wire mapper。
- `frontend/src/app/state/hooks/backendLifecycleStartup.ts`
  - startup 首次请求 fast snapshot。
  - fast 成功后写 observed config，不再等待 full probe 进入主界面。
  - 后台触发 full probe，失败时进入 `timeout_background` 而不是清空快照。
- `frontend/src/app/state/hooks/useToolRuntime.ts`
  - 手动“重新探测工具”和“保存并应用”先执行 fast，立即刷新 UI，再后台 full。
  - full 超时保留 fast snapshot，不再把已有工具状态抹成 failed。
- `frontend/src/app/state/toolRuntimeProbeState.ts`
  - 状态扩展为 `probing_fast`、`partial`、`probing_full`、`timeout_background` 等。
- `RuntimeSettingsShell` / `RuntimeSettingsHeader` / `RuntimeSettingsSidebar`
  - UI 显示快速/完整探测状态、transport、组件耗时、错误和后台探测提示。
- `frontend/wailsjs/go/main/DesktopApp.d.ts`、`DesktopApp.js`、`frontend/scripts/check-wails-bindings.mjs`
  - 同步新增 Wails runtime fast/full 方法，并让 binding checker 读取拆分后的 `desktopTransportBinding.ts`。
- 为 size budget 拆分出：
  - `desktopTransportBinding.ts`
  - `runtimeComponentMapper.ts`
  - `runtimeDiagnosticsMapper.ts`
  - `toolRuntimeBackgroundProbe.ts`
  - `toolRuntimeOfflineApply.ts`
  - `runtimeProbeDiagnosticsText.ts`

### 文档

- `README.md`：追加 fast/full runtime probe、Wails IPC fast fallback、首屏 active load 与 page/status transport 说明。

## 测试与验证

### Backend

```powershell
cd C:\Users\QAQ\Desktop\gshark\backend
gofmt -l .
go test ./...
```

结果：

- `gofmt -l .` 无输出。
- `go test ./...` 通过全部 backend 包。

### Frontend focused / CI

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec tsc --noEmit --pretty false
pnpm run wails-binding:check
pnpm run lint
pnpm run size:check
pnpm run ci
```

结果：

- TypeScript 通过。
- Wails binding check 通过。
- ESLint 通过。
- Size budget 通过。
- `pnpm run ci` 通过：217 个测试文件 / 655 个测试通过，Vite build 通过。

### Desktop assets / root tests

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run build:wails

cd C:\Users\QAQ\Desktop\gshark
go test -tags dev ./...
go test -tags production ./...
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1
git diff --check
```

结果：

- `pnpm run build:wails` 通过，输出 `Desktop asset check: ok`。
- `go test -tags dev ./...` 通过。
- `go test -tags production ./...` 通过。
- `check-desktop-assets.ps1` 通过。
- `git diff --check` 无输出。

### Wails dev smoke

```powershell
cd C:\Users\QAQ\Desktop\gshark
powershell -ExecutionPolicy Bypass -File .\scripts\start-wails-dev.ps1 -CleanGoCache
```

受控 smoke 运行到以下关键点后清理进程：

- `wails dev` 可用，Wails CLI v2.11.0。
- `Generating bindings`、`Installing frontend dependencies`、`Compiling frontend`、`Generating application assets`、`Compiling application` 均完成。
- WebView2 环境创建成功。
- 桌面壳使用 `build\bin\sentinel-backend.exe`，输出 build id：`sha256:fd4d9d22ffe179b5`。
- 后端监听：`127.0.0.1:17891`。
- TShark 输出为新语义：`tshark capability degraded ... optional fields missing: usbms.scsi.opcode (tshark remains available)`。

注意：`start-wails-dev.ps1 -CleanGoCache` 会删除 `frontend/dist/sentinel-backend.exe` 和 `build/bin/sentinel-backend.exe` 后再启动 dev。Smoke 后已再次补跑 `pnpm run build:wails`，最终桌面资产恢复为可用状态。

## 当前机器预期状态

- TShark：可用。`usbms.scsi.opcode` 是 optional field 缺失，只代表部分 USB Mass Storage 专项字段降级。
- FFmpeg：应通过 fast snapshot 快速显示基础状态。
- Python：应通过 fast snapshot 快速显示解释器基础状态。
- Speech：如果默认目录 `C:\Users\QAQ\AppData\Local\gshark-sentinel\models\vosk\zh-CN` 仍不存在，应显示 Vosk 模型目录缺失，而不是 Python 或 FFmpeg 不可读。
- Full probe：可能继续在后台补齐 `tshark -G fields`、Python `import vosk` 与 YARA rules 结果；超时不再清空 fast 状态。

## 评分

基础分：96 / 100。

| Phase | 得分 | 说明 |
|---|---:|---|
| Phase 0：基线与复现 | 8 / 8 | 记录 git status、读取 docs、确认 3500ms timeout 与慢聚合根因 |
| Phase 1：后端探测契约拆分 | 23 / 24 | fast/full 已实现，旧默认 full 兼容；full singleflight 用 mutex 串行化 |
| Phase 2：上下文、缓存与去重 | 17 / 18 | Python/Vosk context 与 TTL cache 已加；FFmpeg 复用已做；YARA 仍保持较轻路径检查 |
| Phase 3：Wails/HTTP 桥接修复 | 16 / 16 | Wails fast/full 方法、IPC fast timeout、HTTP fast fallback、binding check 全部完成 |
| Phase 4：前端状态与诊断 UI | 14 / 14 | partial、probing_full、timeout_background、耗时/错误/transport UI 完成 |
| Phase 5：测试与 smoke | 13 / 14 | 前端 CI、后端/root/build:wails/asset check 通过；Wails smoke 跑到后端监听与 TShark degraded 新语义 |
| Phase 6：文档与报告 | 5 / 6 | README 与本报告完成；未做真实截图 |

奖励分：+7 / 10。

- +2：组件耗时/错误诊断进入 snapshot 和 UI。
- +2：fake slow TShark / context cancel 相关 backend focused tests 覆盖。
- +2：真实 Wails dev smoke 记录 build id、后端监听和 TShark degraded 新语义。
- +1：中文错误文案区分后台 full timeout、模型目录缺失、transport fallback。

最终分：103 / 110，Platinum。

## 剩余风险

- 本轮没有用真实截图证明设置页视觉状态；只做了受控 Wails dev smoke 和自动化测试。
- `start-wails-dev.ps1 -CleanGoCache` 构建时间较长，受控 smoke 未长期停留观察完整 full probe 收敛。
- 如果用户本机 localStorage 已保存了显式空字段，fast/full 拆分不会自动替用户恢复这些字段；需要用户重新保存路径或重置配置。
- Vosk 模型缺失仍会让 `speech.available=false`，但现在应清楚展示为模型目录缺失，而不是 Python/FFmpeg/TShark 不可读。

## 最终结论

本轮修复已把运行时组件探测链路从“启动时同步 full 聚合快照”改为“fast snapshot 先可用，full probe 后台补齐”。这切断了 3500ms 启动预算与 TShark/Python/YARA 慢能力探测之间的硬耦合。Wails 桌面环境下 fast IPC 超时会 HTTP fallback；full 超时只进入后台状态，不再清空已有工具状态。`usbms.scsi.opcode` 仍只表示 TShark 专项能力降级，TShark 本体保持可用。
