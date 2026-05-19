# 运行时工具读取失败修复报告

- 作者：Codex
- 时间：2026-05-16 00:33:42 +08:00（Asia/Shanghai）
- 工作区：`C:\Users\QAQ\Desktop\gshark`

## 本轮目标

修复“应用无法读取 tshark、ffmpeg、python 等工具”的持续性问题，并校准用户看到的运行时组件状态。

本轮结论：日志 `profile=compat ... missing optional fields: usbms.scsi.opcode` 不是 TShark 不可读。当前机器上 TShark、FFmpeg、Python 和 vosk Python 包均可被后端读取；Speech 不可用的直接原因是默认 Vosk 中文模型目录不存在。

## 读取与评审的 docs

- `docs/README.md`：确认本地开发报告归档目录只作为本机记录，当前版本化事实应沉淀到 README / 接口文档 / 治理登记表。
- `README.md`：已有运行时环境变量与 UI 显式配置说明，本轮补充旧空配置迁移、TShark compat 降级和 Speech 依赖拆分说明。
- `docs/misc-module-interface.md`：已明确 JavaScript MISC 运行在 Goja、无 `process.env`；Python MISC 继承后端进程环境。本轮未扩大 JS 环境变量读取面。
- 评审结论：最新 docs 方向正确；需要把本轮“旧全空 localStorage 不再覆盖 env”和“compat 不是 unavailable”落到 README，已完成。

## 根因结论

1. 持续性根因是旧前端可能已经写入全空 `gshark.tool-runtime.v1`。之前读取逻辑只要看到该 key 就当作用户显式保存配置，启动同步会 POST 全空配置到后端，触发 `GSHARK_FFMPEG`、`GSHARK_PYTHON`、`GSHARK_VOSK_MODEL` 被 unset。
2. UI 在 `toolRuntimeSnapshot=null` 时把所有工具都按 `available=false` 渲染为“缺失”，会把“后端未连接/未拿到 snapshot”误报成“tshark、ffmpeg、python 都不可读”。
3. TShark 4.6.5 缺少 `usbms.scsi.opcode` 属于 optional field 降级，后端仍返回 `tshark.available=true`，抓包入口不应因此禁用。
4. FFmpeg 真实安装在 WinGet Gyan 包目录；旧 resolver 只查 PATH 和显式路径，GUI PATH 缺失时可能误报。
5. Python 不能固定写死某个用户目录；但若优先选择 `py -3` 且该解释器没有 vosk，会误把 Speech 依赖降级。本轮改为无显式 `GSHARK_PYTHON` 时优先选择“可启动且能导入 vosk”的候选，若都不能导入 vosk 再退回第一个可启动 Python。

## 本轮主要修改

- 前端 storage 迁移：
  - `frontend/src/app/state/toolRuntimeStorageConfig.ts`
  - `frontend/src/app/state/toolRuntimeStorage.ts`
  - `frontend/src/app/state/toolRuntimeStorage.test.ts`
- 启动同步修复：
  - `frontend/src/app/state/hooks/backendLifecycleStartup.ts`
  - `frontend/src/app/state/hooks/backendLifecycleToolRuntimeStartup.ts`
  - `frontend/src/app/state/hooks/useBackendLifecycle.test.tsx`
  - `frontend/src/app/state/hooks/useToolRuntime.ts`
- UI 状态校准：
  - `frontend/src/app/components/RuntimeSettingsSidebarParts.tsx`
  - `frontend/src/app/components/RuntimeSettingsShell.tsx`
  - `frontend/src/app/components/CaptureSettingsSection.tsx`
  - `frontend/src/app/components/MediaSettingsSection.tsx`
  - `frontend/src/app/components/SpeechSettingsSection.tsx`
  - `frontend/src/app/components/YaraSettingsSection.tsx`
  - `frontend/src/app/components/RuntimeDependencyCard.tsx`
  - `frontend/src/app/components/TSharkCapabilityDetails.tsx`
- 后端 resolver 增强：
  - `backend/internal/engine/media_playback.go`
  - `backend/internal/engine/media_playback_test.go`
  - `backend/internal/engine/speech_to_text.go`
  - `backend/internal/engine/speech_to_text_test.go`
- 文档：
  - `README.md`

## 行为变化

- localStorage 缺失：启动只读取后端 snapshot，并写入 observed v2 record，不 POST 空配置。
- 旧 v1 全空配置：迁移为 `observed-backend-snapshot`，不再清空后端 env。
- 旧 v1 只有 `tsharkPath`：只把 TShark 显式路径合并到后端 snapshot，保留 FFmpeg/Python/Vosk/YARA env 值。
- v2 用户保存配置：只有 `explicitFields=true` 的字段可覆盖后端 snapshot。用户显式保存空 FFmpeg/Python/Vosk 仍允许清空对应 env。
- UI 状态三态化：未知状态显示“未检测”，不再显示“缺失”。
- TShark compat：显示“部分分析降级字段”，不影响 `tshark.available` 和抓包入口。
- FFmpeg resolver：补 WinGet Links、WinGet Gyan 包、`C:\ffmpeg\bin`、`C:\Program Files\ffmpeg\bin`。
- Python resolver：去掉写死 `C:\Users\QAQ\...Python311` 优先逻辑；候选为 env、`py -3`、`python`、`python3`、LocalAppData Python、`C:\Python3*`，并优先选择可导入 vosk 的候选。

## 验证结果

- `cd frontend && pnpm exec vitest run src/app/state/toolRuntimeStorage.test.ts src/app/state/hooks/useBackendLifecycle.test.tsx src/app/components/RuntimeSettingsSidebarParts.test.tsx src/app/components/RuntimeSettingsSections.test.tsx src/app/components/TSharkCapabilityDetails.test.tsx`：通过，30 tests。
- `cd frontend && pnpm run typecheck`：通过。
- `cd frontend && pnpm run size:check`：通过。
- `cd frontend && pnpm run lint`：通过。
- `cd frontend && pnpm run ci`：通过，214 files / 627 tests。
- `cd backend && go test ./internal/engine -run "TestResolveSpeechPythonCommand|TestResolveSpeechToTextStatus|TestResolveFFmpeg" -count=1`：通过。
- `cd backend && go test ./...`：通过。
- `cd backend && gofmt -l .`：无输出。
- `go test -tags dev ./...`：通过。
- `go test -tags production ./...`：通过。
- `cd frontend && pnpm run build:wails`：通过，并输出 `Desktop asset check: ok`。
- `powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1`：通过。

一次资产检查曾与 `build:wails` 并行运行，先于构建完成看到了纯 Vite dist 并失败；随后在 `build:wails` 完成后单独复查通过。该失败是验证命令竞态，不是最终产物问题。

## 真实 runtime snapshot 探针

使用 `frontend/dist/sentinel-backend.exe serve 127.0.0.1:17992` 临时启动后端并查询 `/api/tools/runtime-config`，结果摘要：

```json
{
  "tshark_available": true,
  "tshark_path": "C:\\Program Files\\Wireshark\\tshark.exe",
  "tshark_profile": "compat",
  "tshark_missing_optional": "usbms.scsi.opcode",
  "ffmpeg_available": true,
  "ffmpeg_path": "C:\\Users\\QAQ\\AppData\\Local\\Microsoft\\WinGet\\Packages\\Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe\\ffmpeg-8.0.1-full_build\\bin\\ffmpeg.exe",
  "python_available": true,
  "python_command": "python",
  "vosk_available": true,
  "model_available": false,
  "speech_available": false,
  "speech_message": "未检测到 Vosk 中文模型，请在设置中配置模型目录或放置到默认模型目录。"
}
```

专项结论：

- TShark 可读；`compat` 只代表缺少 optional field。
- FFmpeg 可读；后端通过 WinGet 包路径找到。
- Python 可读；最终选择可导入 vosk 的 `python`。
- vosk Python 包可读。
- Speech 不可用的当前阻塞项是 Vosk 模型目录缺失。

## 工作区备注

实施前工作区已有大量前序改动，包括桌面资源、Wails 绑定、MISC 目录清理、http tools 拆分、frontend UI/CI 改动等。本轮未回滚这些改动，只在运行时工具读取、resolver、状态展示和 README 上追加修复。

## 剩余风险

- 本轮没有下载或安装 Vosk 中文模型；如需让 `speech.available=true`，仍需配置 `GSHARK_VOSK_MODEL` 或在默认目录放置模型。
- 未运行真实 Wails 窗口可视化冒烟；但后端真实 snapshot、前端 CI、root tag tests、`build:wails` 和桌面资产检查均已通过。
- 若用户显式设置 `GSHARK_PYTHON` 指向一个没有 vosk 的解释器，系统会尊重该显式配置并提示 vosk 模块缺失。

## 最终结论

本轮修复了旧全空 localStorage 配置继续清空后端 env 的问题，修正了 UI 将 unknown 误报为 missing 的问题，并增强了 FFmpeg/Python 自动探测。当前“无法读取 tshark、ffmpeg、python”的表象不再成立；真实剩余阻塞是 Vosk 中文模型目录缺失。
