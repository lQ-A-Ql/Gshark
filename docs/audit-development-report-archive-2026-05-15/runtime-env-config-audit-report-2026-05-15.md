# 运行时环境变量配置读取修复报告（2026-05-15）

署名：Codex  
时间戳：2026-05-15 23:20:01 +08:00（Asia/Shanghai）

## 本轮目标

修复运行时组件无法稳定读取环境变量的问题，重点保护后端启动时已经读取到的 `GSHARK_FFMPEG`、`GSHARK_PYTHON`、`GSHARK_VOSK_MODEL`。本轮同时校准运行时设置 UI 对“显式配置路径”和“自动探测路径”的展示语义，并补充 MISC JavaScript / Python 模块读取环境变量的边界说明。

## 开发前文档评审

本轮开始前重读并评审了以下文档：

- `README.md`
- `docs/README.md`
- `docs/misc-module-interface.md`
- `docs/audit-development-report-archive-2026-05-15/backend-bridge-runtime-audit-report-2026-05-15.md`
- `docs/frontend-engineering-audit-spec-2026-05-15.md`
- `docs/governance-defect-register.json`

评审结论：

- 最新后端/桥接可靠性报告对 TShark gate、Wails binding、桌面资源、MISC cwd 污染的判断仍然准确，且不应把 `corepack` 缺失当作项目根因。
- 运行时配置文档此前没有充分说明 `GSHARK_FFMPEG`、`GSHARK_PYTHON`、`GSHARK_VOSK_MODEL` 与 UI 输入框的关系，容易让用户误以为输入框为空等于组件不可用。
- MISC 接口文档此前没有明确 JavaScript 模块是 Goja 运行时，不具备 Node.js `process.env`，也没有说明 Python 模块继承后端进程环境变量的边界。
- 本轮修复应在前端 startup 语义上止血，而不是改变后端 `SetToolRuntimeConfig()` 的已有约定；空字符串会清空显式环境配置这一行为需要被测试记录下来。

## 基线与现场保护

开发前 `git status --short` 已确认工作区存在大量前序改动，包括：

- 上轮桌面可靠性治理相关改动：`app.go`、`main.go`、`frontend/wailsjs/go/main/DesktopApp.*`、`scripts/check-desktop-assets.ps1`、`scripts/check-all.ps1`、`scripts/build-release-package.ps1` 等。
- MISC cwd 污染清理：`backend/internal/transport/plugins/misc/echo-demo-*` 已跟踪测试产物处于删除状态。
- 前端 UI / 类型治理相关改动：全局 select、USB/Object/MISC 若干组件与测试文件。

本轮没有回滚这些前序改动，只在运行时环境变量读取链路和相关文档/测试上追加修复。

## 根因结论

真实根因是前端启动同步语义错误：

1. 后端 `ToolRuntimeConfig()` 会从当前后端进程环境中读取 `GSHARK_FFMPEG`、`GSHARK_PYTHON`、`GSHARK_VOSK_MODEL`。
2. 后端 `SetToolRuntimeConfig()` 遇到空字符串会通过 `os.Unsetenv()` 清空对应环境变量，这是既有显式配置语义。
3. 修复前，前端 `readToolRuntimeConfig()` 在 `localStorage` 缺失时返回一份空默认配置。
4. startup 逻辑把这份“缺失时合成的空配置”当成“用户保存过的完整配置”同步回 `/api/tools/runtime-config`。
5. 结果是后端启动时已经读取到的 env 值，在前端启动阶段被空 POST 覆盖并清空。

因此主因是 startup 空 localStorage 配置覆盖了后端 env snapshot，不是 pnpm/corepack，不是 Wails binding 缺失，也不是 HTTP/Wails runtime-config API 不可达。

## 修改文件

前端运行时配置语义：

- `frontend/src/app/state/toolRuntimeStorage.ts`
- `frontend/src/app/state/toolRuntimeStorageConfig.ts`
- `frontend/src/app/state/toolRuntimeStorage.test.ts`
- `frontend/src/app/state/hooks/backendLifecycleStartup.ts`
- `frontend/src/app/state/hooks/backendLifecycleToolRuntimeStartup.ts`
- `frontend/src/app/state/hooks/useBackendLifecycle.test.tsx`

前端 mapper/client 与 UI：

- `frontend/src/app/integrations/mappers/runtimeMapper.test.ts`
- `frontend/src/app/integrations/clients/toolRuntimeClient.test.ts`
- `frontend/src/app/components/RuntimeSettingsHints.ts`
- `frontend/src/app/components/RuntimeSettingsHints.test.ts`
- `frontend/src/app/components/RuntimeDependencyCard.tsx`
- `frontend/src/app/components/CaptureSettingsSection.tsx`
- `frontend/src/app/components/MediaSettingsSection.tsx`
- `frontend/src/app/components/SpeechSettingsSection.tsx`
- `frontend/src/app/components/YaraSettingsSection.tsx`
- `frontend/src/app/components/RuntimeSettingsShell.tsx`
- `frontend/src/app/components/RuntimeSettingsSidebarParts.tsx`
- `frontend/src/app/components/RuntimeSettingsSidebarParts.test.tsx`
- `frontend/src/app/components/RuntimeSettingsSections.test.tsx`

后端测试与 API contract：

- `backend/internal/engine/tool_runtime_test.go`
- `backend/internal/transport/http_contract_test.go`

文档：

- `README.md`
- `docs/misc-module-interface.md`
- `docs/audit-development-report-archive-2026-05-15/runtime-env-config-audit-report-2026-05-15.md`

## 关键实现

### Phase 1：前端配置来源语义

新增 `readToolRuntimeConfigState()`，返回：

- `missing`：没有完整运行时配置，也没有 legacy tshark path。
- `legacy-tshark-only`：只有旧版 `gshark.tshark-path.v1`。
- `stored-runtime-config`：存在完整 `gshark.tool-runtime.v1`。

兼容行为保留：`readToolRuntimeConfig()` 仍返回 `ToolRuntimeConfig`，避免大范围重写既有调用。

startup 同步改为：

- `missing`：信任后端 `getToolRuntimeSnapshot()`，不 POST 空配置；把后端 snapshot.config 写回 localStorage。
- `legacy-tshark-only`：只把 legacy tshark path 合并进后端 snapshot.config，其余 `ffmpegPath`、`pythonPath`、`voskModelPath`、YARA 配置保留后端值。
- `stored-runtime-config`：用户显式保存过的完整配置继续优先。

同步失败时只进入 degraded 状态，不清空本地已保存配置，也不覆盖当前 UI snapshot。

### Phase 2：后端语义加固

新增后端测试记录既有 contract：

- `ToolRuntimeConfig()` 能从 env 读取并 trim `GSHARK_FFMPEG`、`GSHARK_PYTHON`、`GSHARK_VOSK_MODEL`。
- `SetToolRuntimeConfig()` 收到空值会 unset 对应 env。
- 非空配置能 round-trip 回 env。
- `/api/tools/runtime-config` GET 能暴露 env-backed config，POST 空值会按 contract 传给 service。

本轮没有改变后端 env 优先级，也没有把 PATH/default 探测结果写进显式配置字段。

### Phase 3：UI 展示校准

运行时设置侧栏现在明确区分：

- 输入框：用户显式配置路径。
- 状态卡：后端实际探测路径，来源可能是 env、PATH 或默认目录。

FFmpeg、Python、Vosk、TShark、YARA 的 hint 均说明“留空不等于不可用”。保存动作仍只提交当前表单值，不会自动把 `status.path` 固化进 config。

### Phase 4：MISC 环境变量边界

`docs/misc-module-interface.md` 已明确：

- JavaScript 自定义模块运行在 Goja VM，不是 Node.js，没有 `process.env`。
- 本轮不向 JavaScript 模块暴露完整系统环境变量，避免扩大 token、代理、路径等敏感信息读取面。
- 如后续确需开放，应设计为 `ctx.env(name)` 这类受限宿主 API，并默认只允许 `GSHARK_MISC_` 前缀或 manifest 白名单。
- Python 模块作为独立本地进程运行，继承后端进程 `os.Environ()`；`host_bridge: true` 会额外注入 `GSHARK_MISC_INPUT_JSON`、`PYTHONIOENCODING=utf-8` 和 helper `PYTHONPATH`。

## 验证命令与结果

通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run ci
```

结果：package-manager、typecheck、lint、format、size、boundary、client/mapper/wire any、Wails binding check、Vitest 和 Vite build 全部通过。Vitest 结果为 `214` 个 test files、`622` 个 tests 通过。

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
cd C:\Users\QAQ\Desktop\gshark\backend
gofmt -l .
```

结果：无输出。

通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\backend
go test ./...
```

结果：后端全部 package 测试通过。

通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark
go test -tags dev ./...
go test -tags production ./...
```

结果：root dev/production tag 测试均通过，嵌入桌面资源测试通过。

工作区污染检查：

- 测试后 `backend/internal/transport/plugins/misc` 目录不存在。
- 未观察到新的 MISC 测试模块写回源码树。
- 当前 `git status` 中该目录下的删除项属于前序清理已跟踪污染文件，不是本轮测试新增污染。

## Phase / Task 验收

| Phase | 状态 | 验收结论 |
|---|---|---|
| Phase 0：基线确认与复现保护 | 完成 | 已记录脏工作区与前序改动；通过代码审计和新增测试锁定 env 被空配置覆盖链路；确认非 pnpm/corepack、非 Wails binding 主因。 |
| Phase 1：修复前端配置来源语义 | 完成 | `missing` 不再 POST 空配置；legacy tshark 只合并 tshark；完整 stored config 继续优先；失败进入 degraded。 |
| Phase 2：后端配置语义加固 | 完成 | 后端 env read/unset/round-trip 和 HTTP contract 测试均已覆盖。 |
| Phase 3：UI 展示与提示校准 | 完成 | 输入框改为“显式配置”，状态卡显示实际探测路径，空输入不再被解释为组件不可用。 |
| Phase 4：MISC JavaScript 环境变量边界 | 完成 | 文档明确 Goja 无 `process.env`，Python 继承 env，后续 JS env API 需白名单。 |
| Phase 5：测试与验收 | 完成 | 前端 CI、后端全量测试、root dev/production tag 测试、桌面资产检查均通过。 |
| Phase 6：文档与交付报告 | 完成 | README、MISC 文档与本报告已更新。 |

## 最终结论

本轮已修复“运行时组件无法读取环境变量”的主要链路：首次启动且 localStorage 为空时，前端不再把空默认配置同步回后端，因此不会清空后端进程启动时读取到的 `GSHARK_FFMPEG`、`GSHARK_PYTHON`、`GSHARK_VOSK_MODEL`。

legacy tshark path 迁移时只覆盖 tshark，保留后端 env snapshot 中的 FFmpeg/Python/Vosk/YARA 字段。用户显式保存过完整运行时配置时，本地配置仍然优先。

## 遗留风险

1. 本轮以单元测试、contract 测试和 CI 验证为主，未启动真实 Wails WebView 做可视化截图。
2. 未新增 JavaScript MISC 受限 env API；这是有意保留的安全边界，后续若需要应单独设计权限与白名单。
3. 后端 `SetToolRuntimeConfig()` 的空值 unset 语义仍然存在；它是显式保存空字段时的预期行为，前端 startup 已避免误触发。
4. 工作区仍包含前序可靠性治理改动和大量已跟踪 MISC 污染文件删除，后续提交前建议按主题拆分。

## 自评

本轮修复方向聚焦，没有扩大后端公开 API，也没有把 PATH/default 探测结果误写成用户显式配置。关键风险点已经由前端 storage/lifecycle 测试、后端 env round-trip 测试和 HTTP contract 测试锁住。当前可交付标准达成。
