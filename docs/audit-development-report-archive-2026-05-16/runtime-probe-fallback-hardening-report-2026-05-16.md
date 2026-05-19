# 运行时工具探测 fallback 加固报告

- 作者：Codex
- 时间：2026-05-16 16:04:57 +08:00（Asia/Shanghai）
- 工作区：`C:\Users\QAQ\Desktop\gshark`

## 本轮目标

用户反馈“又无法探测环境工具”，要求审计首屏数据链路改动是否污染了 TShark、FFmpeg、Python/Vosk 等运行时组件探测链路，并直接修补。

本轮先审计 diff 和 runtime probe 调用链，再实施最小加固：

- Wails IPC runtime snapshot / config sync 失败时自动 HTTP fallback。
- 手动“重新探测工具”和“保存并应用”增加真实 abortable timeout。
- 设置页保存只标记实际 dirty 字段为 explicit，避免空表单再次被写成“清空全部 env”的显式配置。
- 设置页 footer 显示“成功走 HTTP fallback，但 IPC 曾失败”的诊断信息。

## 读取与评审的 docs

- `README.md`：当前 README 已说明 Wails runtime probe 优先 IPC、HTTP fallback、设置页会显示最近探测链路和失败原因；本轮实现进一步补齐“IPC 方法存在但调用失败”的 fallback 缺口。
- `docs/README.md`：确认逐轮开发报告放入 `docs/audit-development-report-archive-*`；本报告继续按该约定归档。
- `docs/audit-development-report-archive-2026-05-16/runtime-probe-chain-ipc-first-report-2026-05-16.md`：前序报告已提出 IPC-first 策略；本轮发现旧实现只保证“binding 存在则 IPC 优先”，但未保证“IPC 调用失败后 fallback”。
- `docs/audit-development-report-archive-2026-05-16/capture-first-screen-load-chain-hardening-report-2026-05-16.md`：首屏修复新增 `ListPacketsPage` 和 capture active load；审计结论是这些改动没有直接触碰 runtime probe 核心链路。

评审结论：文档方向准确，但 runtime probe 链路仍缺少一个关键健壮性闭环：桌面 binding 存在时 IPC 抛错会直接使探测失败，而不像 capture status/page 那样 fallback 到 HTTP。

## 审计结论

本轮首屏数据链路改动没有直接污染运行时工具探测核心文件。

未被首屏改动触碰的核心链路包括：

- `frontend/src/app/state/hooks/useToolRuntime.ts`
- `frontend/src/app/state/hooks/backendLifecycleStartup.ts`
- `frontend/src/app/state/toolRuntimeStorage.ts`
- `frontend/src/app/state/toolRuntimeStorageConfig.ts`
- `frontend/src/app/integrations/clients/toolRuntimeClient.ts`
- `backend/internal/engine/tool_runtime.go`
- `backend/internal/transport/http_server.go`

首屏修复直接相关的 bridge 改动主要是新增 `ListPacketsPage`：

- `desktop_backend_proxy.go`
- `frontend/src/app/integrations/desktopBridge.ts`
- `frontend/wailsjs/go/main/DesktopApp.d.ts`
- `frontend/wailsjs/go/main/DesktopApp.js`

因此，“无法探测环境工具”的当前高风险点不是 first-screen parser 或 active load，而是 runtime probe 自身的旧短板：

1. Wails binding 存在但 `GetToolRuntimeSnapshot()` 抛错时，没有 HTTP fallback。
2. 手动刷新没有 timeout，慢探测或 IPC 卡住会让设置页长期不可解释。
3. 设置页保存整张表单时会默认把所有字段标记为 explicit，空字段可能被持久化为用户显式清空 env。

## 修复内容

### 1. Runtime snapshot metadata

扩展 `ToolRuntimeSnapshot` 内部 metadata：

- `transport?: "desktop-ipc" | "http-fallback" | "unknown"`
- `transportError?: string`

新增 `frontend/src/app/integrations/toolRuntimeSnapshotMeta.ts`，用非枚举属性挂载 metadata，避免污染后端 wire shape 或普通对象序列化。

### 2. Wails IPC 失败 fallback

`frontend/src/app/integrations/desktopBridge.ts` 中：

- `getToolRuntimeSnapshot(signal?)`
  - Wails IPC 成功：返回 `transport="desktop-ipc"`。
  - Wails IPC 失败：调用 HTTP fallback，并保留原始 IPC error 到 `transportError`。
- `updateToolRuntimeConfig(config, signal?)`
  - 同样增加 IPC 失败后的 HTTP fallback。

这保持了“桌面 IPC 优先”的策略，同时避免 IPC 单点失败让 UI 误报“工具都不可探测”。

### 3. 手动探测 timeout

新增 `frontend/src/app/state/toolRuntimeProbeActions.ts`：

- `probeToolRuntimeSnapshot()`
- `syncToolRuntimeConfig(config)`

两者都复用 `withAbortableTimeout()` 和 `STARTUP_TOOL_RUNTIME_TIMEOUT_MS`。手动“重新探测工具”和“保存并应用”现在和启动探测一样，有真实 AbortSignal，不再只是 UI 等待。

### 4. 显式字段 dirty 化

`useRuntimeSettingsSidebarModel()` 现在会比较当前 snapshot config 和表单，只把实际变化字段作为 `explicitFields` 传给 `saveToolRuntimeConfig()`。

效果：

- 用户只改 FFmpeg，则只写 `explicitFields.ffmpegPath=true`。
- 用户没有改 Python/Vosk，不会因为表单里显示为空就把 `GSHARK_PYTHON / GSHARK_VOSK_MODEL` 写成显式清空。
- 用户确实把某字段从非空清空并保存时，该字段仍会被显式清空，保留用户意图。

### 5. 设置页 fallback 诊断

`RuntimeSettingsFooter` 在探测成功但发生 fallback 时显示：

```text
最近一次探测已通过 HTTP fallback 完成；备用链路原因：...
```

这样下次看到“探测异常”时，可以区分：

- IPC 成功；
- IPC 失败但 HTTP fallback 成功；
- IPC/HTTP 都失败；
- token / 端口 / timeout / 旧后端问题。

## 修改文件

本轮新增/修改的 runtime probe 相关文件：

- `frontend/src/app/core/types/tools.ts`
- `frontend/src/app/integrations/toolRuntimeSnapshotMeta.ts`
- `frontend/src/app/integrations/clients/toolRuntimeClient.ts`
- `frontend/src/app/integrations/clients/toolRuntimeClient.test.ts`
- `frontend/src/app/integrations/desktopBridge.ts`
- `frontend/src/app/integrations/desktopBridge.test.ts`
- `frontend/src/app/components/RuntimeSettingsShell.tsx`
- `frontend/src/app/components/RuntimeSettingsShell.test.tsx`
- `frontend/src/app/components/RuntimeSettingsSidebar.tsx`
- `frontend/src/app/components/useRuntimeSettingsSidebarModel.ts`
- `frontend/src/app/state/toolRuntimeProbeActions.ts`
- `frontend/src/app/state/toolRuntimeStorageConfig.ts`
- `frontend/src/app/state/hooks/backendLifecycleStartup.ts`
- `frontend/src/app/state/hooks/backendLifecycleToolRuntimeStartup.ts`
- `frontend/src/app/state/hooks/useBackendLifecycle.ts`
- `frontend/src/app/state/hooks/useBackendLifecycleControls.ts`
- `frontend/src/app/state/hooks/useBackendLifecycle.test.tsx`
- `frontend/src/app/state/hooks/useToolRuntime.ts`
- `frontend/src/app/state/sentinelTypes.ts`

## 测试与验证

Focused frontend tests 通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec vitest run src/app/integrations/desktopBridge.test.ts src/app/integrations/clients/toolRuntimeClient.test.ts src/app/state/hooks/useBackendLifecycle.test.tsx src/app/components/RuntimeSettingsShell.test.tsx src/app/state/toolRuntimeStorage.test.ts
```

结果：5 个测试文件 / 41 个测试通过。

前端类型、lint、size、完整 CI 通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec tsc --noEmit --pretty false
pnpm run lint
pnpm run size:check
pnpm run ci
```

结果摘要：

- TypeScript 通过。
- ESLint 通过。
- Size budget 通过。
- `pnpm run ci` 全部通过：217 个测试文件 / 653 个测试通过，Vite build 通过。

后端 focused tests 通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\backend
go test ./internal/engine ./internal/transport -count=1
```

结果：engine 和 transport 通过。

桌面资产检查通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run build:wails
```

结果：Vite build、后端二进制复制、桌面资产检查均通过，输出 `Desktop asset check: ok`。

`git diff --check` 无输出。

## 当前限制

- 本轮未启动真实 `start-wails-dev.ps1 -CleanGoCache` 做可视化验证，因为当前修复可由 bridge/unit/CI 覆盖，且避免留下交互式进程。
- 如果用户本机仍无法探测，应查看设置页 footer 的 transport 与 fallback 诊断；若显示 HTTP fallback 也失败，下一步优先查后端 token、端口、旧进程和 `/api/runtime/identity`。
- 如果设置页已经保存过空字段，当前修复会阻止“未改字段继续被清空”，但用户已显式清空的字段仍会作为用户意图保留；需要用户重新填写或通过重置配置恢复。

## 评分

基础分：94 / 100。

| Phase | 得分 | 说明 |
|---|---:|---|
| 审计与污染确认 | 18 / 20 | 确认首屏改动未触碰 runtime core；未做 live Wails 截图 |
| IPC fallback | 24 / 24 | snapshot/config sync 均支持 IPC 失败后 HTTP fallback |
| Timeout 与取消 | 18 / 18 | 手动刷新/保存使用 abortable timeout |
| 显式字段保护 | 18 / 20 | dirty fields 防止空表单全字段清空；仍保留用户显式清空语义 |
| 诊断 UI | 8 / 8 | footer 显示 fallback 成功但 IPC 失败的原因 |
| 测试与回归 | 8 / 10 | frontend CI、backend focused、build:wails 通过；未跑真实 Wails smoke |

奖励分：+3 / 10。

- +2：IPC/HTTP fallback transport metadata 可见。
- +1：显式字段 dirty 化降低 env 被误清空概率。

最终分：97 / 110，Gold。

## 最终结论

本轮结论是：首屏数据链路补丁没有污染运行时工具探测链路；真正的短板在 runtime probe 自身的 Wails IPC 单点失败、手动探测无 timeout、以及保存表单显式字段过宽。现在这些短板已修补：桌面优先 IPC，IPC 失败自动 HTTP fallback；手动探测和保存会真实 abort；设置页只把用户实际改动字段写成 explicit；UI 能显示 fallback 诊断。后续如果再出现“无法探测环境工具”，应直接看设置页 footer 的 transport/error，而不是重新归因到 TShark optional field 或首屏 parser。
