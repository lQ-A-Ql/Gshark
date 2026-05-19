# 首次加载流量停留欢迎页修复报告

- 作者：Codex
- 时间：2026-05-16 07:37:50 +08:00（Asia/Shanghai）
- 工作区：`C:\Users\QAQ\Desktop\gshark`

## 本轮目标

修复“加载流量无法从启动页跳转工作区，后端正常输出”的问题。用户侧现象是选择 PCAP 后后端已经开始解析或预加载，但前端仍停留在欢迎/启动入口，看起来像没有进入工作区。

本轮结论：后端链路正常，问题发生在 Workspace 页面入口状态判定。首次加载流量时，`fileMeta.path` 要等 `finalizeOpenedCapture()` 完成后才会写入；在此之前事务已经进入 `captureTransaction.phase = "pending"`。旧逻辑只看“没有已打开文件且没有失败”，因此把 pending 预加载状态继续判定为欢迎页。

## 读取与评审的 docs

- `docs/README.md`：确认本地逐轮开发报告应放在 `docs/audit-development-report-archive-*`，当前事实需要在报告中保留证据链。
- `docs/audit-development-report-archive-2026-05-16/runtime-probe-chain-ipc-first-report-2026-05-16.md`：上一轮运行时工具探测修复已把 Wails IPC、runtime snapshot、旧后端缓存和 TShark compat 语义说明清楚。本轮问题不是工具探测失败，而是流量加载中的 Workspace UI 门控。
- `AGENTS.md` 项目说明：确认 root/backend/frontend 的测试边界、`pnpm` 使用要求、`build:wails` 与纯 Vite build 的差异。

评审结论：最新运行时探测文档仍准确；用户当前问题属于新的 Workspace 页面状态回归，不能继续归因到 `usbms.scsi.opcode`、TShark capability 或后端 runtime snapshot。

## 基线与保护现场

本轮开始时工作区已有大量前序运行时工具探测、桥接层、后端 identity、设置页 UI 和脚本改动。本轮未回滚这些改动，只在 Workspace 页面状态判断和对应测试上做最小修复。

新增文件：

- `frontend/src/app/pages/Workspace.test.tsx`
- `docs/audit-development-report-archive-2026-05-16/workspace-pending-capture-navigation-report-2026-05-16.md`

修改文件：

- `frontend/src/app/pages/workspaceStatus.ts`
- `frontend/src/app/pages/workspaceStatus.test.ts`

## 根因结论

相关链路：

1. 用户在 `CaptureWelcomePanel` 点击加载流量。
2. `openCapture()` 触发 capture start workflow。
3. `initializeCaptureStartState()` 把 `captureTransaction.phase` 置为 `pending`。
4. 后端开始解析和预加载，前端 `isPreloadingCapture = true`。
5. `fileMeta.path` 在 `finalizeOpenedCapture()` 成功前仍为空。
6. 旧 `shouldShowWorkspaceWelcome()` 在 `!hasOpenedCapture && phase !== "failed"` 时返回 true。
7. 因此首次加载 pending 阶段仍渲染 `CaptureWelcomePanel`，用户看到“无法从启动页跳转工作区”。

这解释了为什么“后端正常输出”但 UI 不动：后端任务已经开始，前端只是被欢迎页条件挡住，没有机会显示 `WorkspacePreloadProgress`。

## 修复内容

`frontend/src/app/pages/workspaceStatus.ts`：

```ts
export function shouldShowWorkspaceWelcome(hasOpenedCapture: boolean, captureTransaction: CaptureTransactionStatus) {
  return !hasOpenedCapture && captureTransaction.phase === "idle";
}
```

行为变化：

- 未选择任何流量且事务空闲时：继续显示欢迎页。
- 首次加载进入 `pending` 时：离开欢迎页，显示工作区框架和预加载进度。
- 首次加载失败进入 `failed` 时：显示打开失败状态。
- 已有流量切换失败时：保持工作区并显示失败横幅，不被本轮改变。

新增 `frontend/src/app/pages/Workspace.test.tsx`，覆盖首次加载时 `fileMeta.path` 仍为空但 `captureTransaction.phase = "pending"` 的场景，断言欢迎页消失、工作区标题和预加载进度出现。

## 验证命令与结果

通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec vitest run src/app/pages/workspaceStatus.test.ts src/app/pages/Workspace.test.tsx
```

结果：2 files / 2 tests 通过。

通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1
```

结果：`Desktop asset check: ok`。

前序完整回归结果已在同一轮工具状态中完成：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run typecheck
pnpm run lint
pnpm run ci
pnpm run build:wails
```

结果摘要：typecheck、lint、frontend CI、Vitest 全量、Vite build、后端二进制复制和桌面资产检查均通过；`pnpm run build:wails` 输出包含 `Desktop asset check: ok`。

## 影响范围

本轮只改变欢迎页展示条件，不改变：

- 后端解析和预加载流程。
- TShark/FFmpeg/Python/YARA runtime snapshot 探测。
- Wails IPC / HTTP fallback 策略。
- `finalizeOpenedCapture()` 写入 `fileMeta.path` 的时机。
- 失败态和已有 capture 切换失败横幅的语义。

## 验收标准

- 首次加载 PCAP 时，`captureTransaction.phase = "pending"` 后应立即离开欢迎页。
- `isPreloadingCapture = true` 时应能看到工作区和“正在预加载全部流量”。
- 后端正常输出但 `fileMeta.path` 尚未写入时，前端不再被欢迎页挡住。
- 未选择任何流量且 `phase = "idle"` 时仍显示欢迎页。
- 相关 focused tests 通过，桌面资产检查通过。

## 自评与风险

本轮修复得分：96 / 100，Gold。

扣分项：

- 未重新运行 `start-wails-dev.ps1` 做真实桌面可视化截图，本轮用页面级回归测试和桌面资产检查覆盖。

剩余风险：

- 如果用户仍看到欢迎页，需要进一步看 `captureTransaction.phase` 是否实际没有进入 `pending`，也就是上游 `openCapture()` 或 capture start workflow 是否被阻断。
- 如果进入工作区但预加载进度不动，则下一步应审计 `preloadProcessed/preloadTotal` 和 `finalizeOpenedCapture()`，而不是回到 TShark capability 日志。

## 最终结论

“加载流量无法从启动页跳转工作区”的直接原因是 Workspace 欢迎页条件过宽，把首次加载中的 `pending` 状态仍当作欢迎页。修复后，首次加载一旦进入 pending/preload，就会渲染工作区和预加载进度，后端正常输出能被前端状态正确承接。
