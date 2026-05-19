# 流量预加载确认链路修复报告

- 作者：Codex
- 时间：2026-05-16 13:13:55 +08:00（Asia/Shanghai）
- 工作区：`C:\Users\QAQ\Desktop\gshark`

## 本轮目标

修复“后端已解析完成，前端仍停留在预加载阶段”的链路级问题。重点不再归因于 TShark optional field 日志，而是审计并修补前端从后端完成事件、首屏数据页、抓包状态确认到 Workspace 预加载 UI 的完整传输链路。

## 读取与评审的 docs

- `docs/README.md`：确认本地逐轮报告应落入 `docs/audit-development-report-archive-*`，当前事实需要以开发报告补充证据链。
- `README.md`：确认 Wails dev、`build:wails`、桌面资产、运行时工具探测和旧后端缓存说明仍是当前正确开发入口。
- `docs/audit-development-report-archive-2026-05-16/workspace-pending-capture-navigation-report-2026-05-16.md`：上一轮已修复 pending 阶段仍显示欢迎页的问题；本轮继续处理进入工作区后预加载确认卡住的问题。

评审结论：最新文档对“欢迎页门控”与“工具探测不是当前根因”的判断仍准确。本轮新增问题发生在 Workspace 内部的 preload confirmation 链路：后端完成不等于前端已确认 page/status 并提交 `fileMeta`。

## 基线与保护现场

本轮开始时工作区已有多处前序 runtime probe、Wails IPC、后端 identity、设置页 UI、Workspace pending 导航修复等改动。本轮未回滚这些既有改动，只在预加载事件消费、page/status 确认、桥接状态 metadata、预加载诊断 UI 与对应测试上继续收口。

`git status --short` 显示的前序改动仍包括 `README.md`、`app.go`、`desktop_backend_proxy.go`、运行时设置组件、runtime probe hooks、`scripts/start-wails-dev.ps1` 等。本轮新增/重点改动集中在：

- `frontend/src/app/state/hooks/backendLifecycleEvents.ts`
- `frontend/src/app/state/capturePreloadProbe.ts`
- `frontend/src/app/state/capturePreloadProbeStep.ts`
- `frontend/src/app/state/capturePreloadDiagnostics.ts`
- `frontend/src/app/state/hooks/useCaptureStartWorkflow.ts`
- `frontend/src/app/state/hooks/useCapturePreloadState.ts`
- `frontend/src/app/state/SentinelContext.tsx`
- `frontend/src/app/state/sentinelTypes.ts`
- `frontend/src/app/integrations/clients/captureClient.ts`
- `frontend/src/app/integrations/desktopBridge.ts`
- `frontend/src/app/pages/Workspace.tsx`
- `frontend/src/app/components/workspace/WorkspacePreloadProgress.tsx`
- `frontend/src/app/components/workspace/usePreloadElapsedMs.ts`
- `frontend/src/app/state/capturePreloadProbeDiagnostics.test.ts`
- `frontend/src/app/pages/Workspace.test.tsx`
- `docs/audit-development-report-archive-2026-05-16/capture-preload-confirmation-chain-report-2026-05-16.md`

## 根因结论

链路审计结论：

1. 首次加载期间，`activeCapturePathRef.current` 只有在 `finalizeOpenedCapture()` 成功后才写入。
2. 后端 SSE 在解析期间会发送 `__progress__`、`解析完成` 或错误事件。
3. 旧事件层只用 `activeCapturePathRef.current` 判断是否有 capture context；首次加载时该值为空，于是完成/进度事件会被当成后台残留消息忽略。
4. `resolveCapturePreloadFirstPage()` 同时依赖 `/api/packets/page` 和 `/api/capture/status`，但 status 失败被吞成 `null`，UI 只看到“仍在预加载”，看不到 status 失败、path mismatch、token/IPC/HTTP 错误。
5. 切换已有 capture 时必须严格要求 status path 匹配；首次加载没有旧 active capture 时，可以在后端已解析完成、首屏 page 有数据、status 短暂失败的条件下做 degraded finalize，避免单点 status 确认把 UI 永久卡住。

因此，用户看到“后端显示加载完成，前端还是预加载阶段”的直接原因是：完成事件可能未被消费，后续 page/status 确认失败又没有被显式暴露或降级处理。

## 修复内容

### Phase 1：首次加载事件消费

- `backendLifecycleEvents.ts` 的 capture lifecycle guard 改为 `Boolean(activeCapturePathRef.current) || preloadingRef.current`。
- 首次加载期间即使 active path 为空，也会消费 `__progress__`、`解析完成` 和错误事件。
- 空闲状态仍保留保护：没有 active capture 且不在 preloading 时，后台残留事件不会污染 UI。

### Phase 2：预加载确认状态机

- 新增 `CapturePreloadDiagnostics`，记录 phase、opened/status path、normalized path、page total/items、status packet count、transport、page/status 错误与 degraded 标记。
- `resolveCapturePreloadFirstPage()` 改为通过 `Promise.allSettled` 分别记录 page/status 成败。
- 首次加载兜底：`hadActiveCapture=false`、parse finished、无 parse error、page total > 0、status 失败时允许 degraded finalize。
- 已有 capture 切换不使用 page-only 兜底，仍要求 status path 匹配。
- status path mismatch 会立即抛出中文错误，包含本次打开路径、后端状态路径和包数。
- parse 完成但 page total 为 0 时抛出空解析/入库失败错误，不再等超时。

### Phase 3：桥接与路径诊断

- `CaptureStatus` 增加非枚举 metadata：`transport` 与 `transportError`，不改变后端 wire shape。
- HTTP `/api/capture/status` 返回 metadata 标记为 `http-fallback`。
- Wails `desktopBridge.getCaptureStatus()` 优先 IPC；IPC 失败时尝试 HTTP fallback，并把原始 IPC 错误带入 metadata。
- 诊断 UI 可显示 status 来源，便于区分 Wails IPC、HTTP fallback、token/端口或路径问题。

### Phase 4：UI 诊断与用户操作

- Sentinel context 新增 `capturePreloadDiagnostics` 和 `retryCapturePreloadConfirm()`。
- 新增 `WorkspacePreloadProgress`，5 秒后显示轻量诊断，20 秒后显示详细 phase/page/status/path/transport。
- 增加“重新确认”和“停止”按钮；重新确认只唤醒 page/status probe，不重新解析 PCAP。
- 成功 finalize 后清空 diagnostics，避免旧错误残留。

## 测试与验证

Focused tests 通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec vitest run src/app/state/capturePreloadProbe.test.ts src/app/state/capturePreloadProbeDiagnostics.test.ts src/app/state/hooks/useBackendLifecycle.test.tsx src/app/state/hooks/useCaptureStartWorkflow.test.tsx src/app/pages/Workspace.test.tsx
```

结果：5 files / 27 tests passed。

前端基础检查通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run size:check
pnpm run typecheck
pnpm run lint
```

结果：size budget、TypeScript、ESLint 均通过。

前端完整 CI 通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run ci
```

结果摘要：package-manager、typecheck、lint、format、size、boundary、client/mapper/wire any check、Wails binding check、217 个测试文件 / 644 个测试、Vite build 全部通过。

后端与 root Go 测试通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\backend
gofmt -l .
go test ./...

cd C:\Users\QAQ\Desktop\gshark
go test -tags dev ./...
go test -tags production ./...
```

结果：`gofmt -l .` 无输出；backend 全包通过；root dev/production tag 测试通过。

桌面资源链路通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run build:wails

cd C:\Users\QAQ\Desktop\gshark
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1
```

结果：`build:wails` 完成 Vite build、后端二进制复制和桌面资产检查；单独资产检查输出 `Desktop asset check: ok`。

未执行项：本轮未启动长期运行的 `start-wails-dev.ps1` 做可视化截图，避免在本轮交付时留下交互式 dev server。相关行为由 focused tests、全量 CI、root/backend tests 与桌面资产检查覆盖。

## 验收标准映射

- 后端完成事件在首次加载期间会被消费：已由 `useBackendLifecycle.test.tsx` 覆盖。
- page/status 双确认失败不再无声卡住：已由 `capturePreloadProbe.test.ts` 和 `capturePreloadProbeDiagnostics.test.ts` 覆盖。
- status 失败在首次加载可 degraded finalize，已有 capture 切换仍严格要求 status path：已覆盖。
- path mismatch 中文错误包含 opened/status path 和 packet count：已覆盖。
- 预加载 UI 能显示诊断并触发重新确认：已由 `Workspace.test.tsx` 覆盖。
- 不改变 `/api/capture/start` 202 异步语义，不改变 `/api/capture/status` wire shape：本轮仅增加前端非枚举 metadata。

## 评分

基础分：97 / 100，Gold。

| Phase | 得分 | 说明 |
|---|---:|---|
| Phase 0：基线与复现证据 | 6 / 8 | 完成 docs/status/代码链路审计；未做真实 Wails PCAP 复现截图 |
| Phase 1：首次加载事件消费修复 | 18 / 18 | preloading context 下消费 progress/done/error，空闲残留仍保护 |
| Phase 2：预加载确认状态机修复 | 26 / 26 | allSettled、诊断、degraded finalize、path mismatch、空页错误均实现 |
| Phase 3：桥接与路径一致性诊断 | 13 / 14 | IPC/HTTP status metadata 与 fallback 完成；未新增后端字段，保持兼容 |
| Phase 4：UI 诊断与用户操作 | 12 / 12 | 诊断面板、重新确认、停止、成功清理均实现 |
| Phase 5：测试与验收 | 16 / 16 | focused、CI、Go、root tags、build:wails、资产检查均通过 |
| Phase 6：文档与交付报告 | 6 / 6 | 本报告完成 |

奖励分：+3 / 10。

- +2：状态诊断面板显示 page/status/path/transport。
- +1：path mismatch 自动中文提示包含 opened/status 路径与包数。

最终分：100 / 110，Gold。未达到 Platinum 的原因是未完成真实 Wails 可视化截图、真实 PCAP 自动 smoke 和冷启动/大包耗时记录。

## 剩余风险

- 如果用户在真实 Wails dev 中仍看到预加载卡住，应优先截图诊断面板里的 `phase`、`transport`、`page`、`statusPackets`、`opened`、`status`，而不是继续看 TShark optional field 日志。
- 如果 status path 指向旧文件，诊断会明确给出 opened/status path，下一步应检查后端 capture commit、旧后端进程或端口复用。
- 如果 page total 长期为 0 且后端日志显示 parse completed，应检查入库/过滤表达式/空包错误；本轮已经不会把它静默转成无限预加载。

## 最终结论

本轮把“后端完成但前端预加载卡住”的关键断点从无声失败改成可消费、可诊断、可降级的确认链路：首次加载期间完成事件不再被忽略；page/status 成败分开记录；首次加载可在 status 短暂失败时用 page 数据 degraded finalize；已有 capture 切换仍保持严格 path match；UI 会显示真实卡点并提供重新确认与停止操作。
