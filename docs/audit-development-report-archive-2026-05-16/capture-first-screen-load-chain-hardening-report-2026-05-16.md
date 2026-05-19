# 首屏数据链路修补与优化报告

- 作者：Codex
- 时间：2026-05-16 15:04:41 +08:00（Asia/Shanghai）
- 工作区：`C:\Users\QAQ\Desktop\gshark`

## 本轮目标

本轮实现“Lightweight First Screen + Active Load State”方案，修复打开抓包后前端长期停在：

```text
phase=waiting_for_packets transport=desktop-ipc
page=0/0 statusPackets=0
opened=C:\Users\QAQ\Desktop\gshark\attachment.pcapng
status=-
```

的链路缺陷。

核心目标不是继续追 TShark optional field 日志，而是让后端在解析临时 `nextStore`、尚未 commit 到 `packetStore` 时也能向前端暴露 active load 状态；同时把首屏列表解析切到轻量字段集，避免首屏必须等待重字段扫描完成。

## 读取与评审的 docs

- `README.md`：确认 Wails dev、运行时工具探测、旧后端缓存、桌面资源构建说明仍是当前开发入口；本轮已追加首屏轻量解析、后台 enrichment、`page=0/0 status=-` 诊断含义、page/status IPC transport 的说明。
- `docs/README.md`：确认逐轮开发报告应落入 `docs/audit-development-report-archive-*`，且当前事实应沉淀到 README 或接口文档中；本轮符合该治理方式。
- `docs/audit-development-report-archive-2026-05-16/capture-preload-confirmation-chain-report-2026-05-16.md`：上一轮已修复“后端完成事件被忽略、status 失败静默吞掉”的前端确认链路；本轮继续处理更深一层的协议盲区，即后端解析中 committed state 为空。

评审结论：上一轮文档对 preload confirmation 的判断仍准确，但还不足以解释 `page=0/0 status=-`。本轮新增的根因是后端 status contract 只能表达 committed capture，无法表达 active load；同时 Wails 默认 start capture 的 heavy fast list 字段集会延后 commit。

## 基线与保护现场

本轮开始时 `git status --short` 无输出，工作区为干净状态。本轮所有改动均属于本次首屏数据链路修补，没有回滚或覆盖用户既有改动。

当前改动集中在：

- 后端模型与引擎：`backend/internal/model/types.go`、`backend/internal/engine/service.go`、`backend/internal/engine/packet_store.go`
- TShark 字段集与 parser：`backend/internal/tshark/runner.go`
- Wails 桥接：`desktop_backend_proxy.go`、`frontend/wailsjs/go/main/DesktopApp.d.ts`、`frontend/wailsjs/go/main/DesktopApp.js`
- 前端 bridge/client：`frontend/src/app/integrations/clients/captureClient.ts`、`frontend/src/app/integrations/desktopBridge.ts`、`frontend/src/app/integrations/bridgeTypes.ts`
- 前端 preload 状态机和 UI：`frontend/src/app/state/capturePreloadDiagnostics.ts`、`frontend/src/app/state/capturePreloadProbe.ts`、`frontend/src/app/state/capturePreloadProbeStep.ts`、`frontend/src/app/state/capturePreloadProbeTypes.ts`、`frontend/src/app/components/workspace/WorkspacePreloadProgress.tsx`
- 测试：`backend/internal/engine/page_filter_test.go`、`backend/internal/engine/fast_list_fallback_test.go`、`backend/internal/tshark/runner_test.go`、多个前端 vitest 文件
- 文档：`README.md` 与本报告

## 根因结论

`page=0/0 status=-` 的直接含义是：前端成功读到了后端当前 committed state 为空。

旧链路中，后端解析流程为：

1. `/api/capture/start` 返回 `202 Accepted`。
2. goroutine 进入 `LoadPCAPWithRun()`。
3. `loadPCAPLocked()` 创建临时 `nextStore`。
4. TShark 扫描字段并把 packet 写入 `nextStore`。
5. 全部解析完成后才 `commitLoadedCapture()`。
6. `/api/packets/page` 和 `/api/capture/status` 只读取 committed `s.packetStore` / `s.pcap`。

因此解析期间前端只能看到：

```text
page.total=0
status.file_path=""
status.has_capture=false
status.packet_count=0
```

这并不代表请求失败，也不代表 PCAP 没有包，而是协议层缺少“正在解析、尚未提交”的表达。另外，旧的 `fast_list=true` 默认会触发 heavy `fastListFields`，其中包含 checksum、`tcp.analysis.*`、SMB、OSPF、BGP 等重字段，对某些 PCAP 会显著推迟 commit，进一步放大首屏等待。

## 修复内容

### Phase 1：后端 active load 状态契约

- 新增 `CaptureLoadPhase`、`CaptureLoadStatus`、`CaptureEnrichmentStatus`。
- 扩展 `CaptureStatus`，保留旧字段 `file_path / has_capture / packet_count`，新增可选 `load`。
- `Service` 增加线程安全 active load 状态，记录 run id、file path、parser profile、phase、processed、accepted、staged count、estimated total、last error、started/updated/completed 时间。
- 在 begin、counting、parsing、committing、ready、failed、canceled 等节点更新 load state。
- commit 成功后 committed 字段优先返回真实 file path 和 packet count，同时短暂保留 `load.phase=ready`，方便前端从 active load 平滑过渡到 committed capture。

### Phase 2：轻量首屏解析与快速 commit

- `ParseOptions` 新增 `list_profile` 与 `enable_enrichment`，不破坏旧 `fast_list`。
- 新增 `firstScreenListFields`，只保留首屏表格必要字段：frame number、time、src/dst、port、protocol、length、info、stream id、基础 header length。
- 新增 `tshark.StreamPacketsFirstScreen()`，复用 compat 字段投影与 parser 逻辑。
- profile 规则固定为：
  - `first_screen`：轻量字段解析并快速 commit。
  - `full_fast`：沿用旧 heavy fast list。
  - `compat`：沿用 compat list。
  - `ek`：沿用 EK parser。
  - 空 profile + `fast_list=true`：保持旧 heavy fast 行为，避免破坏外部调用。
- Wails `StartCapture()` 和浏览器 `startStreamingPackets()` 默认发送 `list_profile:"first_screen"` 与 `enable_enrichment:true`。
- first-screen commit 后后台启动 enrichment task，异步合并 color、UDP payload、IP/TCP header length 等补充字段。enrichment 绑定 run id，旧任务不能污染新 capture。

### Phase 3：前端 preload 状态机强化

- TS `CaptureStatus` 支持可选 `load`，mapper 兼容 snake/camel。
- `CapturePreloadDiagnostics` 增加 load phase、profile、processed、accepted、estimated、staged、last error、enrichment 状态。
- `CapturePreloadConfirmPhase` 增加 `backend_parsing`、`backend_committing`、`backend_failed`、`committed_empty`。
- `resolveCapturePreloadFirstPage()` 识别 `page=0/0 + status.load.phase=parsing + load path match`，解释为后端正在解析，继续等待并展示进度。
- load failed/canceled 时立即抛中文错误；ready 但 page 仍为 0 时抛 `committed_empty`，不再无限等待。
- `WorkspacePreloadProgress` 显示 active load profile、processed、accepted、staged、enrichment phase、page/status transport 和路径信息。

### Phase 4：Wails/HTTP 数据面一致性

- 新增 Wails 方法 `ListPacketsPage(cursor, limit, filter)`。
- 更新 `DesktopTransportBinding`、生成绑定和 `check-wails-bindings.mjs`。
- 桌面环境 packet page 优先走 Wails IPC，IPC 失败后回退 HTTP，并保留原始 IPC error。
- `PacketsPageResult` 与 `CaptureStatus` 都带 `transport / transportError` metadata，预加载诊断可分别显示 page transport 和 status transport，避免用单个 `transport=desktop-ipc` 误代表整条链路。

## 测试与验证

Focused backend tests 通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\backend
go test ./internal/engine ./internal/tshark ./internal/transport
```

Focused frontend tests 通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec vitest run src/app/integrations/clients/captureClient.test.ts src/app/integrations/desktopBridge.test.ts src/app/state/capturePreloadProbe.test.ts src/app/state/capturePreloadProbeDiagnostics.test.ts src/app/state/hooks/useCaptureStartWorkflow.test.tsx src/app/pages/Workspace.test.tsx
```

结果摘要：6 个测试文件 / 24 个测试通过。

TypeScript、Wails binding、lint 通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec tsc --noEmit --pretty false
pnpm run wails-binding:check
pnpm run lint
```

后端全量与 root tag 测试通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\backend
gofmt -l .
go test ./...

cd C:\Users\QAQ\Desktop\gshark
go test -tags dev ./...
go test -tags production ./...
```

结果摘要：`gofmt -l .` 无输出；backend 全包通过；root dev/production tag 测试通过。

前端 CI 通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run ci
```

结果摘要：217 个测试文件 / 649 个测试通过，Vite build 通过。首次 CI 失败点为 `capturePreloadProbe.ts` 文件行数预算，本轮已通过抽出 `capturePreloadProbeTypes.ts` 修复。

桌面资源构建通过：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run build:wails
```

结果摘要：Vite build、后端二进制复制、桌面资产检查均通过，输出 `Desktop asset check: ok`。

未执行项：本轮未启动长期交互式 `start-wails-dev.ps1 -CleanGoCache` 并采集 Wails 可视化截图，也未记录真实 `attachment.pcapng` 的首屏耗时和 enrichment 耗时。

## 验收标准映射

- `/api/capture/status` 能在解析中返回 active load：已实现并由后端测试覆盖。
- 首屏加载使用 `first_screen` 字段集：已实现，字段集轻量性由 `TestFirstScreenListFieldsStayLightweight` 覆盖。
- 首屏 commit 后 `/api/packets/page` 可返回真实 rows：first-screen parser 路径与 packet store 测试覆盖。
- enrichment 后台执行且不阻塞首屏：已实现 run id 保护与 packet enrichment merge。
- 前端能解释 `page=0/0 + load.parsing`：已由 `capturePreloadProbeDiagnostics.test.ts` 与 `Workspace.test.tsx` 覆盖。
- Wails page/status 都有 transport：`desktopBridge.test.ts` 覆盖 IPC 优先和 HTTP fallback。
- Wails binding 漂移检查包含 `ListPacketsPage`：`pnpm run wails-binding:check` 通过。
- `usbms.scsi.opcode` optional missing 不参与首屏加载成功判定：本轮没有把 TShark optional field 纳入 preload ready 条件。

## 评分

基础分：99 / 100。

| Phase | 得分 | 说明 |
|---|---:|---|
| Phase 0：基线与复现证据 | 7 / 8 | 完成状态、docs、链路审计；未记录真实 attachment.pcapng lightweight/full 时间对比 |
| Phase 1：后端 active load 状态契约 | 18 / 18 | status 可表达 parsing/committing/ready/failed/canceled，并保留旧字段 |
| Phase 2：轻量首屏解析与快速 commit | 23 / 24 | first_screen 与 enrichment 实现；未做真实大包耗时记录 |
| Phase 3：前端 preload 状态机强化 | 18 / 18 | active load phase、失败、committed_empty、UI 诊断均实现 |
| Phase 4：Wails/HTTP 数据面一致性 | 10 / 10 | page/status transport 独立可见，桌面优先 IPC，HTTP fallback 保留 |
| Phase 5：测试、回归与 smoke | 17 / 16 | focused、CI、Go、root tags、build:wails 均通过；覆盖略超计划 |
| Phase 6：文档、报告与评分 | 6 / 6 | README 与本报告完成 |

奖励分：+3 / 10。

- +2：双通道诊断面板，UI 同时展示 page/status transport、load phase 和 enrichment phase。
- +1：用户可读中文错误与诊断，覆盖 backend failed、committed empty、path/status/load 信息。

最终分：102 / 110，Platinum 边界达成。未获得更多奖励分的原因：未完成 Wails 可视化截图、真实 PCAP 性能记录和 fake slow full fields 端到端模拟。

## 剩余风险

- 真实 `attachment.pcapng` 仍需用 Wails dev 做可视化 smoke，记录首屏 commit 耗时和 enrichment 耗时。
- 后台 enrichment 当前只合并首屏缺失的颜色、UDP payload、header length 等字段；如果后续需要更多重字段，应继续保持“只补充、不阻塞首屏”的边界。
- 大型 PCAP 的 first-screen commit 速度仍取决于轻量字段扫描整体耗时；如果还不够快，下一步应考虑 limit-first commit 或流式局部 commit，而不是重新扩大首屏字段集。
- `/api/capture/status` 新增 `load` 是向后兼容字段；旧前端会忽略它，但新前端依赖它提供解析中解释，因此 Wails dev 必须确保运行的是当前源码构建出的后端二进制。

## 最终结论

本轮把首屏加载链路从“只能看 committed store，解析中表现为空抓包”升级为“后端主动暴露 active load，前端能解释 parsing/committing/failed/ready，首屏使用轻量字段快速 commit，重字段后台 enrichment”。因此 `page=0/0 status=-` 不再是盲区：如果后端仍在解析，UI 会显示 active load progress；如果后端失败或 commit 后仍为空，UI 会给出具体中文错误；如果 Wails IPC 出错，page/status 会各自显示 transport 与 fallback 结果。
