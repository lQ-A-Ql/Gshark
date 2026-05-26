# Desktop typed IPC 迁移与自主迭代评估报告

## 本轮目标

落实用户给出的 `Desktop IPC 进一步迁移方案 v3`，把桌面发行版从 generic IPC 后端代理优先推进到 typed IPC 优先，同时新增可版本化追踪的自主迭代评估机制。

本轮实际覆盖面：

- 建立 `docs/desktop-ipc-migration-plan.md` 和 `docs/desktop-ipc-iteration-status.json`。
- 保持 `docs/governance-defect-register.json` 只承载全局 Architecture_Defect，不混入 IPC 迁移过程。
- 为 stream、object、安全材料、tooling、analysis、evidence 增加 DesktopApp typed IPC 方法。
- 在前端 `desktopBridge` 上叠加 typed IPC overrides；binding 缺失时保留旧 generic IPC 兼容，typed binding 存在时不静默落回浏览器 HTTP。
- 将 Wails binding drift 检查升级为分组完整性检查。

## 阅读与评审输入

本轮开发前后对照了以下文档与当前实现状态：

- `AGENTS.md`：确认 root/backend 双 Go module、frontend pnpm、Wails build 资产、结束开发需续写本地报告。
- `docs/README.md`：确认文档入口与当前版本化事实源的组织方式。
- 用户本轮 `Desktop IPC 进一步迁移方案 v3`：作为本轮 phase、task、测试文件、评分阈值和 tracker 字段来源。
- `docs/audit-development-report-archive-2026-05-21/frontend-redundancy-cleanup-2026-05-24.md`：确认最新本地归档写法和验证记录格式。

### 文档评审结论

- IPC 迁移不应塞入 `governance-defect-register.json`；单独的 `desktop-ipc-iteration-status.json` 更适合作为当前轮次、评分、阻塞项与下一轮建议的版本化事实源。
- 用户计划要求每轮只做一个主域，但本轮为了落地 typed IPC 基线一次性覆盖了多个域，属于可接受但需要记录的迭代粒度债务。
- Phase 1-4 目前已完成机器门禁验证，但没有真实桌面 Wails 与 browser-dev 手工 smoke 证据，因此不能把 Phase Audit 写成 fully completed。本轮 tracker 已明确标记为 `machine_validated_audit_pending`。
- Phase 5 的 generic IPC guardrail 尚未实现；下一轮应先补 Phase Audit smoke，再进入自动策略检查脚本。

## 实际改动

### 1. 版本化迁移治理

- 新增 `docs/desktop-ipc-migration-plan.md`：记录桌面/dev transport policy、评分模型、hard blocker、phase 状态和手工 smoke 清单。
- 新增 `docs/desktop-ipc-iteration-status.json`：记录当前 phase audit 状态、各域 typed 方法、最近 round score、open blocker 和下一轮自动建议。
- 更新 `docs/README.md`：把 IPC 迁移计划和 tracker 纳入文档入口，并明确其独立于全局 governance register。

### 2. DesktopApp typed IPC binding

在 `desktop_backend_proxy.go` 新增 typed DesktopApp 方法，当前实现复用现有 backend HTTP route 作为稳定过渡层：

- Stream / packet detail：`GetHttpStream`、`GetRawStream`、`GetRawStreamPage`、`DecodeStreamPayload`、`InspectStreamPayload`、`ListStreamPayloadSources`、`ListStreamIDs`、`UpdateStreamPayloads`、`GetPacketRawHex`、`GetPacketLayers`。
- Object：`ListObjects`、`DownloadObjectsZip`。
- Security material / tooling：`RunWinRMDecrypt`、`GetWinRMDecryptResultText`、`ExportWinRMDecryptResult`、`ListSMB3SessionCandidates`、`GenerateSMB3RandomSessionKey`、`ListNTLMSessionMaterials`、`GetHTTPLoginAnalysis`、`GetSMTPAnalysis`、`GetMySQLAnalysis`、`GetShiroRememberMeAnalysis`。
- Analysis / evidence：`GetGlobalTrafficStats`、`GetIndustrialAnalysis`、`GetVehicleAnalysis`、`GetUSBAnalysis`、`GetC2SampleAnalysis`、`DecryptC2Traffic`、`GetAPTAnalysis`、`GetEvidence`、`GetEvidenceWithFilter`。

新增 `desktop_typed_bindings_test.go` 覆盖 typed methods 到 backend route 的合约代理行为。

### 3. 前端 typed desktop bridge

- 更新 `frontend/src/app/integrations/desktopTransportBinding.ts` 和 `frontend/wailsjs/go/main/DesktopApp.{d.ts,js}`，同步 typed Wails method surface。
- 新增 `desktopTypedBridge*` 分域文件，把 stream、object/tooling、analysis/evidence 的桌面路径改为 typed IPC override。
- 更新 `desktopBridge.ts`：在原 generic `dataBridge` 之上叠加 typed overrides。
- 设计约束：如果某个 typed binding 缺失，就删除对应 override，让旧 binding/dev 兼容路径继续工作；如果 typed binding 已存在但调用失败，则错误由 `withDesktopIpcControls` 返回，不再静默回退到 HTTP。

### 4. Guardrail 与测试更新

- `frontend/scripts/check-wails-bindings.mjs` 从单一方法存在性检查升级为分组检查：`desktop-shell`、`generic-ipc`、`typed-control-plane`、`typed-stream`、`typed-object-tooling`、`typed-analysis-evidence`。
- `frontend/scripts/check-size.mjs` 为新增 typed bridge 分域文件建立 size budget，避免单文件继续膨胀。
- `frontend/src/app/integrations/desktopBridge.test.ts` 增加 migrated domains typed 优先和 binding 缺失 generic fallback 的断言。

## 验证结果

Focused tests 已通过：

```powershell
cd frontend; pnpm exec vitest run src/app/integrations/desktopBridge.test.ts src/app/integrations/bridgeFactory.test.ts src/app/integrations/ipcBackendTransport.test.ts src/app/integrations/clients/streamClient.test.ts src/app/integrations/clients/objectClient.test.ts src/app/integrations/clients/toolClient.test.ts src/app/integrations/clients/analysisClient.test.ts src/app/integrations/clients/c2DecryptClient.test.ts
go test -tags dev -run "TestDesktop(StreamTypedBindings|ObjectToolingAndAnalysisTypedBindings|InvokeBackend|BackendProxy|ValidateDesktopBackendRequest|PingBackendDataPlane)" ./...
```

Full gates 已通过：

```powershell
go test -tags dev ./...
go test -tags production ./...
cd backend; go test ./...
cd frontend; pnpm run ci
cd frontend; pnpm run build:wails
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1
node frontend/scripts/check-wails-bindings.mjs
git diff --check
```

结果摘要：

- Root Go dev tests：通过。
- Root Go production tests：通过。
- Backend Go tests：通过。
- Frontend CI：通过，`227` 个测试文件 / `702` 个测试通过，并完成 typecheck、lint、format、size、boundary、any、binding、Vite build。
- `build:wails`：通过，已生成并校验 `frontend/dist/sentinel-backend.exe`。
- Desktop asset check：通过。
- Wails binding group check：通过。
- `git diff --check`：通过。

未完成项：

- 未执行真实桌面 Wails 手工 smoke。
- 未执行 browser-dev 手工 smoke。
- 因此 Phase 1-4 当前只能标记为 `machine_validated_audit_pending`，不能标记为 Phase Audit fully completed。

## 评分

本轮评分：`96 / 100`

- Contract Correctness：`24 / 25`。typed binding、DTO/mappers、Go route contract 均有覆盖；当前 typed 后端仍复用 backend HTTP route 作为过渡层，扣 1 分。
- Desktop Policy Compliance：`19 / 20`。已迁移域 typed IPC 优先，typed failure 不静默 HTTP fallback；generic IPC 仍保留兼容窗口，扣 1 分。
- Regression Safety：`20 / 20`。focused tests、root dev/production、backend、frontend CI、build:wails、asset check、binding check 均通过。
- Diagnostics and Failure Shape：`14 / 15`。typed endpoint 名称经 `withDesktopIpcControls` 进入错误形态；业务空结果与 IPC transport 错误仍可在部分长尾页继续细化，扣 1 分。
- Docs and Traceability：`10 / 10`。版本化 plan、tracker、README、本地 round report 已同步。
- Dev/Browser Compatibility：`9 / 10`。binding 缺失时仍保留 HTTP/generic 兼容；browser-dev 真实 smoke 未跑，扣 1 分。

Hard blockers：无。

Audit blocker：Phase Audit 手工 smoke 证据未归档。

## 自迭代记录

- 机器门禁结论：当前 typed IPC 迁移 baseline 可用，没有触发 hard blocker。
- 自主决策：不得直接把 Phase 1-4 写成 fully completed；先保留 `machine_validated_audit_pending`。
- 粒度偏差：本轮一次性覆盖多个域，偏离“每轮一个主域”的理想规则；由于用户要求整体实现 v3，本轮接受该偏差，但下一轮应恢复小切片。
- 风险判断：typed 后端方法当前仍代理既有 `/api/...` route，能降低迁移风险，但后续如果要进一步剥离 HTTP transport，需要逐域拆 service-level binding。

## 下一轮自动建议

优先级：

1. 运行并归档 Phase Audit 桌面/browser-dev 手工 smoke，覆盖打开 PCAP、packet page、HTTP/TCP stream、analysis、evidence filter、object/tooling 页。
2. Smoke 通过后，把 `docs/desktop-ipc-migration-plan.md` 和 `docs/desktop-ipc-iteration-status.json` 中 Phase 1-4 改为 completed。
3. 进入 Phase 5，新增 `frontend/scripts/check-desktop-transport-policy.mjs`，阻止已 typed 域新增仅依赖 generic `/api/...` 字符串接线。

署名：Codex
时间：2026-05-24 22:16:25 +08:00
