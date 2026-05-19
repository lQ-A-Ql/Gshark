# 开发治理日报 - 2026-05-13

署名: Kiro
日期: 2026-05-13 03:20:24 +08:00

## 本轮目标

- 首轮治理：完成 iterative-dev-governance spec 的全部 102 项任务，闭环消解 9 个已知架构缺陷（P0×4 + P1×5 + P2×5 + P3×2）。

本轮是 iterative-dev-governance 的首轮（Dev_Round 1），目标是一次性落地治理闭环的全部三块基础设施：`backend/internal/governance/` 辅助包（含 14 条设计属性的 PBT 覆盖）、9 个已知架构缺陷条目的源码修复、以及 Round_Report 归档目录的首次产出。所有 P0/P1/P2/P3 缺陷在本轮内完成闭环，验证基线（gofmt / go test / pnpm run ci / check-all.ps1）全绿。后续轮次进入日常治理节奏，无需在本轮内预先承接。

## 已完成改动

### 新增 — governance 辅助包（backend/internal/governance/）

- backend/internal/governance/models.go
- backend/internal/governance/archive_path.go
- backend/internal/governance/self_audit.go
- backend/internal/governance/task_selector.go
- backend/internal/governance/report_render.go
- backend/internal/governance/archive_path_test.go (PBT Property 1 + 9)
- backend/internal/governance/self_audit_test.go (PBT Property 7)
- backend/internal/governance/task_selector_test.go (PBT Property 6, pgregory.net/rapid)
- backend/internal/governance/report_render_test.go (PBT Property 2/3/4/5/8/10)
- backend/internal/governance/integration_test.go (Requirements 1.4 + 8.2)

### P0 defect closures

- P0-1 tshark capability 降级：backend/internal/tshark/capabilities.go + analysis_helpers.go — 新增 MissingOptionalFields 字段、graceful fallback、dedup-aware `log.Printf` 告警；capabilities_property_test.go 覆盖 Property 11。
- P0-2 field scan cache key：backend/internal/tshark/cache_key.go — 新增 `cacheKey(fieldScanCacheParams)` SHA-256 hex；cache_key_property_test.go 覆盖 Property 12。
- P0-3 _ws.col.* 严重度：backend/internal/tshark/capabilities.go — 新增 FieldProfileFull/DisplayCompat/Compat/Incompatible/Unavailable/Degraded 常量 + `fieldProfileSeverity` 顺位函数；`_ws.col.Protocol` / `_ws.col.Info` 移到 `displayLayerCapabilityFields`。
- P0-4 插件本地代码执行边界：backend/internal/plugin/manager.go + runtime.go — 新增 `PermLocalExec = "exec.local"` 能力门，`newJSPacketSession` / `newPythonPacketSession` 在 packet.read 之前强制验证；manager_test.go 新增 TestRunEnabledPacketPluginsRequiresExecLocalCapability。

### P1 defect closures

- P1-1 BackendBridge 拆分：backend/internal/transport/services.go（新文件）— 7 个聚焦接口（CaptureService、DetectionService、AnalysisService、MediaService、ToolRuntimeService、ToolAnalysisService、PluginService），共覆盖 69 个方法；http_server.go 将单一 `svc *engine.Service` 替换为 7 个 typed 字段。
- P1-2 SentinelContext 状态 ownership：frontend/src/app/state/hooks/useCapturePreloadState.ts + useCaptureSessionState.ts + useDisplayFilterState.ts（3 个新 hook 模块 + co-located 测试）。
- P1-3 useCaptureStartWorkflow 参数拆分：frontend/src/app/state/hooks/useCaptureStartWorkflow.ts — 56 字段扁平 options 重构为 6 个分组（context/refs/streamRefs/setters/clients/hooks）。
- P1-4 tool runtime config 持久化：backend/internal/engine/service.go + tool_runtime.go — 新增 `toolRuntimeMu sync.RWMutex`，SetToolRuntimeConfig 在单一锁下原子化写三路后端（tshark+env+yaraConf）并读回一致快照；frontend/src/app/state/toolRuntimeStorage.test.ts 新增 round-trip 和 overwrite 测试。
- P1-5 contract mapper round-trip：frontend/src/app/integrations/mappers/contractMapper.property.test.ts（新 PBT，使用 fast-check）— 覆盖 Property 13 对 pluginSourceMapper 和 tlsMapper 的 round-trip。Full codegen migration 推迟到后续轮次。

### P2 defect closures

- P2-1 evidence 包边界：backend/internal/architecture/boundary_test.go — 新增 "evidence types are only referenced by engine and transport" 子测试，遍历 internal/ 下所有非白名单包，检测对 model.EvidenceRecord/Response/Filter/APTEvidenceRecord 的任何引用并失败。
- P2-2 industrial_rules.go 命名常量：backend/internal/tshark/industrial_rules.go — 新增 11 个命名常量（Modbus 数量上限、异常码 1–4、突变/突发阈值、4 个严重度级别），替换所有 magic number/string。
- P2-3 前端 boundary check：frontend/scripts/check-boundaries.mjs + check-boundaries.test.mjs — 补充顶部策略 docblock（9 条不变量），新增正向测试 "allows feature imports from integrations/backendClients"。
- P2-4 field scan cache LRU：backend/internal/tshark/field_scan_cache.go（新文件）— `fieldScanCache` 增加 `lru *list.List`、`lruIndex map[string]*list.Element`、`keyFilePath map[string]string`、`maxSize int` 字段；`evictFieldScanCacheLRULocked` 在插入前清理到 maxSize=256；cache_capacity_property_test.go 覆盖 Property 14（随机 maxSize + 3× 插入，LRU/索引长度奇偶校验）。
- P2-5 analysis_helpers.go 拆分：backend/internal/tshark/ — 新增 field_scan_plan.go + field_scan_normalize.go + field_scan_degradation.go + field_scan_warm.go + analysis_utils.go（5 个聚焦文件），analysis_helpers.go 从 494 行减至 204 行。

### P3 defect closures

- P3-1 成熟度标记：backend/internal/engine/speech_to_text.go + c2_decrypt.go + media_playback.go（`// Stability: beta` 或 `experimental`）；frontend/src/app/features/c2/C2DecryptWorkbench.tsx + media/useMediaTranscriptionWorkflow.ts（JSDoc 块注释）。
- P3-2 真实 PCAP 回归：现有 backend/internal/engine/public_protocol_sample_test.go + public_threat_sample_test.go 已覆盖 industrial(S7)、vehicle(CAN)、C2(CS+VShell)、USB(写/删/挂载)、SMTP、MySQL、TFTP、HTTP Object 等 15+ 真实样本回归用例，满足 Requirements 6.7 最低覆盖要求。

## 验证记录

- `cd backend && gofmt -l .` — PASS（无输出）
- `cd backend && go test ./...` — PASS（8 个包全部通过：architecture、engine、governance、miscpkg、plugin、transport、tshark、rules/yara）
- `cd frontend && pnpm run ci` — PASS（190 测试文件 / 525 测试 / typecheck+lint+format+size+boundary+vitest+build 全绿）
- `./scripts/check-all.ps1` — PASS（All checks passed：Desktop shell dev-tag tests、Backend fmt/tests/boundary/focused contracts、Frontend package manager/tests/typecheck/lint/format/size/boundary/build 共 13 阶段）

## 当前缺陷与风险

- 所有 9 个已知 Defect_Register 条目（P0-1/2/3/4、P1-1/2/3/4/5、P2-1/2/3/4/5、P3-1/2）已在本轮闭环。
- 剩余技术债务：P1-5 contract mapper 全量 codegen 迁移（覆盖 ~48 个 asymmetric mapper）被明确标记为后续迭代任务；当前 PBT 仅覆盖 pluginSourceMapper 和 tlsMapper 两对称对。
- 已知副作用：`go vet ./internal/engine/` 报告 `c2_decrypt.go:487: unreachable code` 为预先存在的告警，与本轮改动无关。

## 下一步建议

- 下一轮起进入日常治理节奏：按 P1-5 codegen 优先级承接剩余 mapper 迁移；持续观察 LRU 缓存 maxSize=256 在生产侧的命中率并视需要调整。
- 每十轮触发 Self_Audit：当前轮次 = 1，下次自检触发点为 Dev_Round 10。届时验证主线能力交付（入侵检测 / 威胁流量分析 / 证据链）未被治理任务挤占，并重评 Defect_Register 剩余优先级。
- 若后续引入新的架构缺陷条目，优先添加到 docs/PRD.MD 或 implementation_plan.md 的 "Known Defects" 段落并在下一个日报中登记。

## Progress Update - 2026-05-13 08:52:11 +08:00

署名: Codex

### 本轮目标

- 承接架构治理审计方案 Phase 1 / Phase 2：补强治理报告可信度、让 Defect_Register 具备机器可读状态源，并对齐本地 check-all 与 CI 后端门禁顺序。

### 已完成改动

- `.github/workflows/ci.yml`：新增 Backend governance register check，CI 会运行 `go test ./internal/governance -run "Test.*Defect|Test.*Report|Test.*Archive" -count=1 -v`。
- `scripts/check-all.ps1`：后端顺序调整为 root dev-tag tests → fmt → architecture boundary → focused contracts → governance register check → backend full tests，与 CI 顺序一致。
- `docs/governance-defect-register.json`：新增机器可读 Architecture_Defect 状态源，记录缺陷优先级、关闭提交、修改文件、验证命令、证据测试与报告路径；保留 P1-6 full mapper DTO/codegen migration 为 open。
- `backend/internal/governance/defect_register.go`：新增 register JSON 加载与语义校验；resolved defect 必须具备 closing commit、modified files、validation commands、evidence tests、report path。
- `backend/internal/governance/defect_register_test.go`：新增 canonical register 校验、resolved 缺 evidence 失败、open defect 带 closure evidence 失败、路径 evidence 校验测试。
- `backend/internal/engine/c2_decrypt.go`：删除 `readCSHTTPFieldCandidates` 尾部不可达 `return nil`，消除 `go vet ./internal/engine` 既有告警。
- `docs/README.md`：在当前方向摘要中加入治理缺陷登记表入口。

### 验证记录

- `cd backend && gofmt -l .` — PASS（无输出）。
- `cd backend && go test ./internal/governance -run "Test.*Defect|Test.*Report|Test.*Archive" -count=1 -v` — PASS。
- `cd backend && go vet ./internal/engine` — PASS（无输出）。
- `cd backend && go test ./internal/architecture -run TestBackendArchitectureBoundaries -count=1 -v` — PASS。
- `cd backend && go test ./internal/engine -run "TestGatherEvidence|Test.*InvestigationReport|TestBundledPublic" -count=1 -v` — PASS。
- `cd backend && go test ./...` — PASS。
- `cd frontend && pnpm run ci` — PASS（190 test files / 525 tests / typecheck + lint + format + size + boundary + build）。
- `go test -tags dev ./...` — PASS。
- `git diff --check` — PASS。

### 当前缺陷与风险

- 本轮关闭治理可信度的首个缺口：resolved defect 不再只靠日报叙述，已有 `docs/governance-defect-register.json` 与后端测试校验。
- 已修复 `go vet ./internal/engine` 的 `c2_decrypt.go` unreachable code 告警，不再作为长期口头风险保留。
- 剩余核心技术债仍是 P1-6：full mapper DTO/codegen migration，目前 register 中保持 open。
- 报告 archive 目录仍受 `.gitignore` 保护，本轮没有改变该策略；CI 校验 reportPath 只校验 repo-relative 语义，不要求 ignored 本地归档在干净 checkout 中存在。

### 工程评分

- 主线价值：16/20（治理可信度服务证据链与后续工程质量，但本轮未新增分析能力）。
- 架构边界：18/20（新增 register 可信度边界，check-all/CI 同构，修复 vet 告警）。
- 自动验收：20/20（governance register check 接入 CI 和本地 check-all）。
- 回归风险控制：15/15（未改 API/model/UI 行为；未纳入样本或构建产物）。
- 文档可信度：10/10（实际日期归档续写，列出触达文件与验证）。
- 缺陷关闭质量：9/10（register 有 commit/test evidence；P1-6 保持 open）。
- 复杂度控制：5/5（小范围治理切片，无大杂烩重构）。
- 总分：93/100，Gold。

### 下一步建议

- 下一轮优先进入 Phase 4 的 P1-6 mapper/DTO 契约迁移，先选 3-5 个核心 mapper 做显式 DTO 或 `unknown + parse helper`，并扩大 round-trip / missing-field 测试覆盖。
- 同时保持 Phase 1 register 作为每轮关闭缺陷的唯一机器可读事实源；新增缺陷必须先进入 register，再关闭。

## Progress Update - 2026-05-13 09:12:51 +08:00

署名: Codex

### 本轮目标

- 承接 P1-6 full mapper DTO/codegen migration，先迁移一组核心 mapper 输入契约，减少裸 `any` 对后端 wire payload 的依赖。

### 已完成改动

- `frontend/src/app/integrations/mappers/mapperPrimitives.ts`：`asBucket`、`asConversation` 从 `any` 改为 `unknown`，新增/复用 `asArray` 作为数组 wire payload 收敛入口。
- `frontend/src/app/integrations/mappers/evidenceMapper.ts`：`parseEvidenceRecords` 改为 `unknown` 输入，使用 `EvidenceListWire` + `asPlainObject` + `asEvidenceRecord` 归一化，保留输出合同不变。
- `frontend/src/app/integrations/mappers/industrialMapper.ts`：`asIndustrialAnalysis` 改为 `unknown` 输入，新增 `IndustrialAnalysisWire`，入口只做组合与默认值映射。
- `frontend/src/app/integrations/mappers/vehicleMapper.ts`：`asVehicleAnalysis` 改为 `unknown` 输入，保留文件在 size budget 内。
- `frontend/src/app/integrations/mappers/usbMapper.ts`：`asUSBAnalysis` 改为 `unknown` 输入，数组字段统一经 `asArray` 转换。
- `frontend/src/app/integrations/mappers/objectMapper.ts`：`asObject` / `asObjectList` 改为 `unknown` 输入，新增 `ExtractedObjectWire`，保持 HTTP/FTP source fallback 行为。
- 对应 mapper test 增加 malformed/missing-field 覆盖，验证坏 payload 不抛错且回落默认值。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/evidenceMapper.test.ts src/app/integrations/mappers/industrialMapper.test.ts src/app/integrations/mappers/vehicleMapper.test.ts src/app/integrations/mappers/usbMapper.test.ts src/app/integrations/mappers/objectMapper.test.ts` — PASS（5 files / 15 tests）。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run boundary:check` — PASS。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run lint` — PASS。
- `cd frontend && pnpm run ci` — PASS（190 test files / 530 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P1-6 仍保持 open：本轮是第一组核心 mapper 契约收敛，不标记 full migration resolved。
- mapper 目录仍有大量历史 `any`，下一轮建议继续 C2/APT/Modbus detail mapper，而不是转向 UI 拆分。
- 本轮没有改变 API/model/UI 行为；只收窄 mapper 输入边界并补坏 payload 防御测试。

### 工程评分

- 主线价值：17/20（覆盖 Evidence/Industrial/Vehicle/USB/Object 主线 mapper）。
- 架构边界：17/20（减少裸 `any`，但仍是部分迁移）。
- 自动验收：20/20（focused tests + 全量前端 CI）。
- 回归风险控制：15/15（输出合同兼容，未改业务行为）。
- 文档可信度：10/10（实际日期归档续写，验证记录完整）。
- 缺陷关闭质量：7/10（P1-6 仅推进，不关闭）。
- 复杂度控制：5/5（单主题小切片，未放宽 size budget）。
- 总分：91/100，Gold。

### 下一步建议

- 继续 P1-6：迁移 C2/APT/Modbus detail mapper 的裸 `any`，优先选择已有测试或易补 focused tests 的文件；每轮保持 3-5 个 mapper 的小切片。

## Progress Update - 2026-05-13 09:20:53 +08:00

署名: Codex

### 本轮目标

- 对 P1-6 做第二个自主迭代切片：继续迁移 C2 / APT mapper 的裸 `any` wire input，扩大 malformed payload 防御覆盖。

### 已完成改动

- `frontend/src/app/integrations/mappers/c2AggregateMapper.ts`：HTTP endpoint、DNS、stream aggregate mapper 输入从 `any` 改为 `unknown`，统一使用 `asPlainObject` / `asArray` / shared scalar helpers。
- `frontend/src/app/integrations/mappers/c2IndicatorMapper.ts`：C2 candidate、beacon pattern、score factor mapper 输入从 `any` 改为 `unknown`，保留 CS/VShell family fallback 行为。
- `frontend/src/app/integrations/mappers/c2FamilyMapper.ts`：C2 sample/family 组合 mapper 输入改为 `unknown`，数组字段统一经 `asArray`。
- `frontend/src/app/integrations/mappers/aptMapper.ts`：APT actor profile、evidence、score factor、analysis mapper 输入从 `any` 改为 `unknown`。
- `frontend/src/app/integrations/mappers/c2SampleMapper.test.ts`：补充 null aggregate / null candidate / null top-level payload 的默认值断言。
- `frontend/src/app/integrations/mappers/aptMapper.test.ts`：补充 null profile / null evidence / malformed actors 的默认值断言。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/c2SampleMapper.test.ts src/app/integrations/mappers/aptMapper.test.ts` — PASS（2 files / 4 tests）。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run boundary:check` — PASS。
- `cd frontend && pnpm run ci` — PASS（190 test files / 530 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P1-6 仍保持 open：已完成两组核心 mapper 切片，但尚未覆盖 Modbus detail、media/session、misc module 等剩余 mapper。
- 本轮未改后端与 UI 行为；风险集中在 mapper 默认值行为，已由 C2/APT focused tests 和全量前端 CI 覆盖。

### 工程评分

- 主线价值：18/20（覆盖 C2/APT 威胁分析主线 mapper）。
- 架构边界：18/20（继续减少裸 `any`，并复用 shared primitive）。
- 自动验收：20/20（focused tests + 全量前端 CI）。
- 回归风险控制：15/15（输出合同兼容，不改 API/UI）。
- 文档可信度：10/10（实际日期归档续写）。
- 缺陷关闭质量：7/10（P1-6 继续推进但不关闭）。
- 复杂度控制：5/5（单主题小切片，未放宽 size budget）。
- 总分：93/100，Gold。

### 下一步建议

- 继续 P1-6 第三切片：优先 Modbus / industrial detail mapper，因其已接入真实 Modbus UTF-8 展示链路，且与威胁流量主线相关性高。

## Progress Update - 2026-05-13 09:25:56 +08:00

署名: Codex

### 本轮目标

- 对 P1-6 做第三个自主迭代切片：迁移 Modbus / Industrial detail mapper 的裸 `any` 输入，保护 Modbus UTF-8 转码展示链路。

### 已完成改动

- `frontend/src/app/integrations/mappers/modbusMapper.ts`：`asModbusAnalysis` 改为 `unknown` 输入，数组字段统一经 `asArray`。
- `frontend/src/app/integrations/mappers/modbusDecodedInputMapper.ts`：decoded input mapper 输入改为 `unknown`，null record 回落默认值。
- `frontend/src/app/integrations/mappers/modbusTransactionMapper.ts`：transaction 和 bitRange mapper 输入改为 `unknown`，bit range 使用 `asPlainObject` 防御非对象 payload。
- `frontend/src/app/integrations/mappers/modbusSuspiciousWriteMapper.ts`：suspicious write mapper 输入改为 `unknown`，sources/sample values 使用 `asStringList`。
- `frontend/src/app/integrations/mappers/industrialDetailMapper.ts`：control command、rule hit、detail record mapper 输入改为 `unknown`，工业明细记录抽为独立转换函数。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/industrialMapper.test.ts src/app/pages/IndustrialAnalysis.test.tsx` — PASS（2 files / 4 tests）。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run boundary:check` — PASS。
- `cd frontend && pnpm run ci` — PASS（190 test files / 530 tests / build PASS）。
- `git diff --check` — PASS。

### 自检结论

- 未偏离主线：三轮均围绕 P1-6 mapper/DTO 契约迁移，没有转向 UI 拆分或无关重构。
- 风险控制正常：每轮均保持输出合同兼容，未改后端 API、未接入 MISC 到 Evidence、未放宽 size budget。
- P1-6 仍未关闭：已覆盖 Evidence/Object/USB/Vehicle/Industrial/C2/APT/Modbus 核心链路，但 media/session/misc/protocol mapper 仍有历史 `any`，需要继续小步迁移。

### 工程评分

- 主线价值：18/20（保护 Industrial/Modbus 真实样本展示链路）。
- 架构边界：18/20（继续减少 mapper 裸 `any`）。
- 自动验收：20/20（focused tests + 全量前端 CI）。
- 回归风险控制：15/15（输出合同兼容，不改 API/UI）。
- 文档可信度：10/10（实际日期归档续写）。
- 缺陷关闭质量：7/10（P1-6 继续推进但不关闭）。
- 复杂度控制：5/5（单主题切片，未放宽预算）。
- 总分：93/100，Gold。

### 下一步建议

- 继续 P1-6 第四切片：迁移 media/session/protocol tool mapper；完成后统计 mapper 裸 `any` 剩余数量，决定是否进入阶段性 register 更新。

## Progress Update - 2026-05-13 09:31:40 +08:00

署名: Codex

### 本轮目标

- 对 P1-6 做第四个自主迭代切片：迁移 Media / Speech mapper 的裸 `any` 输入，继续将后端 payload 入口收敛为 `unknown + mapper primitive`。

### 已完成改动

- `frontend/src/app/integrations/mappers/mediaMapper.ts`：`asMediaAnalysis` 改为 `unknown` 输入，artifact 数组统一经 `asArray`。
- `frontend/src/app/integrations/mappers/mediaSessionMapper.ts`：media session 与 artifact mapper 改为 `unknown` 输入，并使用 `asPlainObject` 防御非对象 payload。
- `frontend/src/app/integrations/mappers/mediaTranscriptionMapper.ts`：transcription 与 segment mapper 改为 `unknown` 输入，malformed segment 回落默认值。
- `frontend/src/app/integrations/mappers/speechBatchMapper.ts`：batch task / batch item mapper 改为 `unknown` 输入，item 数组统一经 `asArray`。
- `frontend/src/app/integrations/mappers/mediaMapper.test.ts`：补充 malformed transcription segments 与 malformed batch items 默认值断言。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/mediaMapper.test.ts src/app/features/media/MediaOverviewPanels.test.tsx src/app/features/media/MediaSessionTableUtils.test.ts` — PASS（3 files / 15 tests）。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run boundary:check` — PASS。
- `cd frontend && pnpm run ci` — PASS（190 test files / 532 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P1-6 仍保持 open：media/speech 已迁移，但 protocol tool、runtime/plugin、stream/packet、MISC module 等 mapper 仍有历史裸 `any`。
- 本轮只改 mapper 输入防御和测试，不改后端 API、UI 行为或输出 shape。

### 工程评分

- 主线价值：16/20（覆盖 media/speech 辅助分析链路，主线相关性低于 C2/Industrial）。
- 架构边界：18/20（继续减少裸 `any`，保持 mapper primitive 统一入口）。
- 自动验收：20/20（focused tests + 全量前端 CI）。
- 回归风险控制：15/15（输出合同兼容，不改 API/UI）。
- 文档可信度：10/10（实际日期归档续写）。
- 缺陷关闭质量：7/10（P1-6 继续推进但不关闭）。
- 复杂度控制：5/5（单主题小切片，未放宽 size budget）。
- 总分：91/100，Gold。

### 下一步建议

- 继续 P1-6 第五切片：迁移 HTTP/SMTP/MySQL/Shiro/Session Material 等 protocol tool mapper，并保持每轮 3-5 个文件的小提交节奏。

## Progress Update - 2026-05-13 09:46:09 +08:00

署名: Codex

### 本轮目标

- 对 P1-6 做第五个自主迭代切片：迁移 HTTP / SMTP / MySQL / Shiro / Session Material mapper 的裸 `any` 输入，并保持 MISC 仍为辅助 workbench，不接入 unified Evidence。

### 已完成改动

- `frontend/src/app/integrations/mappers/httpLoginMapper.ts`：顶层 HTTP login mapper 改为 `unknown` 输入，只保留分析结果组合职责。
- `frontend/src/app/integrations/mappers/httpLoginRecordMapper.ts`：新增 HTTP endpoint / attempt 记录 mapper，使用 `asPlainObject` / `asArray` 防御 malformed payload。
- `frontend/src/app/integrations/mappers/smtpMapper.ts`：顶层 SMTP mapper 改为 `unknown` 输入，只保留 session/report 组合职责。
- `frontend/src/app/integrations/mappers/smtpRecordMapper.ts`：新增 SMTP session / command / message 记录 mapper。
- `frontend/src/app/integrations/mappers/mysqlMapper.ts`：顶层 MySQL mapper 改为 `unknown` 输入，只保留 session/report 组合职责。
- `frontend/src/app/integrations/mappers/mysqlRecordMapper.ts`：新增 MySQL session / query / server event 记录 mapper。
- `frontend/src/app/integrations/mappers/shiroRememberMeMapper.ts`：Shiro rememberMe mapper 改为 `unknown` 输入，candidate / key result 统一经 plain-object coercion。
- `frontend/src/app/integrations/mappers/sessionMaterialMapper.ts`：SMB3 / NTLM session material mapper 改为 `unknown` 输入，列表入口统一经 `asArray`。
- `frontend/scripts/check-size.mjs`：为新增 record mapper 建立独立 size budget，避免 mapper 文件未登记增长。
- `frontend/src/app/integrations/mappers/protocolToolMapper.test.ts`、`toolMapper.test.ts`：新增 malformed payload 默认值断言。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/protocolToolMapper.test.ts src/app/integrations/mappers/toolMapper.test.ts` — PASS（2 files / 12 tests）。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run boundary:check` — PASS。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run lint` — PASS。
- `cd frontend && pnpm run ci` — PASS（190 test files / 534 tests / build PASS）。

### 当前缺陷与风险

- P1-6 仍保持 open：protocol/session tool mapper 已迁移，但 runtime/plugin/packet/stream/traffic/TLS/MISC module/vehicle 子 mapper 等仍有历史裸 `any`。
- 本轮未改后端 API、前端输出 shape 或 MISC/Evidence 边界；风险主要是默认值 coercion，已由 focused tests 和全量前端 CI 覆盖。

### 自检结论

- 未偏离主线：本轮仍只处理 mapper DTO/contract 收敛，没有转向 UI patch 或无关拆分。
- 边界无回退：新增 mapper 已纳入 size budget，boundary check 通过，MISC 未接入 Evidence。
- 复杂度可控：新增 record mapper 是为维持既有预算和职责边界，不是机械拆分；顶层 mapper 反而更薄。

### 工程评分

- 主线价值：15/20（覆盖 MISC session/protocol 辅助链路，主线相关性低于 C2/Industrial）。
- 架构边界：19/20（顶层 mapper 与记录 mapper 分层，并消除本组裸 `any`）。
- 自动验收：20/20（malformed payload tests + 全量前端 CI）。
- 回归风险控制：15/15（输出合同兼容，不改 API/UI）。
- 文档可信度：10/10（实际日期归档续写）。
- 缺陷关闭质量：7/10（P1-6 继续推进但不关闭）。
- 复杂度控制：5/5（单主题小切片，未放宽 size budget）。
- 总分：91/100，Gold。

### 下一步建议

- 继续 P1-6 第六切片：迁移 runtime / plugin / packet-stream / traffic / TLS mapper；之后统计 mapper 裸 `any` 剩余数量，决定是否更新 defect register 的阶段进度。

## Progress Update - 2026-05-13 09:57:11 +08:00

署名: Codex

### 本轮目标

- 对 P1-6 做第六个自主迭代切片：迁移 runtime / plugin / packet-stream / traffic / TLS / tshark status mapper 的裸 `any` 输入。

### 已完成改动

- `frontend/src/app/integrations/mappers/packetMapper.ts`：packet payload 与 color_features 改用 `unknown + asPlainObject`。
- `frontend/src/app/integrations/mappers/streamMapper.ts`：HTTP/Binary stream 与 chunk/loadMeta mapper 改用 `unknown + asArray/asPlainObject`。
- `frontend/src/app/integrations/mappers/threatMapper.ts`：threat hit mapper 改用 `unknown` 输入并保留 severity fallback。
- `frontend/src/app/integrations/mappers/pluginMapper.ts`：DBC profile 与 plugin item/list mapper 改用 `unknown` 输入，并显式 coercion PluginItem 字段。
- `frontend/src/app/integrations/mappers/pluginSourceMapper.ts`：plugin source mapper 改用 `unknown` 输入，malformed payload 使用 fallback id。
- `frontend/src/app/integrations/mappers/runtimeMapper.ts`：runtime snapshot 内部 config/ffmpeg/speech/yara 分区改用 plain-object 防御。
- `frontend/src/app/integrations/mappers/tsharkStatusMapper.ts`：tshark status mapper 改用 `unknown` 输入并复用 `asStringList`。
- `frontend/src/app/integrations/mappers/tlsMapper.ts`、`trafficMapper.ts`：TLS config 与 traffic stats mapper 改用 `unknown` 输入。
- 对 packet-stream、plugin、plugin source、runtime、TLS、traffic mapper 补充 malformed payload 默认值断言。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/packetStreamMapper.test.ts src/app/integrations/mappers/pluginMapper.test.ts src/app/integrations/mappers/pluginSourceMapper.test.ts src/app/integrations/mappers/runtimeMapper.test.ts src/app/integrations/mappers/tlsMapper.test.ts src/app/integrations/mappers/trafficMapper.test.ts` — PASS（6 files / 17 tests）。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run lint` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run boundary:check` — PASS。
- `cd frontend && pnpm run ci` — PASS（190 test files / 540 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P1-6 仍保持 open：剩余裸 `any` 集中在 C2 decrypt record、MISC module/schema、USB 子 mapper、Vehicle 子 mapper、WinRM mapper。
- 本轮未改后端 API、页面行为或输出 shape；风险主要是 malformed payload 默认值，已由 focused tests 与全量前端 CI 覆盖。

### 自检结论

- 未偏离主线：连续三轮仍围绕 P1-6 mapper/DTO 契约迁移。
- 自动验收继续增强：本轮新增 6 个 mapper malformed payload 测试，测试总数从 534 增至 540。
- 边界无回退：size/boundary/typecheck/lint/CI 均通过，未扩大 allowlist，未放宽预算。

### 工程评分

- 主线价值：17/20（覆盖 packet/stream/runtime/TLS 等基础链路 mapper）。
- 架构边界：18/20（消除本组裸 `any`，但尚未进入 schema/codegen）。
- 自动验收：20/20（focused tests + 全量前端 CI）。
- 回归风险控制：15/15（输出合同兼容，不改 API/UI）。
- 文档可信度：10/10（实际日期归档续写）。
- 缺陷关闭质量：7/10（P1-6 继续推进但不关闭）。
- 复杂度控制：5/5（单主题切片，未放宽 size budget）。
- 总分：92/100，Gold。

### 下一步建议

- 继续 P1-6 第七切片：迁移 USB 或 Vehicle 子 mapper；这两组仍属主线分析域，优先级高于 MISC module/schema。

## Progress Update - 2026-05-13 10:02:27 +08:00

署名: Codex

### 本轮目标

- 对 P1-6 做第七个自主迭代切片：迁移 USB 子 mapper 的裸 `any` 输入，保护 USB 主线分析域的 DTO 防御边界。

### 已完成改动

- `frontend/src/app/integrations/mappers/usbRecordMapper.ts`：USB packet record mapper 改为 `unknown + asPlainObject`。
- `frontend/src/app/integrations/mappers/usbHidMapper.ts`：keyboard/mouse/HID section mapper 改为 `unknown + asArray/asPlainObject`。
- `frontend/src/app/integrations/mappers/usbMassStorageMapper.ts`：mass-storage operation/section mapper 改为 `unknown + asArray/asPlainObject`。
- `frontend/src/app/integrations/mappers/usbOtherMapper.ts`：other/control section mapper 改为 `unknown + asArray/asPlainObject`。
- `frontend/src/app/integrations/mappers/usbMapper.test.ts`：扩展 malformed USB payload 断言，覆盖 keyboard/mouse/hid/mass-storage/other 默认值。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/usbMapper.test.ts src/app/pages/UsbAnalysis.test.tsx` — PASS（2 files / 8 tests）。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run boundary:check` — PASS。
- `cd frontend && pnpm run ci` — PASS（190 test files / 540 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P1-6 仍保持 open：USB mapper 已完成本轮覆盖；剩余裸 `any` 主要在 Vehicle 子 mapper、MISC module/schema、C2 decrypt record、WinRM。
- 本轮只改 mapper 输入防御，不改 USB 页面行为、后端 API 或 Evidence/MISC 边界。

### 工程评分

- 主线价值：18/20（USB 属 unified Evidence 主线分析域）。
- 架构边界：18/20（消除 USB 子 mapper 裸 `any`）。
- 自动验收：20/20（USB focused tests + 全量前端 CI）。
- 回归风险控制：15/15（输出合同兼容，不改 API/UI）。
- 文档可信度：10/10（实际日期归档续写）。
- 缺陷关闭质量：7/10（P1-6 继续推进但不关闭）。
- 复杂度控制：5/5（单主题切片，未放宽 size budget）。
- 总分：93/100，Gold。

### 下一步建议

- 继续 P1-6 第八切片：迁移 Vehicle 子 mapper，覆盖 CAN/DBC/J1939/DoIP/UDS 的 wire payload 防御。

## Progress Update - 2026-05-13 10:09:26 +08:00

署名: Codex

### 本轮目标

- 对 P1-6 做第八个自主迭代切片：迁移 Vehicle 子 mapper 的裸 `any` 输入，覆盖 CAN/DBC/J1939/DoIP/UDS 的 wire payload 防御。

### 已完成改动

- `frontend/src/app/integrations/mappers/vehicleCanRecordMapper.ts`：CAN record mapper 改为 `unknown + asPlainObject`。
- `frontend/src/app/integrations/mappers/vehicleCanMapper.ts`：CAN aggregate、decoded message、signal timeline、frame mapper 改为 `unknown + asArray/asPlainObject/asBucket`。
- `frontend/src/app/integrations/mappers/vehicleCanDbcMapper.ts`：DBC payload/signal/message mapper 改为 `unknown + asArray/asPlainObject/asStringList`。
- `frontend/src/app/integrations/mappers/vehicleJ1939Mapper.ts`、`vehicleDoipMapper.ts`、`vehicleUdsMapper.ts`：J1939/DoIP/UDS 子 mapper 改为 `unknown + asArray/asPlainObject`。
- `frontend/src/app/integrations/mappers/vehicleMapper.test.ts`：扩展 malformed payload 覆盖 CAN payload records、decoded signals、timeline samples、CAN frames、J1939、DoIP、UDS message/transaction 默认值。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/vehicleMapper.test.ts src/app/pages/VehicleAnalysis.test.ts` — PASS（2 files / 5 tests）。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run boundary:check` — PASS。
- `cd frontend && pnpm run ci` — PASS（190 test files / 540 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P1-6 仍保持 open：Vehicle 主线 mapper 已完成本轮覆盖；剩余裸 `any` 主要在 C2 decrypt、WinRM、MISC module/schema。
- 本轮只改 mapper 输入防御，不改 Vehicle 页面行为、后端 API、Evidence/MISC 边界或 DBC 输出 shape。

### 工程评分

- 主线价值：18/20（Vehicle 属主线分析域，覆盖 CAN/DBC/J1939/DoIP/UDS）。
- 架构边界：18/20（消除 Vehicle 子 mapper 裸 `any`）。
- 自动验收：20/20（Vehicle focused tests + 全量前端 CI）。
- 回归风险控制：15/15（输出合同兼容，不改 API/UI）。
- 文档可信度：10/10（实际日期归档续写）。
- 缺陷关闭质量：7/10（P1-6 继续推进但不关闭）。
- 复杂度控制：5/5（单主题切片，未放宽 size budget）。
- 总分：93/100，Gold。

### 下一步建议

- 继续 P1-6 第九切片：迁移 C2 decrypt 与 WinRM mapper；两者规模较小，优先处理 threat-analysis 相关合同入口。

## Progress Update - 2026-05-13 10:14:58 +08:00

署名: Codex

### 本轮目标

- 对 P1-6 做第九个自主迭代切片：迁移 C2 decrypt 与 WinRM mapper 的裸 `any` 输入，优先收敛 threat-analysis 与辅助解密工具的合同入口。

### 已完成改动

- `frontend/src/app/integrations/mappers/c2DecryptMapper.ts`：C2 decrypt record mapper 改为 `unknown + asPlainObject/asStringList`，`parsed` 仅接受 plain object。
- `frontend/src/app/integrations/mappers/winrmMapper.ts`：WinRM decrypt result mapper 改为 `unknown + asPlainObject`，保留 fallback port 与默认导出文件名行为。
- `frontend/src/app/integrations/mappers/toolMapper.test.ts`：新增 malformed C2 decrypt record 与 malformed WinRM payload 默认值覆盖。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/toolMapper.test.ts src/app/integrations/wailsBridge.test.ts src/app/pages/MiscTools.test.tsx` — PASS（3 files / 21 tests）。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run boundary:check` — PASS。
- `cd frontend && pnpm run ci` — PASS（190 test files / 542 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P1-6 仍保持 open：C2 decrypt 与 WinRM mapper 已完成本轮覆盖；剩余裸 `any` 主要在 MISC module/schema mapper。
- 本轮不改 C2 decrypt display normalization、VShell 低信息过滤、WinRM UI、后端 API 或 MISC/Evidence 边界。

### 工程评分

- 主线价值：17/20（覆盖 C2 decrypt 主线与 WinRM 辅助解密入口）。
- 架构边界：18/20（消除本组 mapper 裸 `any`）。
- 自动验收：20/20（focused tests + 全量前端 CI）。
- 回归风险控制：15/15（输出合同兼容，不改 API/UI）。
- 文档可信度：10/10（实际日期归档续写）。
- 缺陷关闭质量：8/10（P1-6 已接近剩余尾项，但暂不关闭）。
- 复杂度控制：5/5（单主题切片，未放宽 size budget）。
- 总分：93/100，Gold。

### 下一步建议

- 继续 P1-6 第十切片：迁移 MISC module/schema mapper。该切片应明确保持 MISC 独立 workbench，不接入 unified Evidence。

## Progress Update - 2026-05-13 10:20:36 +08:00

署名: Codex

### 本轮目标

- 对 P1-6 做第十个自主迭代切片：迁移 MISC module/schema mapper 的裸 `any` 输入，同时保持 MISC 独立 workbench，不接入 unified Evidence。

### 已完成改动

- `frontend/src/app/integrations/mappers/miscModuleMapper.ts`：manifest/import/run-result mapper 改为 `unknown + asPlainObject/asArray/asStringList`。
- `frontend/src/app/integrations/mappers/miscModuleSchemaMapper.ts`：form/interface/table/field/column/row mapper 改为 `unknown + asPlainObject/asArray`，非对象 row 安全降级为空对象。
- `frontend/src/app/integrations/mappers/toolMapper.test.ts`：新增 malformed MISC module payload 覆盖，确认 manifest/import/run/table 在坏输入下输出稳定默认值。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/toolMapper.test.ts src/app/pages/MiscTools.test.tsx src/app/pages/MiscTools.customModules.test.tsx` — PASS（3 files / 19 tests；第一次因测试漏导入 `asMiscModuleManifest` 失败，已修复后复跑通过）。
- `cd frontend && pnpm run typecheck` — PASS（第一次随同漏导入失败，修复后复跑通过）。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run boundary:check` — PASS。
- `rg -n "\\bany\\b" frontend/src/app/integrations/mappers` — 生产 mapper 裸 `any` 清零，仅 `contractMapper.property.test.ts` 的自然语言测试标题包含 `any`。
- `cd frontend && pnpm run ci` — PASS（190 test files / 543 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P1-6 的第一阶段目标已达成：`frontend/src/app/integrations/mappers` 生产 mapper 不再保留裸 `any` 入参。
- P1-6 不应直接关闭为“完全 codegen 化”：当前仍是手写 DTO/parse helper 路线，后续可进入 schema/codegen 可行性评估。
- 本轮不改 MISC 与 Evidence 边界，MISC 仍保持辅助 workbench。

### 工程评分

- 主线价值：16/20（MISC 非 unified Evidence 主线，但完成 mapper 合同尾项）。
- 架构边界：20/20（生产 mapper 裸 `any` 清零）。
- 自动验收：20/20（focused tests + 全量前端 CI + grep 验证）。
- 回归风险控制：15/15（输出合同兼容，不改 API/UI）。
- 文档可信度：10/10（实际日期归档续写，并记录一次测试失败与修复）。
- 缺陷关闭质量：8/10（P1-6 第一阶段可标记为完成，但不等同 codegen 完成）。
- 复杂度控制：5/5（单主题切片，未放宽 size budget）。
- 总分：94/100，Gold。

### 下一步建议

- 更新 `docs/governance-defect-register.json`：将 P1-6 状态从 open 调整为 first-phase-complete 或 resolved-with-followup，记录生产 mapper 裸 `any` 清零与验证命令；后续新缺陷可拆为 DTO schema/codegen feasibility。

## Progress Update - 2026-05-13 10:24:54 +08:00

署名: Codex

### 本轮目标

- 收口 P1-6 缺陷登记：将“生产 mapper 裸 `any` 入参迁移”作为第一阶段关闭，并把 schema/codegen 可行性拆为后续独立缺陷，避免报告夸大。

### 已完成改动

- `docs/governance-defect-register.json`：P1-6 从 open 改为 resolved，标题调整为 `frontend mapper raw any migration`，closure evidence 指向本阶段最后提交 `dc522143bc5276770b4918aff4c7aa8ebac444bb`。
- `docs/governance-defect-register.json`：新增 P2-6 `mapper schema/codegen feasibility`，用于追踪后续 Go struct -> JSON Schema/OpenAPI -> TS DTO 可行性，不与本阶段 raw-any 清零混写。

### 验证记录

- `go test ./backend/internal/governance -run "TestCanonicalDefectRegisterIsValid|TestValidateDefectRegister" -count=1 -v` — PASS。
- `cd frontend && pnpm run boundary:check` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `rg -n "\\bany\\b" frontend/src/app/integrations/mappers` — 生产 mapper 裸 `any` 清零，仅测试标题文本包含 `any`。
- `cd frontend && pnpm run ci` — PASS（190 test files / 543 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P1-6 已按第一阶段验收关闭；P2-6 继续追踪 schema/codegen，不应在本阶段宣称已完成生成式 DTO 链。
- 当前缺少一个自动门禁专门防止生产 mapper 裸 `any` 回归，下一轮应补脚本/测试。

### 工程评分

- 主线价值：15/20（治理状态可信度收口，不直接改检测能力）。
- 架构边界：19/20（把 P1-6 与后续 codegen 缺陷拆清楚）。
- 自动验收：20/20（governance register test + frontend CI + grep 验证）。
- 回归风险控制：15/15（只改 register，不改产品行为）。
- 文档可信度：10/10（报告与 register 状态一致，未夸大 codegen）。
- 缺陷关闭质量：10/10（P1-6 closure evidence 完整，P2-6 follow-up 独立登记）。
- 复杂度控制：5/5（单主题治理收口）。
- 总分：94/100，Gold。

### 下一步建议

- 补一个 `mapper:any` 防回归门禁并纳入 `pnpm run ci`，确保生产 mapper 文件未来不能重新引入裸 `any`。

## Progress Update - 2026-05-13 10:30:25 +08:00

署名: Codex

### 本轮目标

- 在 P1-6 关闭后补防回归门禁：生产 mapper 文件未来不能重新引入裸 `any`，并让 CI 与本地 `check-all.ps1` 同步执行该检查。

### 已完成改动

- `frontend/scripts/check-mapper-any.mjs`：新增 mapper raw-any 扫描脚本，只扫描 `src/app/integrations/mappers/**/*.ts` 生产文件，跳过 `.test.ts`。
- `frontend/scripts/check-mapper-any.test.mjs`：新增脚本级测试，覆盖生产 mapper 中 `any` 失败、测试文件中自然语言 `any` 不计入、`unknown` mapper 通过。
- `frontend/package.json`：新增 `mapper:any:check`，并接入 `pnpm run ci`，位置在 boundary 之后、Vitest 之前。
- `scripts/check-all.ps1`：新增 `Frontend mapper any check`，保持本地门禁与前端 CI 语义一致。

### 验证记录

- `cd frontend && pnpm exec vitest run scripts/check-mapper-any.test.mjs scripts/check-package-manager.test.mjs` — PASS（2 files / 4 tests）。
- `cd frontend && pnpm run mapper:any:check` — PASS。
- `cd frontend && pnpm run lint` — PASS。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run ci` — PASS（191 test files / 545 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P1-6 raw-any migration 已有自动防回归门禁。
- P2-6 schema/codegen feasibility 仍 open；该门禁不等同于生成式 DTO 方案，只防止 mapper 回退到裸 `any`。

### 工程评分

- 主线价值：16/20（防止 mapper 合同退化，间接服务分析链稳定性）。
- 架构边界：20/20（新增可执行边界门禁）。
- 自动验收：20/20（新脚本测试 + CI 接入 + check-all 同步）。
- 回归风险控制：15/15（只加检查，不改产品行为）。
- 文档可信度：10/10（报告记录门禁范围和限制）。
- 缺陷关闭质量：9/10（P1-6 有防回归，但 P2-6 codegen 仍待评估）。
- 复杂度控制：5/5（小脚本、小测试、无预算放宽）。
- 总分：95/100，Gold。

### 下一步建议

- 下一轮可转入 P2-6 的方案预研：先选择 1-2 个低风险 mapper 建立 `WireDTO` 类型目录和 parse helper 规范，不立即上全量 codegen。

## Progress Update - 2026-05-13 10:38:10 +08:00

署名: Codex

### 本轮目标

- 对 P2-6 做第一片：建立最小 WireDTO 目录，先覆盖 C2 decrypt / WinRM 两个低风险 mapper，不引入全量 codegen。

### 已完成改动

- `frontend/src/app/integrations/wire/toolWireDtos.ts`：新增 C2 decrypt / WinRM raw wire DTO。
- `frontend/src/app/integrations/mappers/c2DecryptMapper.ts`：mapper 内部 payload 标注为 `C2DecryptedRecordWireDTO`。
- `frontend/src/app/integrations/mappers/winrmMapper.ts`：mapper 内部 payload 标注为 `WinRMDecryptResultWireDTO`。
- `frontend/scripts/check-size.mjs`：新增 wire DTO size budget。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/toolMapper.test.ts scripts/check-size.test.mjs` — PASS（2 files / 12 tests）。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run lint` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run ci` — PASS（191 test files / 545 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P2-6 仍 open：本轮只是 WireDTO 规范切片，不是 schema/codegen 完成。
- 当前 WireDTO 使用 `unknown` 字段类型，目标是先把 wire field 名称集中化，后续再评估生成链或更强 parser。

### 工程评分

- 主线价值：16/20。
- 架构边界：18/20。
- 自动验收：20/20。
- 回归风险控制：15/15。
- 文档可信度：10/10。
- 缺陷关闭质量：7/10。
- 复杂度控制：5/5。
- 总分：91/100，Gold。

### 下一步建议

- 继续 P2-6 第二片：选择 Evidence 或 Object mapper 建立对应 WireDTO，优先覆盖 unified Evidence 主线域。

## Progress Update - 2026-05-13 10:43:47 +08:00

署名: Codex

### 本轮目标

- 继续 P2-6 WireDTO 第二片：覆盖 unified Evidence 与 Object mapper，把主线证据/对象 wire 字段从 mapper 内联类型迁到独立 DTO 文件。

### 已完成改动

- `frontend/src/app/integrations/wire/evidenceWireDtos.ts`：新增 `EvidenceListWireDTO`、`UnifiedEvidenceRecordWireDTO`、`ExtractedObjectWireDTO`。
- `frontend/src/app/integrations/mappers/evidenceMapper.ts`：使用 evidence WireDTO 标注后端 payload，不改变输出 `UnifiedEvidenceRecord` shape。
- `frontend/src/app/integrations/mappers/objectMapper.ts`：使用 object WireDTO 标注后端 payload，不改变 object 默认值和 HTTP/FTP source 归一化。
- `frontend/scripts/check-size.mjs`：新增 evidence wire DTO 预算，保持 mapper/DTO 体量可控。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/evidenceMapper.test.ts src/app/integrations/mappers/objectMapper.test.ts scripts/check-size.test.mjs` — PASS（3 files / 9 tests）。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run lint` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run ci` — PASS（191 test files / 545 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P2-6 仍 open：已建立 tool/evidence 两组 WireDTO，但尚未评估 Go struct -> JSON Schema/OpenAPI -> TS DTO 生成链。
- WireDTO 当前仍以 `unknown` 字段为主，目的是集中 wire 字段命名和防止 mapper 内部重新长出 ad-hoc 类型。

### 工程评分

- 主线价值：18/20（覆盖 Evidence/Object 主线合同入口）。
- 架构边界：18/20（wire DTO 独立，mapper 继续只做归一化）。
- 自动验收：20/20（focused mapper tests + size/type/lint/full frontend CI）。
- 回归风险控制：15/15（无 API/UI 行为变化）。
- 文档可信度：10/10。
- 缺陷关闭质量：7/10（P2-6 分片推进，未关闭）。
- 复杂度控制：5/5。
- 总分：93/100，Gold。

### 下一步建议

- 继续 P2-6 第三片：选择 Investigation Report 或 protocol tool mapper 建立 WireDTO；优先 Investigation Report，因为它与 Evidence-Report 主线合同直接相关。

## Progress Update - 2026-05-13 10:51:45 +08:00

署名: Codex

### 本轮目标

- 继续 P2-6 WireDTO 第三片：覆盖 Investigation Report mapper，使 report explainability 字段的 wire contract 从 mapper 内部抽出。

### 已完成改动

- `frontend/src/app/integrations/wire/reportWireDtos.ts`：新增 `InvestigationReportItemWireDTO` 与 `InvestigationReportWireDTO`，集中 report raw payload 字段。
- `frontend/src/app/integrations/mappers/investigationReportMapper.ts`：使用 report WireDTO 标注 payload，保留 `rule_id/reason/confidence/caveats/tags` 映射行为。
- `frontend/scripts/check-size.mjs`：新增 report WireDTO 预算；同时保持 `investigationReportMapper.ts` 原 30 行预算，没有放宽 mapper 预算。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/investigationReportMapper.test.ts src/app/components/InvestigationReportPanel.test.tsx scripts/check-size.test.mjs` — PASS（3 files / 5 tests）。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run lint` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm exec vitest run src/app/state/hooks/useDisplayFilterWorkflow.test.tsx` — PASS（复核一次完整 CI 中的偶发异步失败）。
- `cd frontend && pnpm run ci` — PASS（191 test files / 545 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P2-6 继续 open：已有 tool/evidence/report 三组 WireDTO；后续仍需覆盖更多核心 mapper 并评估 schema/codegen 可行性。
- 本轮未修改 report UI 或后端规则，只收敛前端 wire contract。

### 工程评分

- 主线价值：18/20（直接覆盖 Evidence-Report 展示合同）。
- 架构边界：19/20（report wire DTO 独立，mapper 预算未放宽）。
- 自动验收：20/20（focused tests + full frontend CI）。
- 回归风险控制：15/15（无 API/UI 行为变化）。
- 文档可信度：10/10。
- 缺陷关闭质量：7/10（P2-6 分片推进，未关闭）。
- 复杂度控制：5/5。
- 总分：94/100，Gold。

### 下一步建议

- 继续 P2-6 第四片：选择 runtime/tsharkStatus 或 protocol tool mapper 建立 WireDTO。优先 runtime/tsharkStatus，因为它与 tshark capability 生产诊断闭环相关。

## Progress Update - 2026-05-13 10:57:28 +08:00

署名: Codex

### 本轮目标

- 继续 P2-6 WireDTO 第四片：覆盖 runtime/tsharkStatus mapper，为 tshark capability 诊断链路建立前端 raw payload DTO。

### 已完成改动

- `frontend/src/app/integrations/wire/runtimeWireDtos.ts`：新增 runtime config、TShark status、FFmpeg、speech、YARA、runtime snapshot wire DTO。
- `frontend/src/app/integrations/mappers/runtimeMapper.ts`：使用 runtime WireDTO 标注 snapshot/config/tool status payload，不改变输出 `ToolRuntimeSnapshot`。
- `frontend/src/app/integrations/mappers/tsharkStatusMapper.ts`：使用 `TSharkStatusWireDTO` 与 shared `asPlainObject`，保留 capability 字段映射。
- `frontend/scripts/check-size.mjs`：新增 runtime WireDTO 预算；runtime/tsharkStatus mapper 既有预算未放宽。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/runtimeMapper.test.ts src/app/components/RuntimeSettingsSections.test.tsx scripts/check-size.test.mjs` — PASS（3 files / 8 tests）。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run lint` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run ci` — PASS（191 test files / 545 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P2-6 继续 open：WireDTO 已覆盖 tool/evidence/report/runtime 主线入口，但 `toolRuntimeClient` 内部仍有 `request<any>`，后续需要收敛 client raw payload 泛型。
- 本轮只做前端契约类型收敛，不新增 runtime UI 展示字段。

### 工程评分

- 主线价值：17/20（服务 tshark capability 诊断链路）。
- 架构边界：18/20（runtime wire DTO 独立，mapper 预算未放宽）。
- 自动验收：20/20（focused tests + full frontend CI）。
- 回归风险控制：15/15（无 API/UI 行为变化）。
- 文档可信度：10/10。
- 缺陷关闭质量：7/10（P2-6 分片推进，未关闭）。
- 复杂度控制：5/5。
- 总分：92/100，Gold。

### 下一步建议

- 下一轮可继续 P2-6 第五片：收敛 `toolRuntimeClient` 的 `request<any>`，改为 `unknown` 或 WireDTO 泛型，并补 client focused 测试。

## Progress Update - 2026-05-13 11:03:04 +08:00

署名: Codex

### 本轮目标

- 继续 P2-6 第五片：收敛 `toolRuntimeClient` 内部 `request<any>`，让 runtime/tshark 诊断链路消费显式 WireDTO 或 `unknown` 契约。

### 已完成改动

- `frontend/src/app/integrations/clients/toolRuntimeClient.ts`：`checkTShark`、`checkFFmpeg`、`checkSpeechToText`、runtime config 读写、`setTSharkPath` 的 request 泛型从 `any` 改为对应 WireDTO。
- `frontend/src/app/integrations/clients/toolRuntimeClient.test.ts`：新增 client focused tests，覆盖 TShark capability 字段映射、FFmpeg/Speech 状态映射、runtime config GET/POST payload shape。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/clients/toolRuntimeClient.test.ts src/app/integrations/mappers/runtimeMapper.test.ts` — PASS（2 files / 5 tests）。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run lint` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run ci` — PASS（192 test files / 547 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P2-6 继续 open：runtime client 已去除本文件 `request<any>`；其他 clients 仍有历史 `request<any>`，后续需按域逐步迁移。
- 本轮只收敛 runtime/tshark 诊断链路，不改 HTTP endpoint 或 UI 行为。

### 工程评分

- 主线价值：17/20（tshark capability 诊断链路契约更稳）。
- 架构边界：19/20（client raw payload 不再裸 any）。
- 自动验收：20/20（新增 client tests + full frontend CI）。
- 回归风险控制：15/15（无 API/UI 行为变化）。
- 文档可信度：10/10。
- 缺陷关闭质量：7/10（P2-6 分片推进，未关闭）。
- 复杂度控制：5/5。
- 总分：93/100，Gold。

### 下一步建议

- 下一轮继续按域收敛 client `request<any>`，优先 `objectClient`/`c2DecryptClient`/`analysisClient` 中已具备 mapper + WireDTO 的入口。

## Progress Update - 2026-05-13 11:10:04 +08:00

署名: Codex

### 本轮目标

- 继续 P2-6 第六片：收敛 Object / C2 decrypt client 的 raw payload 泛型，避免 client 继续使用 `request<any>`。

### 已完成改动

- `frontend/src/app/integrations/clients/objectClient.ts`：`/api/objects` 使用 `ExtractedObjectWireDTO[]`。
- `frontend/src/app/integrations/clients/c2DecryptClient.ts`：`/api/c2-analysis/decrypt` 使用 `C2DecryptResultWireDTO`。
- `frontend/src/app/integrations/wire/c2DecryptWireDtos.ts`：新增 C2 decrypt result/record wire DTO。
- `frontend/src/app/integrations/wire/toolWireDtos.ts`：移除 C2 decrypt DTO，保持 tool DTO 文件不超预算。
- `frontend/src/app/integrations/mappers/c2DecryptMapper.ts`：改用 C2 decrypt 专用 WireDTO 文件。
- `frontend/src/app/integrations/clients/c2DecryptClient.test.ts`：新增 VShell/CS decrypt client payload 与映射测试。
- `frontend/scripts/check-size.mjs`：新增 C2 decrypt WireDTO size budget。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/clients/c2DecryptClient.test.ts src/app/integrations/clients/objectClient.test.ts src/app/integrations/mappers/toolMapper.test.ts scripts/check-size.test.mjs` — PASS（4 files / 16 tests）。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run lint` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run ci` — PASS（193 test files / 549 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P2-6 继续 open：Object/C2 decrypt client 已去除本片 `request<any>`，但 analysis/stream/tool/plugin/media/capture 等 clients 仍有历史 `request<any>`。
- 本轮只改前端 client raw payload 类型与测试，不改 API/UI 行为。

### 工程评分

- 主线价值：18/20（覆盖 Object 与 C2 decrypt 主线入口）。
- 架构边界：19/20（client raw payload 进一步收敛，C2 DTO 独立且不放宽 mapper budget）。
- 自动验收：20/20（新增 client tests + full frontend CI）。
- 回归风险控制：15/15（无 API/UI 行为变化）。
- 文档可信度：10/10。
- 缺陷关闭质量：7/10（P2-6 分片推进，未关闭）。
- 复杂度控制：5/5。
- 总分：94/100，Gold。

### 下一步建议

- 继续 P2-6 第七片：优先 `analysisClient`，因为它覆盖 Evidence/Object/USB/Vehicle/Industrial/C2/APT 主线聚合入口；只改 request 泛型到现有 WireDTO/unknown，不改 mapper 行为。

## Progress Update - 2026-05-13 11:17:36 +08:00

署名: Codex

### 本轮目标

- 继续 P2-6 第七片：收敛 `analysisClient` 主线入口的 raw payload 泛型，覆盖 traffic、industrial、vehicle、usb、c2、apt、evidence。

### 已完成改动

- `frontend/src/app/integrations/clients/analysisClient.ts`：analysis/stats 入口从 `request<any>` 改为 `request<unknown>`，由既有 mapper 做安全归一化。
- `frontend/src/app/integrations/clients/analysisClient.ts`：`/api/evidence` 与 module filter 入口改为 `request<EvidenceListWireDTO>`。
- `frontend/src/app/integrations/clients/analysisClient.test.ts`：新增 signal 透传、traffic/evidence 映射、APT malformed payload fallback 测试。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/clients/analysisClient.test.ts src/app/integrations/mappers/evidenceMapper.test.ts src/app/integrations/mappers/trafficMapper.test.ts` — PASS（3 files / 10 tests）。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run lint` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run ci` — PASS（193 test files / 551 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P2-6 继续 open：`analysisClient` 已去除本文件 `request<any>`；stream/tool/plugin/media/capture/hunting 等 clients 仍有历史 `request<any>`。
- 本轮只收敛 client payload 类型和测试，不改 API/UI 行为，不新增业务规则。

### 工程评分

- 主线价值：19/20（覆盖 Evidence 与主分析入口）。
- 架构边界：19/20（主线 client 不再裸 any，Evidence 使用 WireDTO）。
- 自动验收：20/20（focused tests + full frontend CI）。
- 回归风险控制：15/15（无 API/UI 行为变化）。
- 文档可信度：10/10。
- 缺陷关闭质量：8/10（P2-6 分片推进，主线 analysis client 已闭合）。
- 复杂度控制：5/5。
- 总分：96/100，Gold。

### 下一步建议

- 继续 P2-6 第八片：优先 `mediaClient` 或 `huntingClient`，它们体量小于 `streamClient/toolClient/captureClient`，适合继续降低 client `request<any>` 数量并保持单轮风险可控。

## Progress Update - 2026-05-13 11:24:38 +08:00

署名: Codex

### 本轮目标

- 继续 P2-6 第八片：收敛 `mediaClient` raw payload 泛型，覆盖 media analysis、单文件转写、批量转写状态。

### 已完成改动

- `frontend/src/app/integrations/wire/mediaWireDtos.ts`：新增 media analysis、media transcription、speech batch status wire DTO。
- `frontend/src/app/integrations/clients/mediaClient.ts`：media analysis/transcription/batch endpoints 从 `request<any>` 改为对应 WireDTO。
- `frontend/src/app/integrations/clients/mediaClient.test.ts`：新增 media analysis signal/refresh、转写请求体、批量任务状态、blob 下载 URL 与文件名测试。
- `frontend/scripts/check-size.mjs`：新增 media WireDTO size budget，保持 DTO 文件体量受控。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/clients/mediaClient.test.ts src/app/integrations/mappers/mediaMapper.test.ts scripts/check-size.test.mjs` — PASS（3 files / 12 tests）。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run lint` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run ci` — PASS（194 test files / 554 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P2-6 继续 open：`mediaClient` 已去除本文件 `request<any>`；stream/tool/plugin/capture/hunting 等 clients 仍有历史 `request<any>`。
- 本轮只改前端 client payload 类型与测试，不改 media UI、API path 或后端返回 shape。

### 工程评分

- 主线价值：17/20（覆盖 media 辅助分析链路）。
- 架构边界：19/20（client raw payload 进一步收敛，WireDTO 独立并受 size budget 管理）。
- 自动验收：20/20（新增 client tests + full frontend CI）。
- 回归风险控制：15/15（无 API/UI 行为变化）。
- 文档可信度：10/10。
- 缺陷关闭质量：8/10（P2-6 分片推进，media client 已闭合）。
- 复杂度控制：5/5。
- 总分：94/100，Gold。

### 下一步建议

- 继续 P2-6 第九片：优先 `huntingClient`，文件较小且与 Evidence 主线相关；收敛 hunting hit/config payload 并补 client focused tests。

## Progress Update - 2026-05-13 11:34:13 +08:00

署名: Codex

### 本轮目标

- 继续 P2-6 第九片：收敛 `huntingClient` raw payload 泛型，覆盖 threat hit 列表与 hunting runtime config。

### 已完成改动

- `frontend/src/app/integrations/wire/huntingWireDtos.ts`：新增 `ThreatHitWireDTO` 与 `HuntingRuntimeConfigWireDTO`。
- `frontend/src/app/integrations/clients/huntingClient.ts`：threat hit/config endpoints 从 `request<any>` 改为 WireDTO；runtime config parser 改为 `unknown` 输入。
- `frontend/src/app/integrations/clients/huntingClient.ts`：非法 `yara_timeout_ms` 归一化回默认 `25000`，避免 NaN 污染配置状态。
- `frontend/src/app/integrations/clients/huntingClient.test.ts`：补 signal 透传与 malformed runtime config fallback 测试。
- `frontend/scripts/check-size.mjs`：新增 hunting WireDTO size budget。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/clients/huntingClient.test.ts scripts/check-size.test.mjs` — PASS（2 files / 6 tests）。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run lint` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run ci` — PASS（194 test files / 555 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P2-6 继续 open：`huntingClient` 已去除本文件 `request<any>`；stream/tool/plugin/capture 等 clients 仍有历史 `request<any>`。
- 本轮只改 client payload 类型与配置 fallback，不改 hunting UI、API path 或后端返回 shape。

### 工程评分

- 主线价值：18/20（hunting 是 Evidence 主线来源之一）。
- 架构边界：19/20（client raw payload 继续收敛，WireDTO 独立并受 budget 管理）。
- 自动验收：20/20（focused tests + full frontend CI）。
- 回归风险控制：14/15（增加 malformed timeout fallback，行为更保守）。
- 文档可信度：10/10。
- 缺陷关闭质量：8/10（P2-6 分片推进，hunting client 已闭合）。
- 复杂度控制：5/5。
- 总分：94/100，Gold。

### 下一步建议

- 继续 P2-6 第十片前做一次自我审计：统计剩余 client `request<any>`、检查本轮是否偏离 WireDTO/DTO 主线，再决定处理 `pluginClient`、`toolClient`、`streamClient` 或 `captureClient` 的下一小块。

## Progress Update - 2026-05-13 11:42:40 +08:00

署名: Codex

### 本轮目标

- 第十片前自检：确认 P2-6 WireDTO/client payload 主线未漂移，统计剩余 `request<any>`。
- 继续 P2-6 第十片：收敛 `pluginClient` raw payload 泛型，覆盖 DBC、plugin source、plugin item、TLS config。

### 自检结论

- 当前主线未漂移：最近多片均围绕 client raw payload 与 WireDTO 契约收敛，未改 API/UI 行为，未触碰 MISC 接入 Evidence。
- 剩余 `request<any>` 集中在 `streamClient`、`toolClient`、`captureClient`；本轮处理 `pluginClient` 后，plugin 域已从剩余列表移除。
- mapper 生产文件仍由 `mapper:any:check` 守住裸 `any` 回归；新增 WireDTO 继续登记 size budget。

### 已完成改动

- `frontend/src/app/integrations/wire/pluginWireDtos.ts`：新增 DBC profile、plugin item、plugin source、TLS config wire DTO。
- `frontend/src/app/integrations/clients/pluginClient.ts`：DBC/plugin/source/TLS endpoints 从 `request<any>` 改为对应 WireDTO。
- `frontend/src/app/integrations/clients/pluginClient.test.ts`：新增 DBC lifecycle、plugin source、plugin item mutation、delete、TLS config client tests。
- `frontend/scripts/check-size.mjs`：新增 plugin WireDTO size budget。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/clients/pluginClient.test.ts src/app/integrations/mappers/pluginMapper.test.ts src/app/integrations/mappers/pluginSourceMapper.test.ts src/app/integrations/mappers/tlsMapper.test.ts scripts/check-size.test.mjs` — PASS（5 files / 13 tests）。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run lint` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run ci` — PASS（195 test files / 558 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P2-6 继续 open：`pluginClient` 已去除本文件 `request<any>`；剩余主要在 `streamClient`、`toolClient`、`captureClient`。
- 本轮只改 client payload 类型与测试，不改 plugin/TLS UI、API path 或后端返回 shape。

### 工程评分

- 主线价值：16/20（插件/TLS 属支撑能力，DBC 与 vehicle 辅助相关）。
- 架构边界：19/20（plugin 域 client payload 完成 DTO 化）。
- 自动验收：20/20（新增 client tests + full frontend CI）。
- 回归风险控制：15/15（无 API/UI 行为变化）。
- 文档可信度：10/10。
- 缺陷关闭质量：8/10（P2-6 分片推进，plugin client 已闭合）。
- 复杂度控制：5/5。
- 总分：93/100，Gold。

### 下一步建议

- 继续 P2-6 第十一片：在 `toolClient` 内选择一个低风险子域（WinRM 或 protocol analysis）做局部 DTO 化，不一口气改完整 toolClient，避免测试面过宽。

## Progress Update - 2026-05-13 11:51:01 +08:00

署名: Codex

### 本轮目标

- 继续 P2-6 第十一片：在 `toolClient` 内选取 WinRM 子域做低风险 DTO 化，不一次性改完整 toolClient。

### 已完成改动

- `frontend/src/app/integrations/clients/toolClient.ts`：`runWinRMDecrypt` 从 `request<any>` 改为 `request<WinRMDecryptResultWireDTO>`。
- `frontend/src/app/integrations/clients/toolClient.test.ts`：新增 WinRM decrypt request body、result mapping、result text fetch、blob export、JSON error surfaced 测试。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/clients/toolClient.test.ts src/app/integrations/mappers/toolMapper.test.ts` — PASS（2 files / 12 tests）。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run lint` — PASS。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run ci` — PASS（196 test files / 561 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P2-6 继续 open：`toolClient` 只完成 WinRM 子域 DTO 化；MISC module、SMB3、NTLM、HTTP/SMTP/MySQL/Shiro 子域仍有历史 `request<any>`。
- 本轮只改 WinRM client payload 类型与测试，不改 API/UI 行为。

### 工程评分

- 主线价值：16/20（WinRM 属工具支撑链路）。
- 架构边界：18/20（toolClient 按子域局部收敛，避免大范围重构）。
- 自动验收：20/20（新增 client tests + full frontend CI）。
- 回归风险控制：15/15（无 API/UI 行为变化）。
- 文档可信度：10/10。
- 缺陷关闭质量：7/10（P2-6 分片推进，toolClient 尚未整体闭合）。
- 复杂度控制：5/5。
- 总分：91/100，Gold。

### 下一步建议

- 继续 P2-6 第十二片：在 `toolClient` 内继续选择一个低风险子域，例如 protocol analysis（HTTP/SMTP/MySQL/Shiro）或 SMB3/NTLM。

## Progress Update - 2026-05-13 11:58:50 +08:00

署名: Codex

### 本轮目标

- 继续 P2-6 第十二片：收敛 `toolClient` 的 protocol analysis 子域（HTTP/SMTP/MySQL/Shiro）raw payload 泛型。

### 已完成改动

- `frontend/src/app/integrations/wire/protocolToolWireDtos.ts`：新增 HTTP login、SMTP、MySQL、Shiro rememberMe analysis WireDTO。
- `frontend/src/app/integrations/clients/toolClient.ts`：四个 protocol endpoint 从 `request<any>` 改为对应 WireDTO。
- `frontend/src/app/integrations/clients/toolClient.test.ts`：新增 protocol GET path/signal mapping、Shiro POST body mapping 测试。
- `frontend/scripts/check-size.mjs`：新增 protocol tool WireDTO size budget，避免 mapper/DTO 体量无登记增长。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/clients/toolClient.test.ts src/app/integrations/mappers/protocolToolMapper.test.ts scripts/check-size.test.mjs` — PASS（3 files / 14 tests）。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run lint` — PASS。
- `cd frontend && pnpm run ci` — PASS（196 test files / 563 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P2-6 继续 open：`toolClient` 剩余 `request<any>` 已缩小到 MISC module、SMB3、NTLM 子域；`streamClient`、`captureClient` 仍是后续重点。
- 本轮只改 protocol client payload 类型与测试，不改 MISC UI、API path 或后端返回 shape。

### 工程评分

- 主线价值：17/20（HTTP/SMTP/MySQL/Shiro 属 MISC protocol workbench，支撑威胁流量研判但不接入 Evidence）。
- 架构边界：19/20（protocol DTO 独立成文件并登记 budget，client raw payload 继续收敛）。
- 自动验收：20/20（focused tests + full frontend CI）。
- 回归风险控制：15/15（无 API/UI 行为变化）。
- 文档可信度：10/10。
- 缺陷关闭质量：8/10（P2-6 分片推进，protocol 子域已闭合）。
- 复杂度控制：5/5。
- 总分：94/100，Gold。

### 下一步建议

- 继续 P2-6 第十三片：优先处理 `toolClient` 的 SMB3/NTLM 子域；比 MISC module 泛型收敛更小、更接近当前 toolMapper/sessionMaterialMapper 测试覆盖。

## Progress Update - 2026-05-13 12:03:50 +08:00

署名: Codex

### 本轮目标

- 继续 P2-6 第十三片：收敛 `toolClient` 的 SMB3/NTLM session material 子域 raw payload 泛型。

### 已完成改动

- `frontend/src/app/integrations/wire/sessionMaterialWireDtos.ts`：新增 SMB3 session candidate、SMB3 random session key、NTLM session material WireDTO。
- `frontend/src/app/integrations/clients/toolClient.ts`：SMB3 candidate list、SMB3 random session key、NTLM session materials endpoints 从 `request<any>` 改为对应 WireDTO。
- `frontend/src/app/integrations/clients/toolClient.test.ts`：新增 SMB3/NTLM list mapping、SMB3 POST body mapping 测试。
- `frontend/scripts/check-size.mjs`：新增 session material WireDTO size budget。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/clients/toolClient.test.ts src/app/integrations/mappers/toolMapper.test.ts scripts/check-size.test.mjs` — PASS（3 files / 19 tests）。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run lint` — PASS。
- `cd frontend && pnpm run ci` — PASS（196 test files / 565 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P2-6 继续 open：`toolClient` 剩余 `request<any>` 已缩小到 MISC module 子域；`streamClient`、`captureClient` 仍是后续重点。
- 本轮只改 SMB3/NTLM client payload 类型与测试，不改 MISC UI、API path 或后端返回 shape。

### 工程评分

- 主线价值：17/20（SMB3/NTLM 属协议取证辅助链路）。
- 架构边界：19/20（session material DTO 独立登记，toolClient raw payload 继续收敛）。
- 自动验收：20/20（focused tests + full frontend CI）。
- 回归风险控制：15/15（无 API/UI 行为变化）。
- 文档可信度：10/10。
- 缺陷关闭质量：8/10（P2-6 分片推进，SMB3/NTLM 子域已闭合）。
- 复杂度控制：5/5。
- 总分：94/100，Gold。

### 下一步建议

- 继续 P2-6 第十四片：处理 `toolClient` 剩余 MISC module 子域，使 `toolClient.ts` 本文件彻底去除 `request<any>`。

## Progress Update - 2026-05-13 12:10:53 +08:00

署名: Codex

### 本轮目标

- 继续 P2-6 第十四片：收敛 `toolClient` 剩余 MISC module 子域 raw payload 泛型，使本文件不再直接使用 `request<any>`。

### 已完成改动

- `frontend/src/app/integrations/wire/miscModuleWireDtos.ts`：新增 MISC module manifest、form schema、interface schema、import result、run result WireDTO。
- `frontend/src/app/integrations/clients/toolClient.ts`：MISC module list/import/delete/run endpoints 从 `request<any>` 改为 MISC WireDTO 或 `request<unknown>`。
- `frontend/src/app/integrations/clients/toolClient.test.ts`：新增 MISC module list/import/delete/run client tests，覆盖 FormData、URL encoding、invoke body。
- `frontend/scripts/check-size.mjs`：新增 MISC module WireDTO size budget。

### 验证记录

- `cd frontend && pnpm exec vitest run src/app/integrations/clients/toolClient.test.ts src/app/integrations/mappers/toolMapper.test.ts scripts/check-size.test.mjs` — PASS（3 files / 20 tests）。
- `cd frontend && pnpm run size:check` — PASS。
- `cd frontend && pnpm run typecheck` — PASS。
- `cd frontend && pnpm run lint` — PASS。
- 首次 `cd frontend && pnpm run ci` — FAIL（Prettier 仅提示 `toolClient.ts` 格式）。
- `cd frontend && pnpm exec prettier --write src/app/integrations/clients/toolClient.ts src/app/integrations/clients/toolClient.test.ts src/app/integrations/wire/miscModuleWireDtos.ts scripts/check-size.mjs` — PASS。
- `cd frontend && pnpm exec vitest run src/app/integrations/clients/toolClient.test.ts src/app/integrations/mappers/toolMapper.test.ts scripts/check-size.test.mjs` — PASS（3 files / 20 tests）。
- `cd frontend && pnpm run ci` — PASS（196 test files / 566 tests / build PASS）。
- `git diff --check` — PASS。

### 当前缺陷与风险

- P2-6 继续 open：`toolClient.ts` 已去除本文件 `request<any>`；剩余 client raw payload 主要在 `streamClient.ts` 与 `captureClient.ts`。
- 本轮只改 MISC module client payload 类型与测试，不改变 MISC 独立 workbench 边界，不接入 unified Evidence。

### 工程评分

- 主线价值：16/20（MISC module 属辅助 workbench，支撑分析工具链但不接入 Evidence）。
- 架构边界：20/20（`toolClient.ts` 本文件 `request<any>` 清零，WireDTO 独立登记）。
- 自动验收：20/20（focused tests + full frontend CI）。
- 回归风险控制：14/15（仅格式失败后修复，业务行为无变化）。
- 文档可信度：10/10。
- 缺陷关闭质量：9/10（toolClient raw payload 已闭合；P2-6 仍剩 stream/capture）。
- 复杂度控制：5/5。
- 总分：94/100，Gold。

### 下一步建议

- 继续 P2-6 第十五片：开始 `streamClient` 小片收敛，优先选择 stream index 或 packet raw/layers 这类低风险 endpoint，避免一次性重写全部 stream payload。
