# Requirements Document

## Introduction

本 spec 定义 **GShark-Sentinel 迭代式开发治理（iterative-dev-governance）** 的需求。

项目当前已积累两份审计输入：
1. 初步安全与架构审计报告（覆盖后端安全边界、并发安全、测试覆盖、文档一致性）
2. 已知架构缺陷清单（P0–P3 级别，涵盖 tshark capability 降级、BackendBridge 超级接口、SentinelContext 状态 ownership、field scan cache 缺失、前后端契约手写 mapper 等）

治理目标是：在不中断主线能力交付的前提下，通过**自主迭代、每轮写报告、每十轮自检**的闭环机制，系统性地消解上述缺陷，并防止新缺陷积累。

---

## Glossary

- **Governance_Agent**：执行本 spec 的自主开发代理（Codex / Kiro），负责按轮次推进治理任务并输出报告。
- **Dev_Round**：一次完整的开发迭代单元，包含：选取任务 → 实现 → 验证 → 写报告。
- **Report_Archive**：项目已有的日报归档目录，路径格式为 `docs/audit-development-report-archive-YYYY-MM-DD/`。
- **Defect_Register**：已知架构缺陷清单，按 P0/P1/P2/P3 优先级分级，是治理任务的主要输入来源。
- **Self_Audit**：每十轮执行一次的主题偏移检查，输出自检报告并校正后续方向。
- **CI_Gate**：项目全量验证命令 `./scripts/check-all.ps1`，是每轮完成的必要条件。
- **Validation_Baseline**：后端 `go test ./...` + 前端 `pnpm run ci` 的组合，是每轮最低验证门槛。
- **Architecture_Defect**：已知架构缺陷清单中的条目，按 P0/P1/P2/P3 分级。
- **Round_Report**：每轮结束后写入 Report_Archive 的当日开发报告，遵循项目既有报告格式。
- **Drift_Check**：Self_Audit 中对"是否偏离主线能力交付"的判断。
- **P0_Defect**：最高优先级缺陷，必须在治理启动后优先处理，包括 tshark capability 降级策略、field scan cache key 缺失、`_ws.col.*` 字段等级过强、插件本地代码执行边界。
- **P1_Defect**：高优先级缺陷，包括 BackendBridge 超级接口、SentinelContext 状态 ownership、useCaptureStartWorkflow 参数过大、tool runtime config 持久化一致性、前后端契约手写 mapper。
- **P2_Defect**：中优先级缺陷，包括 report/evidence 包级边界、规则硬编码、前端 boundary check 深度、field scan cache 无容量控制、analysis_helpers.go 职责过重。
- **P3_Defect**：低优先级缺陷，包括功能面过宽缺少成熟度标记、缺少真实 PCAP 回归矩阵。

---

## Requirements

### Requirement 1：每轮开发结束后续写当日开发报告

**User Story:** As a Governance_Agent, I want to write a development report at the end of every Dev_Round, so that the project maintains a traceable, date-accurate audit trail consistent with the existing Report_Archive format.

#### Acceptance Criteria

1. WHEN a Dev_Round completes, THE Governance_Agent SHALL write a Round_Report to the path `docs/audit-development-report-archive-YYYY-MM-DD/` where `YYYY-MM-DD` is the actual local date of the round.
2. THE Round_Report SHALL include the following sections in order: 本轮目标、已完成改动、验证记录、当前缺陷与风险、下一步建议。
3. THE Round_Report SHALL include an author line (`署名: Codex`) and a timestamp line (`日期: YYYY-MM-DD HH:MM:SS +08:00`) at the top.
4. WHEN a Report_Archive directory for the current date does not exist, THE Governance_Agent SHALL create the directory and a `README.md` index file before writing the Round_Report.
5. WHEN multiple Dev_Rounds occur on the same date, THE Governance_Agent SHALL append subsequent rounds to the existing daily report file rather than creating duplicate files, using a `## Progress Update - YYYY-MM-DD HH:MM:SS +08:00` heading for each continuation.
6. THE Round_Report SHALL list every source file modified during the round under the 已完成改动 section.
7. THE Round_Report SHALL record the Validation_Baseline result (pass/fail) under the 验证记录 section.

---

### Requirement 2：轮次间自主迭代，不停止等待用户确认

**User Story:** As a Governance_Agent, I want to proceed autonomously from one Dev_Round to the next without pausing for user confirmation, so that the governance process makes continuous progress without manual intervention.

#### Acceptance Criteria

1. WHEN a Dev_Round completes and the Validation_Baseline passes, THE Governance_Agent SHALL select the next task from the Defect_Register and begin the next Dev_Round without requesting user confirmation.
2. WHEN the Validation_Baseline fails at the end of a Dev_Round, THE Governance_Agent SHALL fix the failure within the same round before writing the Round_Report, and SHALL NOT proceed to the next round until the baseline passes.
3. WHILE processing a Dev_Round, THE Governance_Agent SHALL complete the full cycle (select task → implement → validate → write report) before starting any new task.
4. THE Governance_Agent SHALL prioritize Architecture_Defects in P0 order first, then P1, then P2, then P3 when selecting the next task.
5. IF no remaining Architecture_Defect exists at the current priority level, THEN THE Governance_Agent SHALL advance to the next priority level and select from that level.
6. WHERE a P0_Defect or P1_Defect fix requires changes to both backend and frontend, THE Governance_Agent SHALL complete both sides within the same Dev_Round to maintain contract consistency.

---

### Requirement 3：每十轮执行一次自检

**User Story:** As a Governance_Agent, I want to perform a self-audit every ten Dev_Rounds, so that I can detect and correct any drift away from the project's mainline capability delivery focus.

#### Acceptance Criteria

1. WHEN the Dev_Round count reaches a multiple of ten (10, 20, 30, …), THE Governance_Agent SHALL execute a Self_Audit before starting the next Dev_Round.
2. THE Self_Audit SHALL produce a written Drift_Check report appended to the current date's Round_Report under a `## Self-Audit Round N` heading.
3. THE Drift_Check report SHALL answer the following questions explicitly:
   a. 本阶段完成了哪些 Defect_Register 条目？
   b. 是否有任何轮次偏离了主线能力交付（入侵检测、威胁流量分析、证据链）？
   c. 当前 Defect_Register 剩余条目与优先级是否需要重新排序？
   d. 下一阶段的执行方向是否需要校正？
4. IF the Drift_Check identifies a topic drift, THEN THE Governance_Agent SHALL update the task selection order for subsequent rounds to correct the drift before resuming normal iteration.
5. THE Self_Audit SHALL re-run the CI_Gate (`./scripts/check-all.ps1`) and record the result in the Drift_Check report.
6. WHEN the Self_Audit completes, THE Governance_Agent SHALL resume autonomous iteration from the next Dev_Round.

---

### Requirement 4：P0 缺陷优先消解

**User Story:** As a Governance_Agent, I want to address P0-level architecture defects first, so that the most critical safety and correctness risks are eliminated before lower-priority improvements.

#### Acceptance Criteria

1. THE Governance_Agent SHALL address all P0_Defects before beginning work on any P1_Defect.
2. WHEN fixing the tshark capability degradation strategy (P0), THE Governance_Agent SHALL implement a graceful fallback that logs missing optional fields instead of silently failing or returning empty results.
3. WHEN fixing the field scan cache key absence (P0), THE Governance_Agent SHALL add a deterministic, collision-resistant cache key that incorporates all relevant scan parameters.
4. WHEN fixing the `_ws.col.*` field severity level (P0), THE Governance_Agent SHALL downgrade the severity classification so that display-layer fields do not trigger the same alert level as protocol-layer anomalies.
5. WHEN fixing the plugin local code execution boundary (P0), THE Governance_Agent SHALL enforce an explicit sandbox or permission check before any plugin executes local code, and SHALL add a test that verifies the boundary is enforced.
6. IF a P0_Defect fix introduces a breaking change to an existing API or contract, THEN THE Governance_Agent SHALL update all affected callers within the same Dev_Round.

---

### Requirement 5：P1 缺陷系统性重构

**User Story:** As a Governance_Agent, I want to systematically refactor P1-level architecture defects after P0 is clear, so that the codebase's structural integrity improves without disrupting ongoing feature delivery.

#### Acceptance Criteria

1. THE Governance_Agent SHALL begin P1_Defect work only after all P0_Defects have been resolved and verified by the Validation_Baseline.
2. WHEN refactoring BackendBridge (P1), THE Governance_Agent SHALL split the super-interface into focused domain interfaces, each covering no more than one analysis domain, and SHALL update all call sites.
3. WHEN fixing SentinelContext state ownership (P1), THE Governance_Agent SHALL extract each independent state slice into its own owner module and SHALL verify that no cross-slice direct mutation remains.
4. WHEN reducing useCaptureStartWorkflow parameter count (P1), THE Governance_Agent SHALL group related parameters into typed option objects and SHALL update all call sites within the same Dev_Round.
5. WHEN fixing tool runtime config persistence consistency (P1), THE Governance_Agent SHALL ensure that config reads and writes use a single authoritative path and that concurrent access is safe.
6. WHEN replacing hand-written frontend/backend contract mappers (P1), THE Governance_Agent SHALL generate or derive the mapper from a shared type definition and SHALL add a round-trip property test verifying that `decode(encode(x)) == x` for all contract types.
7. WHERE a P1_Defect refactor touches a file that already has tests, THE Governance_Agent SHALL update those tests to cover the refactored interface before closing the round.

---

### Requirement 6：P2/P3 缺陷持续改善

**User Story:** As a Governance_Agent, I want to address P2 and P3 defects in a steady, non-disruptive manner after P0/P1 work is complete, so that the codebase continues to improve without blocking mainline delivery.

#### Acceptance Criteria

1. THE Governance_Agent SHALL begin P2_Defect work only after all P1_Defects have been resolved and verified.
2. WHEN fixing report/evidence package boundary violations (P2), THE Governance_Agent SHALL enforce that no package outside the designated owner imports internal evidence types directly, and SHALL add a boundary test.
3. WHEN removing hardcoded rules (P2), THE Governance_Agent SHALL replace each hardcoded value with a named constant or configuration entry and SHALL document the valid range or allowed values.
4. WHEN deepening frontend boundary checks (P2), THE Governance_Agent SHALL add or extend boundary scripts to cover at least the feature-level import boundaries identified in the 2026-05-12 engineering report.
5. WHEN adding field scan cache capacity control (P2), THE Governance_Agent SHALL implement an LRU or TTL eviction policy with a configurable maximum entry count, and SHALL add a test verifying that the cache does not grow unboundedly.
6. WHEN refactoring analysis_helpers.go (P2), THE Governance_Agent SHALL split the file into focused helper modules each with a single responsibility, and SHALL verify that all existing tests still pass.
7. WHEN addressing P3_Defects, THE Governance_Agent SHALL add maturity markers to features that are not yet production-ready and SHALL add at least one real PCAP regression case per major analysis domain.

---

### Requirement 7：每轮验证门槛强制执行

**User Story:** As a Governance_Agent, I want every Dev_Round to pass the Validation_Baseline before being considered complete, so that no round introduces regressions into the codebase.

#### Acceptance Criteria

1. THE Governance_Agent SHALL run `cd backend && go test ./...` at the end of every Dev_Round and SHALL record the result in the Round_Report.
2. THE Governance_Agent SHALL run `cd frontend && pnpm run ci` at the end of every Dev_Round and SHALL record the result in the Round_Report.
3. IF either validation command fails, THEN THE Governance_Agent SHALL fix the failure before writing the Round_Report and before proceeding to the next Dev_Round.
4. WHEN a fix for a validation failure requires more than one attempt, THE Governance_Agent SHALL document each attempt and its outcome in the Round_Report under the 验证记录 section.
5. THE Governance_Agent SHALL run `cd backend && gofmt -l .` and SHALL fix any formatting violations before the round is considered complete.
6. WHERE a Dev_Round modifies TypeScript files, THE Governance_Agent SHALL run `cd frontend && pnpm run typecheck` and SHALL fix any type errors before the round is considered complete.

---

### Requirement 8：报告格式与文档治理一致性

**User Story:** As a Governance_Agent, I want all Round_Reports to follow the project's established documentation conventions, so that the audit trail remains consistent and navigable for human reviewers.

#### Acceptance Criteria

1. THE Round_Report SHALL be written in Chinese (Simplified) to match the existing report corpus language.
2. WHEN creating a new Report_Archive directory, THE Governance_Agent SHALL update `docs/README.md` to include the new archive in the recommended reading order and the archive description table.
3. THE Governance_Agent SHALL NOT append new rounds to a report file from a previous date; WHEN the local date changes, THE Governance_Agent SHALL start a new file in the new date's archive directory.
4. THE Round_Report SHALL reference the specific Defect_Register entries addressed in the round using their priority label (e.g., P0: tshark capability 降级策略).
5. WHEN a round produces no code changes (e.g., a Self_Audit-only round), THE Governance_Agent SHALL still write a Round_Report documenting the audit findings and the corrected direction.
6. THE Governance_Agent SHALL maintain a running defect closure table in the Self_Audit report, listing each resolved Architecture_Defect with the date and round number it was closed.
