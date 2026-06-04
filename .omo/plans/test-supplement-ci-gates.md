# 测试补充与 CI 门禁计划

## TL;DR

> **Quick Summary**: 补充功能缺失修补计划中新增功能的测试覆盖，添加 CI 门禁检查，续写开发日志。
> 
> **Deliverables**:
> - 补充 10+ 个未测试公共函数的测试
> - 添加 CI 门禁检查（新功能测试、社区 YARA 规则）
> - 续写开发日志
> 
> **Estimated Effort**: 1-2 天
> **Parallel Execution**: YES - 3 waves

---

## Context

### 测试覆盖现状

| 功能模块 | 公共函数数 | 测试函数数 | 覆盖率 |
|----------|-----------|-----------|--------|
| DGA 检测 | 5 | 14 | ✅ 良好 |
| DNP3 解析 | 21 | 21 | ✅ 良好 |
| RTP 流提取 | 12 | 24 | ✅ 良好 |
| IOC 匹配 | 19 | 33 | ✅ 良好 |
| MITRE ATT&CK | 6 | 16 | ✅ 良好 |
| 规则管理 | 24 | 32 | ✅ 良好 |
| Malleable C2 | 5 | 13 | ✅ 良好 |
| 暴力破解 | 嵌入式 | 9 | ✅ 良好 |
| 数据外泄 | 嵌入式 | 15 | ✅ 良好 |
| DNS 隧道 | 嵌入式 | 16 | ✅ 良好 |
| 流负载源 | 嵌入式 | 18 | ✅ 良好 |
| 流解码器 | 嵌入式 | 52 | ✅ 良好 |
| IEC104 | 嵌入式 | 14 | ✅ 良好 |
| 狩猎剧本 | 21 | 25 | ✅ 良好 |
| C2 分析 | 嵌入式 | 28 | ✅ 良好 |

### 发现的测试缺口

| 缺口 | 严重度 | 说明 |
|------|--------|------|
| `ioc_import.go` 无独立测试文件 | 🟡 MEDIUM | 导入函数测试在 `ioc_match_test.go` 中，但应独立 |
| `playbook.go` 步骤执行函数未测试 | 🟡 MEDIUM | `executePlaybookStep`、`executeStepThreatHunt` 等未直接测试 |
| `rule_manager.go` HTTP 下载测试 | 🟢 LOW | 已有 mock 服务器测试 |
| CI 未包含新功能专项测试 | 🟡 MEDIUM | CI 只跑全量测试，未针对新功能 |

---

## Work Objectives

### Core Objective
补充测试覆盖，添加 CI 门禁，续写开发日志。

### Must Have
- 所有新增公共函数有对应测试
- CI 门禁包含新功能专项测试
- 开发日志记录本次工作

### Must NOT Have
- 不修改现有已通过的测试
- 不引入新的编译错误

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (并行):
├── Task 1: 补充 ioc_import.go 独立测试文件 [quick]
├── Task 2: 补充 playbook.go 步骤执行测试 [unspecified-high]
└── Task 3: 补充 CI 门禁检查 [quick]

Wave 2 (顺序):
└── Task 4: 续写开发日志 [quick]

Wave FINAL:
└── Task F1: 全量验证 [quick]
```

---

## TODOs

- [x] 1. 补充 ioc_import.go 独立测试文件

  **What to do**:
  - 创建 `backend/internal/engine/ioc_import_test.go`
  - 将 `ioc_match_test.go` 中的导入测试移动到新文件
  - 添加缺失的测试用例：
    - `ImportSTIX` 边界情况（空 bundle、无 pattern）
    - `ImportCSV` 边界情况（只有表头、空行）
    - `ImportJSON` 边界情况（嵌套对象）
    - `parseSTIXPattern` 各种 pattern 格式
    - `normalizeIOCType` 各种类型映射
  - 运行 `cd backend && go test ./internal/engine/...` 验证

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1

  **References**:
  - `backend/internal/engine/ioc_import.go` — IOC 导入函数
  - `backend/internal/engine/ioc_match_test.go` — 现有导入测试

  **Acceptance Criteria**:
  - [ ] `ioc_import_test.go` 文件存在
  - [ ] 所有 `Import*` 函数有对应测试
  - [ ] `cd backend && go test ./internal/engine/...` → PASS

  **Commit**: YES
  - Message: `test(ioc): add standalone ioc_import_test.go with edge cases`

- [x] 2. 补充 playbook.go 步骤执行测试

  **What to do**：
  - 在 `playbook_test.go` 中添加步骤执行测试：
    - `TestRunPlaybookWithFilterQueryStep`
    - `TestRunPlaybookWithYARAScanStep`
    - `TestRunPlaybookWithC2AnalysisStep`
    - `TestRunPlaybookWithAPTAnalysisStep`
    - `TestRunPlaybookWithCustomStep`
    - `TestRunPlaybookWithDNSTunnelStep`
    - `TestRunPlaybookWithBruteForceStep`
    - `TestRunPlaybookWithDataExfiltrationStep`
  - 运行 `cd backend && go test ./internal/engine/...` 验证

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1

  **References**:
  - `backend/internal/engine/playbook.go` — 步骤执行函数
  - `backend/internal/engine/playbook_test.go` — 现有测试

  **Acceptance Criteria**:
  - [ ] 所有 `executeStep*` 函数有对应测试
  - [ ] `cd backend && go test ./internal/engine/...` → PASS

  **Commit**: YES
  - Message: `test(playbook): add step execution tests for all step types`

- [x] 3. 补充 CI 门禁检查

  **What to do**：
  - 在 `.github/workflows/ci.yml` 中添加新功能专项测试：
    - `go test ./internal/engine -run "TestDNP3|TestIEC104|TestRTP|TestIOC|TestMITRE|TestRuleManager|TestMalleable|TestBruteForce|TestDataExfiltration|TestDNSTunnel|TestPlaybook" -count=1 -v`
  - 在 `scripts/check-all.ps1` 中添加对应检查
  - 运行验证

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1

  **References**:
  - `.github/workflows/ci.yml` — CI 配置
  - `scripts/check-all.ps1` — 全量检查脚本

  **Acceptance Criteria**：
  - [ ] CI 配置包含新功能专项测试
  - [ ] `check-all.ps1` 包含新功能专项测试

  **Commit**: YES
  - Message: `ci: add feature-gap-remediation test gate`

- [x] 4. 续写开发日志

  **What to do**：
  - 在 `docs/audit-development-report-archive-2026-06-03/` 中创建开发日志
  - 记录本次工作：
    - 功能缺失审计发现
    - 修补计划执行过程
    - 测试补充和 CI 门禁
    - 关键技术决策
    - 后续建议

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 2

  **References**：
  - `docs/audit-development-report-archive-2026-06-03/` — 已有开发日志
  - `.omo/plans/feature-gap-remediation.md` — 修补计划

  **Acceptance Criteria**：
  - [ ] 开发日志文件存在
  - [ ] 包含本次工作的完整记录

  **Commit**: YES
  - Message: `docs: add feature-gap-remediation development log`

---

## Final Verification Wave

- [x] F1. **全量验证** — `quick`
  运行 `cd backend && go test ./...` 和 `cd frontend && pnpm run test:run` 验证所有测试通过。
  Output: `Backend [PASS/FAIL] | Frontend [PASS/FAIL] | VERDICT`

---

## Commit Strategy

| Task | Commit Message |
|------|---------------|
| 1 | `test(ioc): add standalone ioc_import_test.go with edge cases` |
| 2 | `test(playbook): add step execution tests for all step types` |
| 3 | `ci: add feature-gap-remediation test gate` |
| 4 | `docs: add feature-gap-remediation development log` |

---

## Success Criteria

### Verification Commands
```bash
cd backend && go test ./...         # Expected: all packages PASS
cd frontend && pnpm run test:run    # Expected: 237 suites, 766 tests PASS
```

### Final Checklist
- [x] 所有新增公共函数有对应测试
- [x] CI 门禁包含新功能专项测试
- [x] 开发日志记录本次工作
- [x] 所有测试通过
