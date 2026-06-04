# 前端测试补充计划

## TL;DR

> **Quick Summary**: 补充前端缺失的测试文件，覆盖最近修改的页面、组件和 Wire DTO。
> 
> **Deliverables**:
> - RuleManagement 页面测试
> - DesignSystem 组件测试（MetricCard, StatusHint）
> - PageShell 组件测试
> - AnalysisHero 组件测试（ARIA 属性）
> - useSentinelProviderBody 测试
> 
> **Estimated Effort**: 1-2 天
> **Parallel Execution**: YES - 2 waves

---

## Context

### 测试覆盖现状

| 文件 | 测试文件 | 测试数 | 状态 |
|------|---------|--------|------|
| RuleManagement.tsx | ❌ 不存在 | 0 | 🔴 缺失 |
| DesignSystem.tsx | ❌ 不存在 | 0 | 🔴 缺失 |
| PageShell.tsx | ❌ 不存在 | 0 | 🔴 缺失 |
| AnalysisHero.tsx | ❌ 不存在 | 0 | 🔴 缺失 |
| useSentinelProviderBody.ts | ❌ 不存在 | 0 | 🔴 缺失 |
| IndustrialAnalysis.tsx | ✅ 存在 | 1 | 🟡 不足 |

---

## Work Objectives

### Core Objective
补充前端缺失的测试文件，覆盖最近修改的页面、组件和 Wire DTO。

### Must Have
- 所有缺失测试文件已创建
- 每个测试文件至少 3 个测试用例
- `cd frontend && pnpm run test:run` → PASS

### Must NOT Have
- 不修改现有已通过的测试
- 不引入新的编译错误

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (并行):
├── Task 1: RuleManagement 页面测试 [unspecified-high]
├── Task 2: DesignSystem 组件测试 [quick]
├── Task 3: PageShell 组件测试 [quick]
└── Task 4: AnalysisHero 组件测试 [quick]

Wave 2 (并行):
├── Task 5: useSentinelProviderBody 测试 [unspecified-high]
└── Task 6: IndustrialAnalysis 测试补充 [quick]

Wave FINAL:
└── Task F1: 全量验证 [quick]
```

---

## TODOs

- [x] 1. RuleManagement 页面测试

  **What to do**：
  - 创建 `frontend/src/app/pages/RuleManagement.test.tsx`
  - Mock `useRuleManagement` hook
  - 添加以下测试用例：
    - `TestRuleManagementRendersHero` — 渲染 AnalysisHero
    - `TestRuleManagementShowsLoading` — 加载状态显示
    - `TestRuleManagementShowsError` — 错误状态显示
    - `TestRuleManagementShowsPacks` — 规则包列表显示
    - `TestRuleManagementTogglePack` — 切换规则包启用/禁用
    - `TestRuleManagementCheckUpdates` — 检查更新按钮
  - 运行 `cd frontend && pnpm run test:run` 验证

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1

  **References**:
  - `frontend/src/app/pages/RuleManagement.tsx` — 当前页面
  - `frontend/src/app/pages/IndustrialAnalysis.test.tsx` — 测试模式参考
  - `frontend/src/app/features/rules/useRuleManagement.ts` — hook 定义

  **Acceptance Criteria**：
  - [ ] `RuleManagement.test.tsx` 文件存在
  - [ ] 至少 6 个测试用例
  - [ ] `cd frontend && pnpm run test:run` → PASS

  **Commit**: YES
  - Message: `test(rules): add RuleManagement page tests`

- [x] 2. DesignSystem 组件测试

  **What to do**：
  - 创建 `frontend/src/app/components/DesignSystem.test.tsx`
  - 添加以下测试用例：
    - `TestMetricCardRendersLabelAndValue` — 渲染标签和值
    - `TestMetricCardHasAriaAttributes` — ARIA 属性
    - `TestMetricCardRendersIcon` — 图标渲染
    - `TestStatusHintRendersChildren` — 子元素渲染
    - `TestStatusHintAppliesTone` — 色调应用
    - `TestSurfacePanelRendersChildren` — 面板渲染
  - 运行 `cd frontend && pnpm run test:run` 验证

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1

  **References**:
  - `frontend/src/app/components/DesignSystem.tsx` — 组件定义

  **Acceptance Criteria**：
  - [ ] `DesignSystem.test.tsx` 文件存在
  - [ ] 至少 6 个测试用例
  - [ ] `cd frontend && pnpm run test:run` → PASS

  **Commit**: YES
  - Message: `test(ui): add DesignSystem component tests`

- [x] 3. PageShell 组件测试

  **What to do**：
  - 创建 `frontend/src/app/components/PageShell.test.tsx`
  - 添加以下测试用例：
    - `TestPageShellRendersChildren` — 子元素渲染
    - `TestPageShellHasRoleMain` — role="main" 属性
    - `TestPageShellAppliesDensity` — 密度样式
    - `TestPageShellAppliesLayout` — 布局样式
  - 运行 `cd frontend && pnpm run test:run` 验证

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1

  **References**:
  - `frontend/src/app/components/PageShell.tsx` — 组件定义

  **Acceptance Criteria**：
  - [ ] `PageShell.test.tsx` 文件存在
  - [ ] 至少 4 个测试用例
  - [ ] `cd frontend && pnpm run test:run` → PASS

  **Commit**: YES
  - Message: `test(ui): add PageShell component tests`

- [x] 4. AnalysisHero 组件测试

  **What to do**：
  - 创建 `frontend/src/app/components/AnalysisHero.test.tsx`
  - 添加以下测试用例：
    - `TestAnalysisHeroRendersTitle` — 标题渲染
    - `TestAnalysisHeroRendersSubtitle` — 副标题渲染
    - `TestAnalysisHeroRefreshButtonHasAriaLabel` — 刷新按钮 ARIA 属性
    - `TestAnalysisHeroCallsOnRefresh` — 刷新回调
    - `TestAnalysisHeroRendersTags` — 标签渲染
  - 运行 `cd frontend && pnpm run test:run` 验证

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1

  **References**：
  - `frontend/src/app/components/AnalysisHero.tsx` — 组件定义

  **Acceptance Criteria**：
  - [ ] `AnalysisHero.test.tsx` 文件存在
  - [ ] 至少 5 个测试用例
  - [ ] `cd frontend && pnpm run test:run` → PASS

  **Commit**: YES
  - Message: `test(ui): add AnalysisHero component tests`

- [x] 5. useSentinelProviderBody 测试

  **What to do**：
  - 创建 `frontend/src/app/state/useSentinelProviderBody.test.ts`
  - Mock 所有子 hooks
  - 添加以下测试用例：
    - `TestUseSentinelProviderBodyReturnsAllSubContexts` — 返回所有子 context
    - `TestUseSentinelProviderBodyBackendValue` — backend value 正确
    - `TestUseSentinelProviderBodyCaptureValue` — capture value 正确
    - `TestUseSentinelProviderBodyPacketValue` — packet value 正确
  - 运行 `cd frontend && pnpm run test:run` 验证

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2

  **References**:
  - `frontend/src/app/state/useSentinelProviderBody.ts` — hook 定义

  **Acceptance Criteria**：
  - [ ] `useSentinelProviderBody.test.ts` 文件存在
  - [ ] 至少 4 个测试用例
  - [ ] `cd frontend && pnpm run test:run` → PASS

  **Commit**: YES
  - Message: `test(state): add useSentinelProviderBody tests`

- [x] 6. IndustrialAnalysis 测试补充

  **What to do**：
  - 在 `IndustrialAnalysis.test.tsx` 中添加更多测试用例：
    - `TestIndustrialAnalysisShowsMetricCards` — MetricCard 显示
    - `TestIndustrialAnalysisShowsModbusTable` — Modbus 表格显示
    - `TestIndustrialAnalysisFilterByUnit` — Unit 过滤
    - `TestIndustrialAnalysisFilterByFunction` — Function 过滤
  - 运行 `cd frontend && pnpm run test:run` 验证

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2

  **References**:
  - `frontend/src/app/pages/IndustrialAnalysis.test.tsx` — 现有测试
  - `frontend/src/app/pages/IndustrialAnalysis.tsx` — 页面定义

  **Acceptance Criteria**：
  - [ ] 至少 5 个测试用例（现有 1 + 新增 4）
  - [ ] `cd frontend && pnpm run test:run` → PASS

  **Commit**: YES
  - Message: `test(industrial): add IndustrialAnalysis page tests`

---

## Final Verification Wave

- [x] F1. **全量验证** — `quick`
  运行 `cd frontend && pnpm run test:run` 验证所有测试通过。
  Output: `Test Files [N passed] | Tests [N passed] | VERDICT`

---

## Commit Strategy

| Task | Commit Message |
|------|---------------|
| 1 | `test(rules): add RuleManagement page tests` |
| 2 | `test(ui): add DesignSystem component tests` |
| 3 | `test(ui): add PageShell component tests` |
| 4 | `test(ui): add AnalysisHero component tests` |
| 5 | `test(state): add useSentinelProviderBody tests` |
| 6 | `test(industrial): add IndustrialAnalysis page tests` |

---

## Success Criteria

### Verification Commands
```bash
cd frontend && pnpm run test:run    # Expected: 237+ suites, 766+ tests PASS
```

### Final Checklist
- [x] 所有缺失测试文件已创建
- [x] 每个测试文件至少 3 个测试用例
- [x] 所有测试通过
