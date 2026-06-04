# 前端页面布局优化计划

## TL;DR

> **Quick Summary**: 优化前端各个页面的布局显示，不改变总体布局结构。修复间距不一致、组件不统一、无障碍性缺失等问题。
> 
> **Deliverables**:
> - RuleManagement 页面使用设计系统组件
> - 统一错误显示（StatusHint）
> - 修复硬编码 bg-white
> - 统一 MetricCard 使用
> - 添加基础无障碍属性
> 
> **Estimated Effort**: 1-2 天
> **Parallel Execution**: YES - 3 waves

---

## Context

### 布局审计发现

| 严重度 | 问题 | 影响页面 |
|--------|------|---------|
| 🔴 HIGH | RuleManagement 绕过设计系统（原始 button/input、ad-hoc 间距） | RuleManagement |
| 🔴 HIGH | 所有页面零 ARIA 属性 | 全部 16 个页面 |
| 🟠 MEDIUM | 硬编码 `bg-white` 破坏暗色模式 | HttpStream, RawStreamPage |
| 🟠 MEDIUM | 错误显示不一致（ad-hoc div vs StatusHint） | MediaAnalysis |
| 🟠 MEDIUM | `gap-0` 覆盖导致面板无间距 | IndustrialAnalysis |
| 🟠 MEDIUM | MetricCard vs AnalysisStatCard 不一致 | IndustrialAnalysis |
| 🟡 LOW | UsbAnalysis 使用 Banner 而非 StatusHint | UsbAnalysis |
| 🟡 LOW | `360px` 最小宽度可能导致横向滚动 | RawStreamPage, AptAnalysis |

---

## Work Objectives

### Core Objective
优化前端页面布局显示，不改变总体布局结构。

### Must Have
- 所有页面使用统一的设计系统组件
- 错误显示使用 StatusHint
- 基础 ARIA 属性

### Must NOT Have
- 不改变总体布局结构
- 不改变页面功能逻辑
- 不引入新的 npm 依赖

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (并行):
├── Task 1: RuleManagement 页面重构 [unspecified-high]
├── Task 2: 错误显示统一（MediaAnalysis, UsbAnalysis） [quick]
└── Task 3: 硬编码 bg-white 修复 [quick]

Wave 2 (并行):
├── Task 4: MetricCard 统一 [quick]
├── Task 5: gap-0 修复 [quick]
└── Task 6: 基础 ARIA 属性添加 [unspecified-high]

Wave 3:
└── Task F1: 全量验证 [quick]
```

---

## TODOs

- [x] 1. RuleManagement 页面重构

  **What to do**：
  - 将原始 `<button>` 替换为 shadcn `Button` 组件
  - 将原始 `<input>` 替换为 shadcn `Input` 组件
  - 使用 `MetricCard` 替换原始统计显示
  - 使用 `StatusHint` 替换 ad-hoc 错误显示
  - 添加 `aria-label` 到所有按钮
  - 绑定 `<label>` 到 `<input>`（通过 `htmlFor`）
  - 添加响应式断点到配置表单和下载面板

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1

  **References**:
  - `frontend/src/app/pages/RuleManagement.tsx` — 当前页面
  - `frontend/src/app/components/ui/button.tsx` — shadcn Button
  - `frontend/src/app/components/ui/input.tsx` — shadcn Input
  - `frontend/src/app/components/DesignSystem.tsx` — MetricCard, StatusHint

  **Acceptance Criteria**:
  - [ ] 无原始 `<button>` 或 `<input>` 元素
  - [ ] 所有按钮有 `aria-label`
  - [ ] 所有输入框有绑定的 `<label>`
  - [ ] 配置表单有响应式断点

  **Commit**: YES
  - Message: `ui(rules): refactor RuleManagement to use design system components`

- [x] 2. 错误显示统一

  **What to do**：
  - `MediaAnalysis.tsx`：将 ad-hoc 错误 div 替换为 `<StatusHint tone="amber">{error}</StatusHint>`
  - `UsbAnalysis.tsx`：将 `Banner` 替换为 `StatusHint`

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1

  **References**:
  - `frontend/src/app/pages/MediaAnalysis.tsx:86` — ad-hoc 错误 div
  - `frontend/src/app/pages/UsbAnalysis.tsx` — Banner 使用
  - `frontend/src/app/components/DesignSystem.tsx` — StatusHint

  **Acceptance Criteria**：
  - [ ] MediaAnalysis 使用 StatusHint
  - [ ] UsbAnalysis 使用 StatusHint

  **Commit**: YES
  - Message: `ui: unify error display to use StatusHint across pages`

- [x] 3. 硬编码 bg-white 修复

  **What to do**：
  - `HttpStream.tsx`：将 `bg-white` 替换为 `bg-background`
  - `RawStreamPage.tsx`：将 `bg-white` 替换为 `bg-background`

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1

  **References**:
  - `frontend/src/app/pages/HttpStream.tsx:87` — bg-white
  - `frontend/src/app/pages/RawStreamPage.tsx:120` — bg-white

  **Acceptance Criteria**：
  - [ ] 无硬编码 `bg-white`

  **Commit**: YES
  - Message: `ui: replace hardcoded bg-white with bg-background for dark mode`

- [x] 4. MetricCard 统一

  **What to do**：
  - `IndustrialAnalysis.tsx`：将 `AnalysisStatCard` 替换为 `MetricCard`

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2

  **References**:
  - `frontend/src/app/pages/IndustrialAnalysis.tsx` — AnalysisStatCard 使用
  - `frontend/src/app/components/DesignSystem.tsx` — MetricCard

  **Acceptance Criteria**：
  - [ ] IndustrialAnalysis 使用 MetricCard

  **Commit**: YES
  - Message: `ui(industrial): use MetricCard for consistent stat display`

- [x] 5. gap-0 修复

  **What to do**：
  - `IndustrialAnalysis.tsx`：移除网格容器上的 `gap-0`，让 `meow-tile-grid` 处理间距

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2

  **References**:
  - `frontend/src/app/pages/IndustrialAnalysis.tsx:82,89,103,110,119` — gap-0

  **Acceptance Criteria**：
  - [ ] 无 `gap-0` 覆盖

  **Commit**: YES
  - Message: `ui(industrial): remove gap-0 overrides to let tiled layout handle spacing`

- [x] 6. 基础 ARIA 属性添加

  **What to do**：
  - `AnalysisHero.tsx`：为刷新按钮添加 `aria-label`
  - `DesignSystem.tsx`：为 MetricCard 添加 `role="region"` 和 `aria-label`
  - `PageShell.tsx`：为主要内容区域添加 `role="main"`

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2

  **References**:
  - `frontend/src/app/components/AnalysisHero.tsx` — 刷新按钮
  - `frontend/src/app/components/DesignSystem.tsx` — MetricCard
  - `frontend/src/app/components/PageShell.tsx` — 页面壳

  **Acceptance Criteria**：
  - [ ] 刷新按钮有 `aria-label`
  - [ ] MetricCard 有 `role="region"`
  - [ ] PageShell 主内容区有 `role="main"`

  **Commit**: YES
  - Message: `a11y: add basic ARIA attributes to shared layout components`

---

## Final Verification Wave

- [x] F1. **全量验证** — `quick`
  运行 `cd frontend && pnpm run typecheck && pnpm run lint && pnpm run test:run` 验证所有检查通过。
  Output: `Typecheck [PASS/FAIL] | Lint [PASS/FAIL] | Tests [PASS/FAIL] | VERDICT`

---

## Commit Strategy

| Task | Commit Message |
|------|---------------|
| 1 | `ui(rules): refactor RuleManagement to use design system components` |
| 2 | `ui: unify error display to use StatusHint across pages` |
| 3 | `ui: replace hardcoded bg-white with bg-background for dark mode` |
| 4 | `ui(industrial): use MetricCard for consistent stat display` |
| 5 | `ui(industrial): remove gap-0 overrides to let tiled layout handle spacing` |
| 6 | `a11y: add basic ARIA attributes to shared layout components` |

---

## Success Criteria

### Verification Commands
```bash
cd frontend && pnpm run typecheck   # Expected: PASS
cd frontend && pnpm run lint        # Expected: 0 warnings
cd frontend && pnpm run test:run    # Expected: 237 suites, 766 tests PASS
```

### Final Checklist
- [x] 所有页面使用统一的设计系统组件
- [x] 错误显示使用 StatusHint
- [x] 基础 ARIA 属性
- [x] 无硬编码颜色
- [x] 所有测试通过
