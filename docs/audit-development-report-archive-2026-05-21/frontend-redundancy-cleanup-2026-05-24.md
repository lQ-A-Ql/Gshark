# 前端冗余清理与 MCP 设置链路收口报告

## 本轮目标

按用户要求使用 `code-simplifier` 清理当前前端冗余代码，范围聚焦最近变动最大的运行时设置 / MCP 本地接口链路，要求：

- 不改变行为契约
- 不靠 UI 补丁掩盖结构问题
- 满足现有 frontend size / boundary / any / wails-binding / test / build 门禁
- 与最新 MCP 文档和 2026-05-24 审计归档保持一致

## 阅读与评审输入

本轮先读取并对照了以下最新文档：

1. `docs/mcp-interface.md`
2. `docs/audit-development-report-archive-2026-05-21/mcp-six-issue-closure-2026-05-24.md`
3. `docs/audit-development-report-archive-2026-05-21/frontend-white-background-language-2026-05-24.md`

### 文档评审结论

- `docs/mcp-interface.md` 的首版边界清晰，已明确本地只读、默认关闭、固定 endpoint、复用 bearer token、无 remote / stdio / 写操作，这些约束足以指导前端实现，不需要前端再自行发明持久化语义。
- `mcp-six-issue-closure-2026-05-24.md` 对“后端为 MCP 启用态唯一事实源”的要求是正确的；本轮前端收敛继续遵守该约束，没有把启用态回写到本地缓存。
- `frontend-white-background-language-2026-05-24.md` 与当前 UI 收口方向一致；本轮新增的 MCP 设置区保持纯白 surface，没有回引装饰性渐变背景。
- 评审未发现新的产品契约冲突；需要继续注意的是，后续任何 token 展示、IPC 包装、MCP DTO 增量都必须同时过 boundary 与 size gate，不能只看功能测试。

## 实际改动

### 1. MCP 设置面板去重

- 新增独立组件 `frontend/src/app/components/MCPSettingsSection.tsx`，把 MCP 状态展示、端点复制、token 复制、启停开关和刷新动作集中到单一 section。
- 把重复的状态卡片骨架和“带复制按钮的信息卡”抽成局部 helper，减少重复 JSX，同时保持原有测试可见文本不变。
- `RuntimeSettingsSidebar.tsx` 继续只做薄编排，MCP section 与其他 runtime section 并列渲染。

### 2. Runtime settings model 去重

- `useRuntimeSettingsSidebarModel.ts` 收敛了重复的 MCP 异步任务模板：
  - MCP 刷新
  - MCP 启停保存
  - 端点复制
  - token 复制
- 通过统一 helper 保留原提示文案，但去掉了重复的 `busy/notice/try/catch/finally` 样板。

### 3. Token 读取下沉到 state 层

- 新增 `frontend/src/app/state/hooks/useBackendAuthToken.ts`。
- bearer token 的读取不再由组件层直接 import `integrations/httpBridge` / `bridgeTypes`，而是由 lifecycle/state 层统一读取，再通过 `SentinelContext` 暴露。
- 这一步同时修复了 frontend boundary check 对组件层越级访问 `integrations/*` 的违规。

### 4. MCP DTO / mapper / controls 拆分

- 新增 `frontend/src/app/integrations/wire/mcpWireDtos.ts`，把 MCP 原始 payload 从 `runtimeWireDtos.ts` 拆出。
- 新增 `frontend/src/app/integrations/mappers/mcpStatusMapper.ts`，把 MCP 状态映射从 `runtimeComponentMapper.ts` 拆出。
- 新增 `frontend/src/app/state/hooks/useBackendLifecycleMCPControls.ts`，让 MCP 控制逻辑不再挤在 `useBackendLifecycleControls.ts` 中。
- 新增 `frontend/src/app/state/hooks/backendLifecycleTypes.ts`，把 lifecycle 大类型契约从 `useBackendLifecycle.ts` 抽离，避免主 hook 因类型声明而继续膨胀。

### 5. 测试拆分与收口

- 新增 `frontend/src/app/components/MCPSettingsSection.test.tsx`
- 新增 `frontend/src/app/state/hooks/useBackendLifecycleMCPControls.test.tsx`
- `RuntimeSettingsSections.test.tsx` 回到“基础 runtime section 渲染 / setter 接线”职责，不再混入 MCP 专项断言。
- `useBackendLifecycleControls.test.tsx` 回到 TLS / runtime control 范围，不再承载 MCP 用例。

### 6. 尺寸门禁同步

- 更新 `frontend/scripts/check-size.mjs`
- 为新增的 `mcpWireDtos.ts` 与 `mcpStatusMapper.ts` 添加 size budget。
- 通过拆分而不是简单调高预算，恢复相关文件的单一职责。

## 验证结果

已通过：

```powershell
cd frontend; pnpm exec vitest run src/app/components/RuntimeSettingsSections.test.tsx src/app/components/MCPSettingsSection.test.tsx src/app/integrations/desktopBridge.test.ts src/app/integrations/clients/toolRuntimeClient.test.ts src/app/state/hooks/useBackendLifecycle.test.tsx src/app/state/hooks/useBackendLifecycleControls.test.tsx src/app/state/hooks/useBackendLifecycleMCPControls.test.tsx
cd frontend; pnpm run typecheck
cd frontend; pnpm run lint
cd frontend; pnpm run format:check
cd frontend; pnpm run size:check
cd frontend; pnpm run ci
git diff --check
```

结果：

- `pnpm run typecheck`：通过
- `pnpm run lint`：通过
- `pnpm run format:check`：通过
- `pnpm run size:check`：通过
- `pnpm run ci`：通过
- `vitest`：全量 `227` 个测试文件 / `700` 个测试通过
- `vite build`：通过
- `git diff --check`：通过

## 本轮结论

本轮不是简单删代码，而是把 MCP 本地设置链路从“重复状态模板 + 组件越级取 token + DTO/mapper/test 挤在通用文件里”收敛为更清晰的分层结构：

- 组件层只做展示与交互
- runtime sidebar model 只做页面状态编排
- state/lifecycle 统一负责 token 与 MCP 状态
- integrations 继续负责 transport / DTO / mapper

整体行为未改，且所有 frontend CI 门禁已恢复为绿色。

署名：Codex
时间：2026-05-24 21:17:48 +08:00
