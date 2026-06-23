# V1 源分析改进完成报告

**完成日期**：2026-06-21
**对应审计**：`docs/audit-development-report-archive-2026-06-20/full-project-audit-report-2026-06-20.md`
**改进范围**：TShark 白名单后端原子化、Backend `tool_*.go` 公共 pipeline、前端分析 Hook 缓存统一
**报告版本**：v1.0

---

## 执行摘要

本轮改进聚焦 V1 源分析报告中识别出的三项中高风险工程债务：

1. **后端传输层命令注入风险**（R1 / `http_tool_handlers.go`）— 工具路径配置缺乏白名单校验。
2. **后端 `tool_*.go` 模板复制** — `engine` 根包中多个 `tool_*.go` 文件重复实现路径/允许目录生命周期。
3. **前端 8 个 feature hook 结构重复** — 各分析 hook 自行实现缓存、取消、守卫、错误处理，导致一致性问题。

改进后：

- 后端新增 `internal/tool` 包，提供 `ExecutableValidator`、`AllowedDirList`、`Runtime` 三种抽象，统一外部二进制路径校验与允许目录生命周期。
- 后端 transport 层新增 `/api/tools/tshark/allowed-dirs`、`/api/tools/tshark/allowed-dirs/{dir}` 原子化 API，支持查询、添加、删除白名单目录。
- 前端新增 `app/hooks/useAnalysisResult.ts` 共享 hook，8 个 capture-scoped 分析 hook 全部迁移为薄包装。
- 前端 RuntimeSettings 增加 TShark 路径警告 + 一键加入白名单 + 允许目录列表管理。

**验证结果**：后端 `go test ./...` ✅、前端 `pnpm run ci` ✅（936 tests）、全量 `./scripts/check-all.ps1` ✅。

---

## 变更清单

### Phase 1：TShark 白名单后端原子化改造

| 文件 | 变更 |
|------|------|
| `backend/internal/transport/http_tool_handlers.go` | 新增 `RegisterTSharkAllowedDirHandlers`，注册 list/add/remove handler |
| `backend/internal/transport/http_tool_handlers.go` | `handleSetTSharkPath` 改为调用 `toolRuntime.SetPath(path)`，返回 warning/error |
| `backend/internal/transport/services.go` | `ToolRuntime` 接口增加 `AllowTSharkDir`、`RemoveTSharkAllowedDir`、`TSharkAllowedDirs` 方法 |
| `backend/internal/engine/service.go` | 实现 `AllowTSharkDirWithContext`、`RemoveTSharkAllowedDirWithContext`、`TSharkAllowedDirsWithContext` |
| `backend/internal/engine/tool_runtime.go` | 委托给 `tool.Runtime` |

### Phase 2：Backend `tool_*.go` 公共 pipeline

| 文件 | 变更 |
|------|------|
| `backend/internal/tool/validator.go` | 新增 `ExecutableValidator`：绝对路径校验、脚本扩展名拒绝、符号链接目标递归校验、目录 vs 文件校验 |
| `backend/internal/tool/allowlist.go` | 新增 `AllowedDirList`：线程安全的允许目录集合、路径成员校验、目录存在性校验 |
| `backend/internal/tool/runtime.go` | 新增 `Runtime`：封装外部二进制路径 + 允许目录生命周期，提供 `SetPath` / `AllowDir` / `RemoveDir` / `Revalidate` |
| `backend/internal/tool/runtime_test.go` | `Runtime` 单元测试 |
| `backend/internal/tool/allowlist_test.go` | `AllowedDirList` 单元测试 |
| `backend/internal/tool/validator_test.go` | `ExecutableValidator` 单元测试 |
| `backend/internal/transport/tool_runtime.go` | 基于 `tool.Runtime` 构建 `ToolRuntime` 服务 |
| `backend/internal/engine/shared_helpers.go` | 清理冗余 precondition helper，统一使用 `tool` 包 |
| `backend/internal/engine/tool_*.go` | 改为基于公共 `tool` 包实现 |

### Phase 3：前端分析 Hook 缓存统一与守卫补齐

| 文件 | 变更 |
|------|------|
| `frontend/src/app/hooks/useAnalysisResult.ts` | 新增共享 hook：缓存命中、in-flight 去重、`force` 刷新、取消、错误处理、`isPreloadingCapture` 守卫 |
| `frontend/src/app/hooks/useAnalysisResult.test.tsx` | 新增单元测试：成功缓存、缓存命中、force 刷新、disabled、onSuccess、失败 |
| `frontend/src/app/features/c2/useC2Analysis.ts` | 迁移为 `useAnalysisResult` 薄包装 |
| `frontend/src/app/features/industrial/useIndustrialAnalysis.ts` | 迁移为 `useAnalysisResult` 薄包装 |
| `frontend/src/app/features/apt/useAPTAnalysis.ts` | 迁移为 `useAnalysisResult` 薄包装 |
| `frontend/src/app/features/vehicle/useVehicleAnalysis.ts` | 迁移为 `useAnalysisResult` 薄包装 |
| `frontend/src/app/features/media/useMediaAnalysis.ts` | 迁移为 `useAnalysisResult` 薄包装，保留 `force` 参数 |
| `frontend/src/app/features/traffic/useTrafficGraph.ts` | 迁移为 `useAnalysisResult` 薄包装，保留 preload contract |
| `frontend/src/app/features/usb/useUsbAnalysis.ts` | 迁移为 `useAnalysisResult` 薄包装 |
| `frontend/src/app/features/evidence/useEvidence.ts` | 迁移为 `useAnalysisResult` 薄包装，保留 preload contract |
| `frontend/src/app/components/RuntimeSettingsSections.tsx` | 增加 TShark 路径警告、一键加入白名单、允许目录列表 |

### Phase 4：文档更新

| 文件 | 变更 |
|------|------|
| `AGENTS.md` | 更新子系统说明：Tool runtime、TShark allowlist、Frontend shared analysis hook、Frontend feature hooks |
| `AGENTS.md` | 修正后端测试基线描述为所有 backend packages |

---

## 架构改进说明

### 后端 `internal/tool` 包边界

- 不依赖 `internal/model`、`transport`、`engine`、`tshark`、HTTP、MISC/plugin 或 `os/exec`。
- `ExecutableValidator` 只负责路径/文件系统级校验。
- `AllowedDirList` 只负责目录集合的成员关系与持久化。
- `Runtime` 组合二者，提供外部二进制运行时配置的原子视图。

### 前端 `useAnalysisResult` 语义

- **缓存键**：由 capture revision、filePath、totalPackets 及可选参数（如 modules、dbcProfiles、hidSource）组成。
- **守卫**：`enabled = backendConnected && hasUsableCapturePath(filePath, totalPackets)`；`isPreloadingCapture` 为 true 时暂停自动请求。
- **去重**：通过 `AnalysisResourceCache` 保证同一 key 同时只触发一次请求。
- **取消**：依赖 `useAbortableRequest`；cache key 变化或组件卸载时取消旧请求。
- **错误**：fetch 失败时回退到 `emptyValue` 并显示 `errorMessage`。
- **成功回调**：`onSuccess` 通过 ref 缓存，避免 effect 震荡。

### 未迁移的 hook

以下管理/工作流 hook 不属于 capture-scoped analysis，未纳入 `useAnalysisResult`：

- `useObjectExport`
- `useRuleManagement`
- `useThreatHuntingWorkbench`
- 其他管理型 hook

这些 hook 将在后续专门的管理状态统一 pass 中处理。

---

## 验证结果

### 后端

```bash
cd backend
go test ./...
```

结果：✅ 全通过（含 `internal/tool` 新包测试）。

### 前端

```bash
cd frontend
pnpm run ci
```

结果：✅ 通过，936 tests。

### 全量检查

```powershell
powershell -ExecutionPolicy Bypass -File ./scripts/check-all.ps1
```

结果：✅ 通过。

---

## 后续建议

1. **P0 剩余项**：继续处理 react-router 升级、MISC zip 签名验证、CS/VShell 密码学缺陷、rule_manager 路径遍历/SSRF。
2. **前端**：为 `useObjectExport` 等管理 hook 引入类似 `useAnalysisResult` 的公共工作流 hook。
3. **CI**：在 `check-all.ps1` 中增加 `pnpm audit --prod` 与后端 `gosec`/`staticcheck`。
4. **文档**：将本次改进后的接口语义补充到 `docs/api/openapi.yaml`。

---

## 附录：相关文件索引

- 计划源：`docs/audit-development-report-archive-2026-06-20/full-project-audit-report-2026-06-20.md`
- AGENTS.md：`AGENTS.md`
- 后端工具包：`backend/internal/tool/`
- 后端 transport 工具 handler：`backend/internal/transport/http_tool_handlers.go`
- 前端共享 hook：`frontend/src/app/hooks/useAnalysisResult.ts`
- 前端 Runtime UI：`frontend/src/app/components/RuntimeSettingsSections.tsx`
