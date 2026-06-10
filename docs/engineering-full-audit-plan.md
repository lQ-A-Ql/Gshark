# 工程化全量审计方案

本文是 meow~traffic 工程、设计、约束和文档的可重复全量审计方案。范围聚焦工程正确性与架构卫生；除非另行扩展，不逐条审计每个检测规则的误报/漏报模型。

## 目标

- 验证实现架构是否符合文档边界。
- 保持公开文档、OpenAPI、typed IPC、前端 wire DTO 和 core types 与代码一致。
- 发现取消链路、抓包替换、桌面/浏览器传输、外部工具探测、扩展运行时和证据可追溯性风险。
- 将稳定缺陷沉淀到版本化文档或 `docs/governance-defect-register.json`。

## 权威事实源

| 领域 | 事实源 |
| --- | --- |
| 后端路由 | `backend/internal/transport/http_server.go`、`backend/internal/transport/misc_modules.go` |
| 后端契约 | `backend/internal/transport/services.go`、`backend/internal/servicecontract` |
| 后端逻辑 | `backend/internal/engine`、`backend/internal/tshark`、`backend/internal/model` |
| 前端传输 | `frontend/src/app/integrations`、`frontend/wailsjs/go/main/DesktopApp.d.ts` |
| 前端数据模型 | `frontend/src/app/integrations/wire`、`frontend/src/app/integrations/mappers`、`frontend/src/app/core/types` |
| 功能行为 | `frontend/src/app/features`、`frontend/src/app/pages`、`frontend/src/app/state` |
| 工程约束 | `AGENTS.md`、`.github/workflows/ci.yml`、`scripts/check-all.ps1`、`frontend/package.json` |
| 当前文档 | `README.md`、`docs/README.md`、`docs/architecture/README.md`、`docs/api/openapi.yaml` |

## 审计域

1. 工程工作流
   - 确认双 Go module 和 `go.work` 约束。
   - 确认根模块 build tag 与后端无 tag 测试。
   - 确认前端 pnpm-only 工作流。
   - 确认 CI 与本地检查命令已文档化。

2. 后端架构
   - 对照 OpenAPI 检查 route 注册。
   - 检查 transport handler 是否使用 context-aware 服务方法。
   - 检查长任务分析和媒体路径是否尊重取消。
   - 检查 `transport`、`engine`、`tshark`、`model`、`miscpkg`、`mcp`、`governance` 依赖关系是否通过边界测试。

3. 前端架构
   - 检查桌面数据面是否通过 typed IPC。
   - 检查 browser mode 是否保留 HTTP/SSE fallback。
   - 检查 pages/features 是否避免直接后端 `fetch`。
   - 检查 wire DTO、mappers、`core/types` 是否分层清晰。

4. API 与 IPC 契约
   - 对比 `/api/*` 路由与 `docs/api/openapi.yaml`。
   - 对比 typed binding requirements 与 `DesktopApp.d.ts`。
   - 检查新增后端响应字段是否被 mapper 接收，或被明确声明为动态结构。

5. 证据与报告
   - 检查 `GatherEvidence` 来源是否产出可追溯记录。
   - 检查前端证据排序、过滤、导出、报告逻辑是否兼容当前后端 payload。
   - 确认低置信度或上下文不足的证据带有 caveat。

6. 运行时与安全
   - 检查 bearer token 和鉴权例外。
   - 检查工具探测是否清楚报告降级状态。
   - 检查 blob 上限与导出路径。
   - 检查 MISC zip 模块导入、删除和运行时执行边界。

7. 文档治理
   - 检查 README 和 docs 索引是否指向存在的文件。
   - 检查历史审计归档是否没有被当作当前权威事实。
   - 检查 Mermaid 图是否仍匹配当前模块名。

## 风险分级

| 优先级 | 含义 | 示例 |
| --- | --- | --- |
| P0 | 阻塞安全使用或破坏分析状态 | 抓包替换竞态、未鉴权 mutating route、发布包复用旧后端二进制 |
| P1 | 主要工作流或契约破坏 | 已迁移页面缺少 typed IPC、公开 endpoint 与 OpenAPI 不一致、长任务忽略取消 |
| P2 | 重要可维护性或数据质量问题 | mapper/type 漂移、证据 caveat 不清、扩展形态缺文档 |
| P3 | 低风险文档或打磨问题 | 文案过期、图节点标签不完整、命令示例缺失 |

## 审计记录格式

```text
ID: Architecture_Defect_<short-id>
Priority: P0|P1|P2|P3
Area: backend|frontend|ipc|api|docs|runtime|evidence|security
Source: 文件路径和行号/路由/类型
Observation: 问题或缺口
Impact: 影响
Expected remediation: 具体修复或文档更新
Verification: 验证命令或复核步骤
Status: open|fixed|deferred
```

不能立即修复的稳定缺陷应进入 `docs/governance-defect-register.json`。

## 验证命令

聚焦命令：

```powershell
cd backend
go test ./internal/architecture -run TestBackendArchitectureBoundaries -count=1 -v
go test ./internal/engine -run "TestGatherEvidence|Test.*InvestigationReport|TestBundledPublic" -count=1 -v
go test ./...

cd ..\frontend
pnpm run boundary:check
pnpm run client:any:check
pnpm run mapper:any:check
pnpm run wire:any:check
pnpm run wails-binding:check
pnpm run test:run
```

完整命令：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check-all.ps1
```

如果是文档主导审计且无法承受完整耗时，至少运行：

```powershell
cd backend
go test ./internal/architecture -run TestBackendArchitectureBoundaries -count=1 -v

cd ..\frontend
pnpm run boundary:check
```

同时用 `rg` 做链接和路由一致性检查：

```powershell
rg -n "project-development-guide|project-design-and-constraints|engineering-full-audit-plan" README.md docs
rg -n "mux\.HandleFunc|/api/" backend/internal/transport/http_server.go backend/internal/transport/misc_modules.go
rg -n "^  /api/" docs/api/openapi.yaml
```

## 完成标准

一次审计完成需要满足：

- 选定命令全部通过，或失败原因已记录。
- route/API 与 typed IPC 差异已经修复或登记。
- 文档链接指向存在的文件。
- Mermaid 图语法可渲染，并匹配当前模块边界。
- 新的稳定缺陷已进入治理登记表或明确后续报告。
