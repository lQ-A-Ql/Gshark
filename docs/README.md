# meow~traffic 文档中心

> 品牌名是 `meow~traffic`；`github.com/gshark/sentinel/...`、`MEOW_TRAFFIC_*`、`meow-traffic`、`sentinel-backend.exe` 等仍是当前有效的内部兼容标识，除非有完整迁移方案，否则不要随手改名。

本文是项目文档总入口。当前事实以代码、CI、`AGENTS.md`、根 README、本文档、项目模型、接口文档和治理登记表为准。`audit-development-report-archive-*` 是历史审计和迭代证据，不能单独代表当前实现。

## 推荐阅读顺序

1. [项目根 README](../README.md)：产品定位、核心功能、启动方式、运行时说明。
2. [项目整体模型](./project-model.md)：系统上下文、C4 组件、数据生命周期、信任边界、扩展模型和门禁矩阵。
3. [项目开发指南](./project-development-guide.md)：双 Go module、pnpm、Wails/dev、build tag、缓存和检查命令。
4. [设计与工程约束](./project-design-and-constraints.md)：模块边界、`WithContext`、typed IPC、证据、安全和 CI 约束。
5. [架构总览与 Mermaid 流程图](./architecture/README.md)：系统上下文、后端分层、前端数据面、Capture、Evidence 和核心算法流程。
6. [HTTP OpenAPI 文档](./api/openapi.yaml)：后端 REST/SSE 接口契约。
7. [安全修复规范手册](./security-fix-playbook.md)：安全修复红线、阶段规则和 review checklist。
8. [治理缺陷登记表](./governance-defect-register.json)：机器可读的缺陷状态源、优先级、关闭提交和验证命令。
9. [MISC 模块接口文档](./misc-module-interface.md)：内建与 zip 自定义模块的 manifest、API、表单、签名和运行时规则。
10. [Desktop IPC typed migration plan](./desktop-ipc-migration-plan.md)：桌面 typed IPC 迁移策略和阶段状态。

## 当前事实源

| 文档 | 用途 |
| --- | --- |
| [项目整体模型](./project-model.md) | 统一描述系统模型、数据流、信任边界、扩展面和变更门禁 |
| [项目开发指南](./project-development-guide.md) | 开发命令、模块结构、运行时配置和本地检查 |
| [设计与工程约束](./project-design-and-constraints.md) | 后端、前端、API/IPC、证据、安全和 CI 的约束 |
| [架构总览](./architecture/README.md) | 以图谱形式呈现核心流程和模块关系 |
| [OpenAPI](./api/openapi.yaml) | HTTP/SSE 契约 |
| [MISC 模块接口](./misc-module-interface.md) | MISC zip 与内建模块契约 |
| [MCP 接口](./mcp-interface.md) | 本地 MCP tools/resources/prompts 接入说明 |
| [安全修复手册](./security-fix-playbook.md) | 安全整改和 review 红线 |
| [治理缺陷登记表](./governance-defect-register.json) | 机器可读缺陷登记和验收状态 |

## 专项资料

- [车机流量分析方案](./automotive-analysis-plan.md)
- [车机流量分析 0 基础教程](./automotive-analysis-zero-basics.md)
- [车机与工控分析重点说明](./ctf-vehicle-industrial-focus.md)
- [公共样本语料说明](./public-sample-corpus-2026-05-06.md)
- `docs/knowledge/`：协议、C2、WebShell、YARA、USB/媒体、Wails 等知识库资料。

## 历史归档

`docs/audit-development-report-archive-*` 和 `backend/docs/audit-development-report-archive-*` 保存历史审计、迭代计划和修复证据。读取规则：

- 历史归档可以解释“为什么这么改”，但不能直接作为当前行为契约。
- 本地开发报告或一次性工作笔记不纳入远端事实源；需要长期约束时必须进入当前事实源。
- 历史结论若仍需约束开发，必须沉淀到当前事实源、测试或治理登记表。
- 新增长期有效的接口、架构、安全或门禁规则时，不要只写在归档报告里。

## 维护规则

- 新增或调整 HTTP route：同步 [OpenAPI](./api/openapi.yaml) 和 transport/contract 测试。
- 新增 typed Wails binding：同步 `app.go`、Wails 生成声明、`desktopTypedBridge*`、requirements 和桌面 IPC 门禁。
- 新增后端长任务：提供 `WithContext` 变体，HTTP handler 使用 `r.Context()`。
- 新增核心前端 DTO：同步 wire DTO、mapper、core type，并通过 type governance。
- 新增 MISC 包交付形态、权限或签名规则：同步 [MISC 模块接口](./misc-module-interface.md)。
- 新增全局开发规则、安全规则或阶段治理状态：同步 `AGENTS.md`、[项目整体模型](./project-model.md)、[安全修复手册](./security-fix-playbook.md) 或治理登记表。

## 权威优先级

1. 代码、测试、CI 配置和构建脚本。
2. `AGENTS.md` 与安全修复规范。
3. 根 README、本文档、[项目整体模型](./project-model.md)、开发指南、设计约束和架构图谱。
4. OpenAPI、MISC、MCP、Desktop IPC 等专项契约。
5. 治理缺陷登记表和阶段性 review/remediation 报告。
6. 历史审计归档。
