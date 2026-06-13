# meow~traffic 文档中心

> 品牌已更名为 `meow~traffic`；本文档中出现的 `github.com/gshark/sentinel/...`、`MEOW_TRAFFIC_*`、`meow-traffic`、`sentinel-backend.exe` 等名称仍是当前真实可用的内部兼容标识，本轮不迁移。

本目录是项目文档总入口。当前项目已进入多方向并行开发阶段，版本化当前事实以根 README、本文档、权威工程文档、接口文档和治理登记表为准。`audit-development-report-archive-*` 只作为历史证据，不直接代表当前实现。

## 推荐阅读顺序

1. [项目根 README](../README.md)：了解产品定位、核心功能、启动方式和当前边界。
2. [项目开发指南](./project-development-guide.md)：查看双 Go module、pnpm、Wails/dev、构建标签、缓存和检查命令。
3. [设计与工程约束](./project-design-and-constraints.md)：查看产品边界、模块边界、WithContext、typed IPC、CI 和安全运行时约束。
4. [架构总览与 Mermaid 流程图](./architecture/README.md)：查看系统上下文、后端分层、前端数据面、Capture、Evidence 和核心算法流程。
5. [HTTP OpenAPI 文档](./api/openapi.yaml)：查看后端 REST/SSE 接口契约。
6. [工程化全量审计方案](./engineering-full-audit-plan.md)：查看全量审计方法、风险分级、证据记录格式和验收命令。
7. [治理缺陷登记表](./governance-defect-register.json)：查看版本化 Architecture_Defect 状态源和当前 open task。
8. [全量一期治理登记表](./full-governance-phase1-register.md)：查看 engine/service/frontend 类型与状态治理的阶段性状态。
9. [Desktop IPC typed migration plan](./desktop-ipc-migration-plan.md)：查看桌面 typed IPC 迁移策略、自主迭代评分与 phase 状态。
10. [Desktop IPC iteration status](./desktop-ipc-iteration-status.json)：查看机器可读的当前 IPC 迁移进度、评分与下一轮建议。
11. [MISC 模块接口文档](./misc-module-interface.md)：查看内建与 zip 自定义 MISC 模块接口。
12. [车机流量分析方案](./automotive-analysis-plan.md)：查看车机方向能力规划。

## 当前方向摘要

- [项目开发指南](./project-development-guide.md)、[设计与工程约束](./project-design-and-constraints.md)、[架构总览与 Mermaid 流程图](./architecture/README.md) 与 [工程化全量审计方案](./engineering-full-audit-plan.md)：当前工程事实、架构边界、约束和审计闭环的权威文档集。
- [治理缺陷登记表](./governance-defect-register.json)：机器可读的 Architecture_Defect 状态源，记录缺陷优先级、关闭提交、验证命令、证据测试和报告路径。
- [全量一期治理登记表](./full-governance-phase1-register.md)：记录本期 engine Service 解耦、engine 大包门禁、前端 type/cache/filePath guard 和低严重度治理状态。
- [Desktop IPC typed migration plan](./desktop-ipc-migration-plan.md) 与 [Desktop IPC iteration status](./desktop-ipc-iteration-status.json)：桌面 typed IPC 迁移的版本化计划、评分规则、当前 phase 与下一轮建议；不混入全局 Architecture_Defect register。
- 本地开发报告：`docs/audit-development-report-archive-*` 仅用于本机逐轮记录，受 `.gitignore` 管理，不纳入远端；需要远端可复现的事实必须沉淀到版本化文档中。

## 当前方向校准

当前计划整体仍围绕离线流量分析、协议专项、危险应用研判和证据链调查工作台推进，没有根本偏离项目定位。下一阶段应把主线重新放回证据 schema、协议报告输出、真实样本验证和威胁流量误报抑制；前端一致性、构建体积和动效优化转入维护与支线处理。

## 接口与开发文档

- [项目开发指南](./project-development-guide.md)：开发环境、双 module、build tag、pnpm、Wails/dev、缓存和检查命令。
- [设计与工程约束](./project-design-and-constraints.md)：产品边界、模块边界、HTTP context、typed IPC、证据、安全和 CI 约束。
- [架构总览与 Mermaid 流程图](./architecture/README.md)：系统上下文、后端分层、前端数据面、Capture、Evidence、C2、WebShell、YARA、专项协议和 MISC 流程图。
- [HTTP OpenAPI 文档](./api/openapi.yaml)：后端 HTTP/SSE 接口契约。
- [工程化全量审计方案](./engineering-full-audit-plan.md)：审计域、风险分级、证据记录格式、验证命令和完成标准。
- [全量一期治理登记表](./full-governance-phase1-register.md)：高/中/低 13 项治理问题的阶段状态、规则和验收命令。
- [本地 MCP 接入文档](./mcp-interface.md)：本地只读 MCP 的启用方式、鉴权、tools/resources/prompts 清单与客户端接入示例。
- [Desktop IPC typed migration plan](./desktop-ipc-migration-plan.md)：Wails typed IPC 迁移、自主迭代评分和桌面/dev transport policy。
- [MISC 模块接口文档](./misc-module-interface.md)：内建与 zip 自定义 MISC 模块的 manifest、API、表单和运行时说明。
- [车机流量分析方案](./automotive-analysis-plan.md)：车机方向能力规划。
- [车机流量分析 0 基础教程](./automotive-analysis-zero-basics.md)：车机流量分析入门材料。
- [车机与工控分析重点说明](./ctf-vehicle-industrial-focus.md)：CTF / 专项场景下车机与工控分析关注点。

## 历史材料

早期 PRD、实施计划和重复补丁报告中已有大量内容被当前 README、治理缺陷登记表和接口文档取代。历史逐轮证据链可保留在本地归档目录中；当前事实以版本化文档为准。

## 归档说明

- `audit-development-report-archive-*`：本地开发报告目录，默认被 `.gitignore` 忽略，不要求在干净 clone 或 CI 中存在。

## 维护规则

- 新增逐轮报告时，可放入本地日期归档目录，但不要作为版本化治理测试的硬依赖。
- 若新增或调整总体开发计划，优先更新根 README、权威工程文档、接口文档或 `governance-defect-register.json`。
- 新增 HTTP route 时同步更新 `api/openapi.yaml`；新增 typed Wails binding、核心类型、MISC 接口或 CI 约束时同步更新对应权威文档。
- 历史归档不要直接当作当前事实引用；需要远端可复现的事实必须沉淀到版本化文档中。
