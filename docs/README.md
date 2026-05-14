# GShark-Sentinel 文档中心

本目录是项目文档总入口。当前项目已经从早期 PRD / 实施方案阶段进入多方向并行开发阶段，阅读时建议优先从“当前状态与路线图”进入，再按方向查看合并摘要。

## 推荐阅读顺序

1. [项目根 README](../README.md)：了解产品定位、核心功能、启动方式和当前边界。
2. [治理缺陷登记表](./governance-defect-register.json)：查看版本化 Architecture_Defect 状态源和当前 open task。
3. [MISC 模块接口文档](./misc-module-interface.md)：查看内建与 zip 自定义 MISC 模块接口。
4. [插件接口文档](./plugin-interface.md)：查看威胁狩猎插件接口。
5. [车机流量分析方案](./automotive-analysis-plan.md)：查看车机方向能力规划。

## 当前方向摘要

- [治理缺陷登记表](./governance-defect-register.json)：机器可读的 Architecture_Defect 状态源，记录缺陷优先级、关闭提交、验证命令、证据测试和报告路径。
- 本地开发报告：`docs/audit-development-report-archive-*` 仅用于本机逐轮记录，受 `.gitignore` 管理，不纳入远端；版本化当前事实以本 README、接口文档和 `governance-defect-register.json` 为准。

## 当前方向校准

当前计划整体仍围绕离线流量分析、协议专项、危险应用研判和证据链调查工作台推进，没有根本偏离项目定位。下一阶段应把主线重新放回证据 schema、协议报告输出、真实样本验证和威胁流量误报抑制；前端一致性、构建体积和动效优化转入维护与支线处理。

## 接口与开发文档

- [MISC 模块接口文档](./misc-module-interface.md)：内建与 zip 自定义 MISC 模块的 manifest、API、表单和运行时说明。
- [插件接口文档](./plugin-interface.md)：威胁狩猎插件的输入、输出和运行方式。
- [车机流量分析方案](./automotive-analysis-plan.md)：车机方向能力规划。
- [车机流量分析 0 基础教程](./automotive-analysis-zero-basics.md)：车机流量分析入门材料。
- [车机与工控分析重点说明](./ctf-vehicle-industrial-focus.md)：CTF / 专项场景下车机与工控分析关注点。

## 历史材料

早期 PRD、实施计划和重复补丁报告中已有大量内容被当前 README、治理缺陷登记表和接口文档取代。历史逐轮证据链可保留在本地归档目录中；当前事实以版本化文档为准。

## 归档说明

- `audit-development-report-archive-*`：本地开发报告目录，默认被 `.gitignore` 忽略，不要求在干净 clone 或 CI 中存在。

## 维护规则

- 新增逐轮报告时，可放入本地日期归档目录，但不要作为版本化治理测试的硬依赖。
- 若新增或调整总体开发计划，优先更新本 README、接口文档或 `governance-defect-register.json`。
- 历史归档不要直接当作当前事实引用；需要远端可复现的事实必须沉淀到版本化文档中。
