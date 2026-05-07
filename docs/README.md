# GShark-Sentinel 文档中心

本目录是项目文档总入口。当前项目已经从早期 PRD / 实施方案阶段进入多方向并行开发阶段，阅读时建议优先从“当前状态与路线图”进入，再按方向查看合并摘要，最后按需追溯逐轮审计报告。

## 推荐阅读顺序

1. [项目根 README](../README.md)：了解产品定位、核心功能、启动方式和当前边界。
2. [2026-05-05 归档索引](./audit-development-report-archive-2026-05-05/README.md)：查看主线收口、Evidence 范围澄清、Vehicle / USB 证据接入和验证结果。
3. [2026-05-02 归档索引](./audit-development-report-archive-2026-05-02/README.md)：查看上一轮 C2 / APT / MISC 证据链产品化、前端模块化和验证结果。
4. [当前开发态势与下一步规划](./audit-development-report-archive-2026-04-30/current-development-status-and-roadmap-2026-04-30.md)：查看上一轮跨方向状态、风险和建议优先级。
5. [2026-04-30 归档索引](./audit-development-report-archive-2026-04-30/README.md)：查看前端一致性、MISC 风格基线、方向摘要和路线图。

## 当前方向摘要

- [主线收口与 Evidence 范围澄清报告](./audit-development-report-archive-2026-05-05/mainline-evidence-scope-and-validation-report-2026-05-05.md)：明确 MISC 不接入 Evidence，新增 Vehicle / USB 主线证据，修复前端模块归类，补齐验证与文档索引。
- [C2 / APT / MISC 证据链产品化报告](./audit-development-report-archive-2026-05-02/c2-apt-misc-productization-report-2026-05-02.md)：C2 VShell、APT actor registry、MISC Payload / WebShell、误导文案清理、前端骨架审计与模块化拆分（types 目录拆分、feature hooks 提取、UI 组件收敛）、测试验证和下一步优先级。
- [前端设计与交互开发合并摘要](./audit-development-report-archive-2026-04-30/merged-frontend-design-development-summary-2026-04-30.md)：MISC 浅色准线、共享组件、浮层、拖拽屏蔽、HEX 可读性、cancellable 请求与前端一致性。
- [协议专项与 MISC 工具箱合并摘要](./audit-development-report-archive-2026-04-30/merged-protocol-misc-development-summary-2026-04-30.md)：HTTP 登录、SMTP、MySQL、Shiro、Payload / WebShell、WinRM、SMB3 与 MISC manifest 语义。
- [C2 样本分析与 APT 组织画像合并摘要](./audit-development-report-archive-2026-04-30/merged-c2-apt-development-summary-2026-04-30.md)：C2 候选画像、APT 证据解释、弱信号 caveat 与证据链规划。
- [车机与工控分析合并摘要](./audit-development-report-archive-2026-04-30/merged-vehicle-industrial-development-summary-2026-04-30.md)：CAN / J1939 / DoIP / UDS、Modbus、控制行为时间线与专项协议语义规划。

## 当前方向校准

当前计划整体仍围绕离线流量分析、协议专项、危险应用研判和证据链调查工作台推进，没有根本偏离项目定位。下一阶段应把主线重新放回证据 schema、协议报告输出、真实样本验证和威胁流量误报抑制；前端一致性、构建体积和动效优化转入维护与支线处理。

## 接口与开发文档

- [MISC 模块接口文档](./misc-module-interface.md)：内建与 zip 自定义 MISC 模块的 manifest、API、表单和运行时说明。
- [插件接口文档](./plugin-interface.md)：威胁狩猎插件的输入、输出和运行方式。
- [车机流量分析方案](./automotive-analysis-plan.md)：车机方向能力规划。
- [车机流量分析 0 基础教程](./automotive-analysis-zero-basics.md)：车机流量分析入门材料。
- [车机与工控分析重点说明](./ctf-vehicle-industrial-focus.md)：CTF / 专项场景下车机与工控分析关注点。

## 历史材料

早期 PRD、实施计划和重复补丁报告中已有大量内容被当前 README、路线图与方向合并摘要取代，本轮已清理顶层过期副本。历史逐轮证据链继续保留在归档目录中；当前事实以最新路线图、方向摘要和接口文档为准。

## 归档说明

- `audit-development-report-archive-2026-05-05/`：主线收口、Evidence 范围澄清、Vehicle / USB 主线证据接入、验证记录与文档评审。
- `audit-development-report-archive-2026-05-02/`：最新 C2 / APT / MISC 证据链产品化、WebShell 解码表达、前端模块化和验证报告。
- `audit-development-report-archive-2026-04-29/`：上一日 C2 / APT 系列、前端设计 round16 至 round27 与 WinRM 历史补丁报告。
- `audit-development-report-archive-2026-04-30/`：上一阶段归档，包含前端 round28 至 round37、四个方向合并摘要与跨方向路线图。

## 维护规则

- 新增逐轮报告时，放入对应日期归档目录，并更新该目录的 `README.md`。
- 同一天内的同方向报告应优先汇总到方向合并摘要，避免文档继续无序膨胀。
- 若新增或调整总体开发计划，优先更新 `current-development-status-and-roadmap-2026-04-30.md` 或新日期对应路线图。
- 历史归档不要直接当作当前事实引用；如需引用，请同时说明其历史状态与当前差异。
