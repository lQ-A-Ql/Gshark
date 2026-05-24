# MCP 接入文档落地记录

## 本轮目标

将 `meow~traffic` 已实现的本地只读 MCP 能力沉淀为一份版本化接入文档，并把文档入口接入主文档导航，便于：

- 团队成员快速理解本地 MCP 的边界与接入方式
- 外部 MCP 客户端按统一方式接入
- 后续实现与接口文档保持同一事实源

## 开发前文档复读

本轮开始前复读并核对：

- `docs/README.md`
- `docs/audit-development-report-archive-2026-05-21/local-mcp-implementation-2026-05-21.md`
- `README.md`

## 最新文档复评

### 1. `docs/README.md`

结论：

- 当前文档总入口缺少对 MCP 的稳定入口链接。
- 现有目录说明更偏向 MISC、插件和车机分析，MCP 已实现但还没有版本化主文档承接。

建议：

- 增加 `本地 MCP 接入文档` 入口，归入“接口与开发文档”。

### 2. `local-mcp-implementation-2026-05-21.md`

结论：

- 已清楚说明 MCP 首版设计边界、工具分层和测试结果。
- 更适合作为本地实施报告，不适合直接作为团队长期引用的接口说明。

建议：

- 另起一份版本化 `docs/mcp-interface.md`，将“真实已实现接口”沉淀为长期文档。

### 3. `README.md`

结论：

- 根 README 已有 MISC 文档入口，但还没有突出 MCP 作为扩展/集成能力的一部分。

建议：

- 在相关文档区补一个 MCP 接入文档入口，便于新同学和外部集成直接发现。

## 实际改动

1. 新增版本化 MCP 接入文档
   - 新增 `docs/mcp-interface.md`
   - 内容覆盖：
     - 本地只读边界
     - `/api/mcp` 与 `/api/mcp/config` 职责分离
     - 鉴权模型
     - 当前真实 `tools / resources / prompts` 清单
     - Codex / Inspector / 通用 HTTP 客户端接入示例
     - payload 截断、取消语义和常见问题

2. 更新文档总入口
   - 更新 `docs/README.md`
   - 在“接口与开发文档”中新增 `本地 MCP 接入文档`

3. 更新项目根 README
   - 更新 `README.md`
   - 在相关文档列表中新增 `本地 MCP 接入文档`

## 落地结果

当前版本化文档已经能够覆盖以下真实已验证能力：

- 读取 MCP 配置与启停状态
- 通过 bearer token 调用 `/api/mcp`
- 列出全部已实现 tools / resources / prompts
- 读取当前抓包状态
- 读取 packet page
- 读取 HTTP stream payload

本轮还对 MCP 做了手工联调确认：

- `capture.status` 可返回当前抓包文件、包总数与 load phase
- `capture.packet_page` 可返回分页包列表
- `stream.http` 可返回实际 HTTP request / response payload
- `stream.payload_sources` 可返回 payload source 候选

## 结论

- 本地 MCP 已从“实现存在”升级为“有稳定版本化接入文档可引用”。
- 当前文档已补充后续审计收口结果：MCP 启用态以后端进程内状态为唯一事实源，不再由前端 `localStorage` 启动自动重放；`/api/mcp/config` 与 `/api/mcp` 均受统一 bearer 鉴权保护；endpoint 当前固定为 `http://127.0.0.1:17891/api/mcp`。
- 下一步如果继续扩展 MCP，建议优先更新 `docs/mcp-interface.md`，而不是只写本地归档报告。

署名：Codex
时间：2026-05-21 20:43:39 +08:00
