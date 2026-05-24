# Codex 本地 MCP 连接配置记录

## 本轮目标

将 `meow~traffic` 已实现的本地只读 MCP 接入到 Codex 自身配置，使后续 Codex 会话可直接通过本机 `Streamable HTTP` 端点访问项目 MCP。

## 开发前文档复读

本轮开始前复读并核对：

- `docs/README.md`
- `docs/audit-development-report-archive-2026-05-21/local-mcp-implementation-2026-05-21.md`

复评结论：

1. `local-mcp-implementation-2026-05-21.md`
   - 已明确本地 MCP 的端点、鉴权方式、只读边界与配置面设计。
   - 当前 Codex 接入应严格复用既有 bearer token，而不是新增第二套认证。

2. `docs/README.md`
   - 当前主线仍围绕离线流量分析、证据链与协议专项，没有与 MCP 接入产生方向冲突。
   - 本轮属于本地工具链连通性工作，不涉及版本化接口文档变更。

## 实际改动

1. 核对本地 MCP 服务状态
   - 确认后端健康检查 `GET /health` 可用。
   - 使用 bearer token 访问 `GET /api/mcp/config`，确认 MCP 已启用且端点为 `http://127.0.0.1:17891/api/mcp`。

2. 配置 Codex 全局 MCP server
   - 使用 Codex CLI 执行：
     - `codex mcp add meow-traffic --url http://127.0.0.1:17891/api/mcp --bearer-token-env-var GSHARK_BACKEND_TOKEN`
   - 将配置写入 `C:\Users\QAQ\.codex\config.toml`
   - 新增条目：
     - `[mcp_servers.meow-traffic]`
     - `url = "http://127.0.0.1:17891/api/mcp"`
     - `bearer_token_env_var = "GSHARK_BACKEND_TOKEN"`

3. 配置本机 bearer token 环境变量
   - 将当前有效 token 写入用户级环境变量 `GSHARK_BACKEND_TOKEN`
   - 同时写入当前 shell 进程环境，便于本轮命令行即时验证

## 验证结果

已验证：

1. `codex mcp get meow-traffic`
   - 显示 `transport: streamable_http`
   - 显示 `url: http://127.0.0.1:17891/api/mcp`
   - 显示 `bearer_token_env_var: GSHARK_BACKEND_TOKEN`

2. `codex mcp list`
   - `meow-traffic` 已出现在 MCP server 列表中
   - 鉴权方式显示为 `Bearer token`

3. 真实 MCP JSON-RPC 请求
   - 对 `/api/mcp` 发起 `tools/list`
   - 返回 `200 OK`
   - 返回体包含工具列表，说明端点、鉴权与 MCP 服务均工作正常

## 当前结论

- Codex 全局配置已完成，后续新的 Codex CLI / Desktop 会话可以直接使用 `meow-traffic` 这个 MCP server。
- 由于用户级环境变量是在本轮配置过程中写入，已启动的 Codex 进程通常需要重启后才会继承新的 `GSHARK_BACKEND_TOKEN`。
- 当前正在进行中的旧会话工具清单不会热刷新；新开会话最稳妥。

## 后续建议

1. 若后端 bearer token 变更，需要同步更新用户环境变量 `GSHARK_BACKEND_TOKEN`。
2. 若后续希望减少 token 轮换带来的手工维护，可考虑在桌面设置页增加“为外部 MCP 客户端导出当前 token 到用户环境变量”的显式按钮，但仍需提醒本地安全边界。

署名：Codex
时间：2026-05-21 20:37:41 +08:00
