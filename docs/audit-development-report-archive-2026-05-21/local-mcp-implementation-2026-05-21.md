# meow~traffic 本地 MCP 实施报告

## 本轮目标

按既定方案在 `meow~traffic` 中落地首版本地只读 MCP：

- 后端提供默认关闭的本机 `Streamable HTTP` MCP 入口
- 设置页新增 MCP 开关与连接信息展示
- 复用现有 bearer token，不做远程绑定与 stdio bridge
- 将现有只读分析能力映射为 `tools / resources / prompts`

## 实际改动摘要

1. 后端 MCP 服务与控制面
   - 新增 `backend/internal/mcp/server.go`
   - MCP JSON-RPC 入口挂载到 `/api/mcp`
   - 单独新增 `/api/mcp/config` 作为配置/状态控制面
   - 新增 `MCPConfig`、`MCPStatus` 模型与 `engine` 配置读写方法
   - 运行状态默认本机 loopback、只读、禁用 remote 与 stdio

2. MCP 协议能力
   - 已实现 `initialize`、`initialized`、`ping`
   - 已实现 `tools/list`、`tools/call`
   - 已实现 `resources/list`、`resources/templates/list`、`resources/read`
   - 已实现 `prompts/list`、`prompts/get`
   - 工具分组覆盖 `runtime.*`、`capture.*`、`stream.*`、`analysis.*`、`tooling.*`
   - 资源覆盖运行时快照、抓包状态、证据摘要、MISC 模块、插件目录、最近审计，以及 packet/stream 模板资源

3. 前端设置页与状态流
   - 新增运行时设置中的 MCP 独立区块
   - 支持本地启用开关、端点显示、token 脱敏展示、复制端点、复制 token、刷新状态
   - 启动时读取后端 MCP 状态；后续审计已收口为不再读取前端本地持久化配置或自动同步回后端
   - `SentinelContext` 与 backend lifecycle 已完整暴露 `mcpStatus`、`refreshMCPStatus`、`saveMCPConfig`

4. 桌面桥接
   - Wails 桌面代理新增 `GetMCPStatus`、`UpdateMCPConfig`
   - 前端 runtime client、desktop bridge、backend bridge transport 已打通 MCP 状态读写

## 测试与验证

已补充并通过：

- 后端 transport contract test
  - `/api/mcp/config` GET/POST
  - `/api/mcp` 禁用态 404
  - `/api/mcp` 鉴权要求
  - `initialize`、`tools/list`、`resources/list`、`prompts/list`
  - `tools/call`
  - 长 payload 截断
  - 取消语义向 MCP tool 层透传
- 前端测试
  - `useBackendLifecycleControls` 的 MCP 状态刷新/保存
  - `useBackendLifecycle` 启动读取后端 MCP 状态
  - `RuntimeSettingsSections` 中 MCP 区块渲染与交互
  - runtime client / desktop bridge 的 MCP 映射

已执行验证命令：

```powershell
go test -tags dev ./...
cd backend && go test ./...
cd frontend && pnpm run test:run
cd frontend && pnpm run typecheck
```

结果：

- Root Go tests：通过
- Backend Go tests：通过
- Frontend Vitest：225 文件 / 699 测试全部通过
- Frontend typecheck：通过

## 设计落地说明

- `/api/mcp` 仅负责 JSON-RPC，不承担配置写入
- 配置写入统一走 `/api/mcp/config`
- MCP 首版坚持“本机优先 + 只读分析”
- 资源默认返回紧凑摘要，深数据仍通过分页或按 ID 工具查询
- 设置 UI 不暴露远程地址配置，也不暴露 stdio 入口

## 最新文档复评

本轮开发前再次复读：

- `docs/public-sample-corpus-2026-05-06.md`
- `docs/automotive-analysis-plan.md`

复评结论：

1. `public-sample-corpus-2026-05-06.md`
   - 仍然适合作为本地 MCP smoke 数据池
   - 其中的 USB、Industrial、HTTP/Object、Vehicle 样本都适合用来验证 `tools/list` 之后的只读查询链路
   - 后续可以直接拿它补一份 MCP Inspector 手工联调脚本，不需要额外找样本

2. `automotive-analysis-plan.md`
   - 与当前 MCP 资源/工具分层没有冲突
   - 车机分析的 DoIP / UDS / CAN / J1939 分层正好适合后续继续扩充 `analysis.vehicle` 及 `meow://analysis/evidence` 的消费路径
   - 建议后续为车机事务视图补一个专用 prompt 模板，但不属于本轮首版范围

## 后续建议

1. 增加 MCP Inspector 手工联调脚本与截图留档
2. 视需要补 `resources/subscribe` 或更细粒度分页工具，但仍保持只读
3. 为车机 / 工控高价值场景补专门 prompt 模板与 smoke 样本流程

署名：Codex
时间：2026-05-21 20:18:05 +08:00
