# MCP 六项审计问题收口报告

## 本轮目标

按快速审计结论收口 MCP 首版的六项一致性与覆盖缺口：

- MCP 启用态以后端为唯一事实源
- 固定 endpoint 策略测试化、文档化
- `/api/mcp` 与 `/api/mcp/config` 鉴权边界明确化
- 前端 HTTP fallback 与 Wails IPC 的 MCP 状态映射保持一致
- 文档移除前端 `localStorage` 启动重放语义
- 保持本地只读、默认关闭、不提供 remote / stdio / 写操作的首版边界

## 实际改动

1. 前端状态源收口
   - `useBackendLifecycleStartupEffect` 启动时只读取后端 `getMCPStatus()`。
   - 删除 `frontend/src/app/state/mcpStorage.ts`。
   - 设置页开关仍通过用户显式操作调用 `saveMCPConfig({ enabled })`。
   - `useRuntimeSettingsSidebarModel` 不再把 MCP 启用态写入 `localStorage`。

2. 后端契约测试补强
   - `TestMCPConfigContract` 固定默认 disabled、固定 endpoint、transport 与只读能力标志。
   - 新增 `TestMCPConfigContractAuthRequired`，确认 `/api/mcp/config` 受 bearer token 保护，且 `/health` 仍是全局鉴权例外。

3. 前端桥接测试补强
   - `useBackendLifecycle` 新增陈旧 `gshark.mcp-config.v1` 不会回写后端的启动测试。
   - `desktopBridge` 新增 HTTP fallback 与 Wails IPC MCP status 归一结果一致性测试。

4. 文档修订
   - `docs/mcp-interface.md` 明确 `/api/mcp` 与 `/api/mcp/config` 均受统一 bearer 鉴权保护。
   - 明确 MCP 启用态只保存在后端当前进程内，前端不做本地持久化或启动自动重放。
   - 明确 endpoint 当前固定为 `http://127.0.0.1:17891/api/mcp`，不是动态发现。
   - 修正 2026-05-21 MCP 本地归档中已过期的前端持久化描述。

## 验证结果

已通过：

```powershell
cd backend; go test ./internal/transport
cd frontend; pnpm exec vitest run src/app/state/hooks/useBackendLifecycle.test.tsx src/app/integrations/desktopBridge.test.ts src/app/integrations/clients/toolRuntimeClient.test.ts
cd backend; go test ./...
cd frontend; pnpm run test:run
cd frontend; pnpm run typecheck
cd frontend; pnpm run lint
cd frontend; pnpm run format:check
git diff --check
```

## 审计结论

- P0/P1 鉴权绕过：未发现。
- MCP 默认关闭：后端默认 disabled，且陈旧前端本地缓存不会再自动改变后端状态。
- 配置面职责：`/api/mcp/config` 只做状态读写，不承载 JSON-RPC。
- JSON-RPC 面职责：`/api/mcp` 只在 enabled 后处理 MCP JSON-RPC，关闭态返回 disabled。
- endpoint 策略：本轮保持固定 `127.0.0.1:17891`，并在测试和文档中明确。
- 只读边界：未新增写操作、远程监听、stdio bridge、订阅或导出落盘能力。

署名：Codex
时间：2026-05-24 20:23:19 +08:00
