# meow~traffic 本地 MCP 接入文档 v1

> 品牌已更名为 `meow~traffic`；本文档中涉及的 `github.com/gshark/sentinel/...`、`GSHARK_*`、`gshark-sentinel`、`sentinel-backend.exe` 等名称仍是当前真实可用的内部兼容标识，本轮不迁移。

本文档描述当前 `meow~traffic` 本地 MCP 的真实落地形态，重点覆盖：

- MCP 的本地只读边界与启用方式
- `/api/mcp` 与 `/api/mcp/config` 的职责分离
- 当前真实可用的 `tools / resources / prompts`
- Codex、MCP Inspector 和通用 HTTP 客户端的接入方式
- 鉴权、截断、取消与常见问题

## 1. 设计边界

当前 MCP 是“本机优先 + 只读分析”的本地服务：

- 仅监听本机 loopback
- 默认关闭
- 传输方式为 `Streamable HTTP`
- 复用后端现有 bearer token
- 启用态只保存在当前后端进程内，前端不做本地持久化或启动自动重放
- 不提供 remote bind
- 不提供 stdio bridge
- 不提供写操作、抓包控制、插件管理、配置保存、导出落盘等高风险行为

当前端或外部 MCP 客户端调用本地 MCP 时，应该把它视为：

- 面向离线流量分析工作台的只读查询层
- 适合 LLM 做上下文挂载、按需深查、协议/证据总结
- 不适合承载配置写入和系统管理动作

## 2. 端点与职责

### 2.1 MCP JSON-RPC 端点

- `POST /api/mcp`

职责：

- 只负责 MCP JSON-RPC 请求
- 支持 `initialize`、`initialized`、`ping`
- 支持 `tools/list`、`tools/call`
- 支持 `resources/list`、`resources/templates/list`、`resources/read`
- 支持 `prompts/list`、`prompts/get`

当前实现位置：

- [backend/internal/mcp/server.go](/C:/Users/QAQ/Desktop/gshark/backend/internal/mcp/server.go:1)
- [backend/internal/transport/http_server.go](/C:/Users/QAQ/Desktop/gshark/backend/internal/transport/http_server.go:313)

### 2.2 MCP 配置/状态端点

- `GET /api/mcp/config`
- `POST /api/mcp/config`

职责：

- 读取 MCP 当前状态
- 开启或关闭 MCP
- 不承载 MCP JSON-RPC
- 与 `/api/mcp` 一样受统一 bearer 鉴权保护

当前 `POST` 只接受：

```json
{
  "enabled": true
}
```

当前实现位置：

- [backend/internal/transport/http_server.go](/C:/Users/QAQ/Desktop/gshark/backend/internal/transport/http_server.go:296)
- [backend/internal/engine/mcp_config.go](/C:/Users/QAQ/Desktop/gshark/backend/internal/engine/mcp_config.go:1)

## 3. 鉴权模型

本地 MCP 复用后端 bearer token。

`/api/mcp` 与 `/api/mcp/config` 都走后端统一鉴权；只有 `/health` 是全局鉴权例外。

当后端配置了 `GSHARK_BACKEND_TOKEN`，以下鉴权方式都可用：

1. `Authorization: Bearer <token>`
2. `X-GShark-Auth: <token>`
3. query `access_token=<token>`

推荐统一使用 `Authorization: Bearer <token>`。

鉴权行为实现位置：

- [backend/internal/transport/http_server.go](/C:/Users/QAQ/Desktop/gshark/backend/internal/transport/http_server.go:1093)

## 4. 启用与状态

当前 MCP 默认关闭，启用态以后端当前进程内状态为准。前端设置页只在用户显式点击开关时写入 `/api/mcp/config`，不会从 `localStorage` 自动恢复或重放启用态。

启用后端点固定为：

- `http://127.0.0.1:17891/api/mcp`

该端点当前不是动态发现结果；如修改后端监听端口，需要同步调整实现与文档。

`GET /api/mcp/config` 返回的核心状态字段包括：

- `config.enabled`
- `enabled`
- `endpoint`
- `transport`
- `auth_required`
- `read_only`
- `remote_supported`
- `stdio_supported`
- `last_error`

当前固定语义：

- `endpoint = http://127.0.0.1:17891/api/mcp`
- `transport = streamable-http`
- `read_only = true`
- `remote_supported = false`
- `stdio_supported = false`

数据结构定义位置：

- [backend/internal/model/types.go](/C:/Users/QAQ/Desktop/gshark/backend/internal/model/types.go:110)

## 5. 协议能力

当前 `initialize` 响应声明：

- `protocolVersion = 2025-06-18`
- `tools.listChanged = false`
- `resources.listChanged = false`
- `resources.subscribe = false`
- `prompts.listChanged = false`

说明：

- 当前不支持 `resources/subscribe`
- 当前 tool / resource / prompt 列表是静态集

## 6. Tools

当前所有工具均为只读，并附带：

- `annotations.readOnlyHint = true`
- `annotations.idempotentHint = true`

### 6.1 runtime.*

#### `runtime.snapshot`

用途：

- 读取运行时工具依赖快照

参数：

```json
{
  "mode": "fast"
}
```

`mode` 可选值：

- `fast`
- `full`

### 6.2 capture.*

#### `capture.status`

用途：

- 读取当前抓包状态

#### `capture.packet_page`

用途：

- 按 cursor 分页读取包列表

参数：

```json
{
  "cursor": 0,
  "limit": 50,
  "filter": "http"
}
```

#### `capture.packet`

用途：

- 按包号读取单包摘要

参数：

```json
{
  "packet_id": 12
}
```

#### `capture.packet_raw_hex`

用途：

- 按包号读取原始十六进制

#### `capture.packet_layers`

用途：

- 按包号读取协议层解码结果

#### `capture.stream_ids`

用途：

- 读取指定协议的 stream id 列表

参数：

```json
{
  "protocol": "HTTP"
}
```

`protocol` 可选值：

- `HTTP`
- `TCP`
- `UDP`

### 6.3 stream.*

#### `stream.http`

用途：

- 读取重组后的 HTTP stream

参数：

```json
{
  "stream_id": 14
}
```

返回通常包含：

- `stream_id`
- `protocol`
- `from`
- `to`
- `chunks`
- `request`
- `response`

#### `stream.raw`

用途：

- 读取完整 TCP/UDP raw stream

参数：

```json
{
  "protocol": "TCP",
  "stream_id": 3
}
```

#### `stream.raw_page`

用途：

- 分页读取 TCP/UDP raw stream chunk

参数：

```json
{
  "protocol": "TCP",
  "stream_id": 3,
  "cursor": 0,
  "limit": 1024
}
```

#### `stream.payload_sources`

用途：

- 读取可疑 payload source 候选

参数：

```json
{
  "limit": 50
}
```

### 6.4 analysis.*

#### `analysis.traffic`

用途：

- 读取全局流量统计

#### `analysis.industrial`

用途：

- 读取工控分析结果

#### `analysis.vehicle`

用途：

- 读取车机分析结果

#### `analysis.usb`

用途：

- 读取 USB 分析结果

参数：

```json
{
  "hid_source": "auto",
  "hid_event_limit": 2000
}
```

`hid_source` 可选值：

- `auto`
- `usbhid`
- `capdata`
- `btatt`
- `raw`

#### `analysis.c2_overview`

用途：

- 读取 C2 样本分析概览

#### `analysis.apt`

用途：

- 读取 APT 分析结果

#### `analysis.evidence`

用途：

- 读取统一证据记录

参数：

```json
{
  "modules": ["c2", "industrial"]
}
```

### 6.5 tooling.*

#### `tooling.ntlm_sessions`

用途：

- 读取 NTLM session material 列表

#### `tooling.http_login`

用途：

- 读取 HTTP 登录行为分析

#### `tooling.smtp`

用途：

- 读取 SMTP 会话分析

#### `tooling.mysql`

用途：

- 读取 MySQL 会话分析

#### `tooling.shiro`

用途：

- 读取 Shiro rememberMe 分析

参数：

```json
{
  "candidate_keys": ["kPH+bIxk5D2deZiIxcaaaA=="]
}
```

#### `tooling.smb3_candidates`

用途：

- 读取 SMB3 session candidate 列表

## 7. Resources

当前资源适合挂“紧凑上下文”，而不是一次性取走整份大数据。

### 7.1 固定资源

- `meow://runtime/snapshot`
- `meow://capture/status`
- `meow://analysis/evidence`
- `meow://catalog/misc-modules`
- `meow://catalog/plugins`
- `meow://audit/recent`

### 7.2 模板资源

- `meow://packet/{id}`
- `meow://stream/{protocol}/{id}`

示例：

- `meow://packet/609`
- `meow://stream/HTTP/14`
- `meow://stream/TCP/3`

说明：

- `meow://stream/{protocol}/{id}` 当前支持 `HTTP`、`TCP`、`UDP`
- `resources/read` 返回 `mimeType = application/json`

## 8. Prompts

当前仅保留高频分析入口：

### `triage_capture`

用途：

- 用于抓包总览、风险归纳和下一步 pivot 建议

可选参数：

```json
{
  "focus": "c2"
}
```

### `inspect_suspicious_stream`

用途：

- 用于单条可疑流复核

参数：

```json
{
  "protocol": "HTTP",
  "stream_id": 14
}
```

### `summarize_evidence`

用途：

- 用于把当前 evidence 结果整理成调查摘要

可选参数：

```json
{
  "modules": "c2,industrial"
}
```

## 9. 通用调用示例

### 9.1 读取 MCP 状态

```powershell
$token = $env:GSHARK_BACKEND_TOKEN
Invoke-WebRequest -UseBasicParsing `
  -Uri 'http://127.0.0.1:17891/api/mcp/config' `
  -Headers @{ Authorization = "Bearer $token" } `
  -Method GET
```

### 9.2 启用 MCP

```powershell
$token = $env:GSHARK_BACKEND_TOKEN
Invoke-WebRequest -UseBasicParsing `
  -Uri 'http://127.0.0.1:17891/api/mcp/config' `
  -Headers @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' } `
  -Method POST `
  -Body '{"enabled":true}'
```

### 9.3 列工具

```powershell
$token = $env:GSHARK_BACKEND_TOKEN
$headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
$body = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
Invoke-WebRequest -UseBasicParsing `
  -Uri 'http://127.0.0.1:17891/api/mcp' `
  -Headers $headers `
  -Method POST `
  -Body $body
```

### 9.4 读取当前抓包状态

```powershell
$token = $env:GSHARK_BACKEND_TOKEN
$headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
$body = '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"capture.status","arguments":{}}}'
Invoke-WebRequest -UseBasicParsing `
  -Uri 'http://127.0.0.1:17891/api/mcp' `
  -Headers $headers `
  -Method POST `
  -Body $body
```

### 9.5 读取 HTTP stream payload

```powershell
$token = $env:GSHARK_BACKEND_TOKEN
$headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
$body = '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"stream.http","arguments":{"stream_id":14}}}'
Invoke-WebRequest -UseBasicParsing `
  -Uri 'http://127.0.0.1:17891/api/mcp' `
  -Headers $headers `
  -Method POST `
  -Body $body
```

## 10. Codex 接入示例

如果需要把当前项目 MCP 接入 Codex，可使用：

```powershell
codex mcp add meow-traffic --url http://127.0.0.1:17891/api/mcp --bearer-token-env-var GSHARK_BACKEND_TOKEN
```

写入后的等效配置如下：

```toml
[mcp_servers.meow-traffic]
url = "http://127.0.0.1:17891/api/mcp"
bearer_token_env_var = "GSHARK_BACKEND_TOKEN"
```

说明：

- 已启动的 Codex 进程通常需要重启后才会继承新的用户环境变量
- 若 bearer token 轮换，需要同步更新 `GSHARK_BACKEND_TOKEN`

## 11. MCP Inspector / 第三方客户端接入

接入要点：

1. 使用 `Streamable HTTP`
2. 端点填写 `http://127.0.0.1:17891/api/mcp`
3. Header 增加 `Authorization: Bearer <token>`
4. 先调 `tools/list` 与 `resources/list`
5. 再按需调用 `capture.status`、`capture.packet_page`、`stream.http`、`analysis.evidence`

推荐 smoke 顺序：

1. `initialize`
2. `tools/list`
3. `resources/list`
4. `tools/call: capture.status`
5. `tools/call: capture.stream_ids`
6. `tools/call: stream.http` 或 `stream.raw`

## 12. 返回体与工程约束

### 12.1 文本截断

`tools/call` 返回体中的 `content[0].text` 会被截断到 `200000` 字符以内，超出部分追加：

```text
...<truncated>
```

因此：

- 大流、大 payload、大 evidence 结果不应只依赖 `content.text`
- 需要优先使用 `structuredContent`

### 12.2 取消语义

MCP tool 调用会透传 HTTP request context。

这意味着：

- 客户端取消请求时，后端会把取消继续传给支持 `WithContext` 的分析逻辑
- 新增 HTTP handler / tool 映射时必须优先使用 `WithContext` 变体

### 12.3 只读承诺

当前 MCP 不应暴露：

- 上传抓包
- 开始/停止抓包
- 保存运行时配置
- 保存 TLS / 解密配置
- 插件增删改
- MISC 包导入
- 任意导出落盘

如果后续扩展写操作，应单独做权限与审计设计，不应默认追加到当前本地只读 MCP。

## 13. 常见问题

### 13.1 `GET /api/mcp/config` 返回 `401 unauthorized`

原因：

- bearer token 缺失或不匹配

处理：

- 检查 `GSHARK_BACKEND_TOKEN`
- 检查客户端是否传了 `Authorization: Bearer <token>`

### 13.2 `POST /api/mcp` 返回 `404 mcp endpoint is disabled`

原因：

- MCP 尚未启用

处理：

- 先 `POST /api/mcp/config`，body 为 `{"enabled":true}`

### 13.3 `POST /api/mcp` 返回 `503 mcp server is unavailable`

原因：

- 后端 MCP server 未正确初始化

处理：

- 检查后端版本与启动日志
- 核对 [backend/internal/mcp/server.go](/C:/Users/QAQ/Desktop/gshark/backend/internal/mcp/server.go:1) 是否已包含当前实现

### 13.4 能连上但读不到抓包

原因通常包括：

- 当前还没有已提交的抓包
- 抓包仍在解析或 enrichment 中
- 调用的是错误 stream id

建议先调用：

1. `capture.status`
2. `capture.packet_page`
3. `capture.stream_ids`

## 14. 当前实现对应位置

- MCP 协议服务： [backend/internal/mcp/server.go](/C:/Users/QAQ/Desktop/gshark/backend/internal/mcp/server.go:1)
- 路由挂载与鉴权： [backend/internal/transport/http_server.go](/C:/Users/QAQ/Desktop/gshark/backend/internal/transport/http_server.go:157)
- MCP 状态模型： [backend/internal/model/types.go](/C:/Users/QAQ/Desktop/gshark/backend/internal/model/types.go:110)
- MCP 配置读写： [backend/internal/engine/mcp_config.go](/C:/Users/QAQ/Desktop/gshark/backend/internal/engine/mcp_config.go:1)
- 设置页 MCP 区块： [frontend/src/app/components/MCPSettingsSection.tsx](/C:/Users/QAQ/Desktop/gshark/frontend/src/app/components/MCPSettingsSection.tsx:1)
- 运行时设置侧栏逻辑： [frontend/src/app/components/useRuntimeSettingsSidebarModel.ts](/C:/Users/QAQ/Desktop/gshark/frontend/src/app/components/useRuntimeSettingsSidebarModel.ts:1)
