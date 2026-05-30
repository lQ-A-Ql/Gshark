# MCP 工具扩展开发报告 2026-05-30

## 概述

扩展本地 MCP (Model Context Protocol) 服务器的工具集，新增 8 个工具覆盖威胁狩猎、C2 分析、对象导出、流解码、媒体会话等核心取证能力。

## 新增工具清单

### 高优先级（4 个）

| 工具名 | 类型 | 说明 |
|--------|------|------|
| `threat.hunting_hits` | 只读 | 执行威胁狩猎，返回 YARA + 前缀匹配命中结果 |
| `c2.candidates` | 只读 | 列出 C2 候选流（支持 family 过滤、最低置信度、数量限制） |
| `objects.list` | 只读 | 列出从流量中提取的文件对象及元数据 |
| `tooling.winrm_decrypt` | 写入 | 用 NTLM 凭据解密 WinRM 会话 |

### 中优先级（4 个）

| 工具名 | 类型 | 说明 |
|--------|------|------|
| `capture.filter_count` | 只读 | 统计匹配显示过滤器的包数量（不返回包内容） |
| `stream.decode` | 只读 | 运行流解码器（base64/冰蝎/蚁剑/哥斯拉/auto） |
| `c2.decrypt` | 写入 | 用提供的密钥解密 C2 流量（CobaltStrike/VShell） |
| `media.sessions` | 只读 | 列出媒体会话（RTP/RTSP 音视频） |

## 架构决策

### 接口扩展策略

MCP 包（`internal/mcp`）保持只依赖 `internal/model`，不直接导入 `internal/engine`。对于 `stream.decode` 工具，通过 `Dependencies.StreamDecode` 函数字段注入，由 transport 层在初始化时桥接到 `engine.DecodeStreamPayload`。

### 新增 MCP 接口方法

- `DetectionService`: 新增 `ThreatHuntWithContext`、`ObjectsWithContext`、`GetHuntingRuntimeConfig`
- `AnalysisService`: 新增 `C2Decrypt`
- `MediaService`: 新增 `MediaAnalysis`
- `ToolAnalysisService`: 新增 `RunWinRMDecryptWithContext`

所有方法在 transport 层的 `services.go` 接口中已存在，`engine.Service` 已满足，无需新增实现代码。

### 写操作标注

`tooling.winrm_decrypt` 和 `c2.decrypt` 标记为 `readOnlyHint: false, idempotentHint: false`，因为它们会产生解密结果文件或修改缓存状态。

## 修改文件

| 文件 | 变更 |
|------|------|
| `backend/internal/mcp/server.go` | 扩展接口定义、新增 8 个工具定义和执行逻辑、添加 `boolValue` helper |
| `backend/internal/transport/http_server.go` | 接入 `StreamDecode` 函数字段到 MCP Dependencies |
| `backend/internal/transport/http_contract_test.go` | 新增 `TestMCPExpandedToolsContract` 和 `TestMCPExpandedToolsListIncludesNewTools` |
| `CLAUDE.md` | 补充前端架构边界规则、size budget、integrations 层、后端治理等文档 |

## 测试验证

- 新增 2 个测试函数，覆盖 6 个工具的端到端调用合约 + 8 个工具的 tools/list 注册验证
- 全量后端测试通过（architecture + engine + governance + transport + tshark + yara）
- `gofmt` 合规
- 架构边界测试通过

## 后续可扩展方向

- `threat.yara_rules`: 列出已加载 YARA 规则元数据
- `report.generate`: 生成调查报告
- `misc.invoke`: 运行 MISC 模块
- `objects.content`: 获取对象文件内容
