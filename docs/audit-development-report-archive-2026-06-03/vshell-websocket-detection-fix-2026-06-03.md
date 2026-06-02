# VShell WebSocket C2 检测修复报告 2026-06-03

## 概述

修复 VShell WebSocket C2 通道的检测漏报问题。针对 WebSocket VShell 样本 `challenge.pcap` 进行分析和修复。

## 问题分析

### 根因 1：WebSocket 协议被标记为 "OTHER"

tshark 输出 WebSocket 数据帧的列协议为 "WebSocket"，`normalizeProto("websocket")` 没有匹配任何 case，返回 "OTHER"。

- 修复：`normalize.go` 新增 `websocket` → `"WebSocket"` 映射（独立协议，不映射为 HTTP）

### 根因 2：同一 TCP 流被拆到不同 stream key

旧的 stream key 格式 `"%s:%d", Protocol, StreamID` 导致：
- HTTP 握手帧 → `"HTTP:208"`
- WebSocket 数据帧 → `"WebSocket:208"`
- TCP ACK/重传 → `"TCP:208"`

三个 key 对应同一个 TCP 流，但流级心跳分析只能看到其中一个分组的数据。

- 修复：stream key 改为 `"stream:%d", StreamID`，按纯 stream ID 分组
- 新增 `streamHasTCPProtocol()` 检查流中是否有 TCP/HTTP/WebSocket/TLS 包

### 根因 3：心跳检测阈值过严

WebSocket 心跳间隔因 TCP 重传被拉长（部分间隔达 22s），简单平均值 avg=12.25s 超出旧阈值 [8, 12]。

- 修复：新增 `filterOutlierIntervals()` 过滤 >2 倍中位数的异常间隔
- 心跳阈值放宽到 [8, 14] 秒

## 修复效果

| 指标 | 修复前 | 修复后 |
|------|--------|--------|
| WebSocket 帧 Protocol | OTHER | WebSocket |
| stream key 分组 | 按协议名拆分 3 组 | 按 stream ID 合并 1 组 |
| VShell heartbeat 检测 | 0 | 1（avg=10.8s） |
| WebSocket 握手候选 | conf=82 ✓ | conf=82 ✓ |
| 总 VShell 候选 | 1559 | 1560（+1 heartbeat） |

## 修改文件

| 文件 | 变更 |
|------|------|
| `backend/internal/tshark/normalize.go` | `normalizeProto` 新增 `websocket` case |
| `backend/internal/tshark/parse_ek.go` | Protocol 字段使用 `normalizeProto(protocol)` 而非 `normalizeProto(FirstNonEmpty(displayProtocol, protocol))` |
| `backend/internal/engine/tool_c2.go` | stream key 改为纯 stream ID；新增 `streamHasTCPProtocol()`、`filterOutlierIntervals()`；心跳阈值放宽到 [8,14] |
| `backend/internal/engine/vshell_ws_e2e_test.go` | 新增：WebSocket VShell 端到端检测测试 |

## 技术决策

- WebSocket 作为独立协议（不是 HTTP 别名），因为握手完成后是独立的二进制帧协议
- Stream key 不混入协议名，避免同一 TCP 流被拆分
- 心跳检测支持 burst 模式：先过滤短间隔（<3s），再过滤异常值（>2x 中位数）
