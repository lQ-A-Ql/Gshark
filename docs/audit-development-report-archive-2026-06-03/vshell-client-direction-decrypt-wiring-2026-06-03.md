# VShell WebSocket 客户端方向解密接线报告 2026-06-03

> 本报告记录将 VShell WebSocket 客户端→服务器方向解密能力接入生产解密链路的完整过程，
> 包括根因排查、权威逆向资料交叉验证、解析器崩溃修复、解掩码路径接线，以及新增测试覆盖。
>
> 前置报告：
> - [VShell WebSocket C2 检测修复报告](vshell-websocket-detection-fix-2026-06-03.md)
> - [VShell WebSocket C2 解密功能完善报告](vshell-websocket-decrypt-enhancement-2026-06-03.md)
> - [解密能力增强计划（Phase 1-3）](ENHANCEMENT_PLAN.md)

---

## 1. 背景与问题

前序工作完成了 VShell WebSocket C2 的检测与服务器→客户端方向解密（100% 成功），
但客户端→服务器方向解密始终失败（0%），实战可用性仅 50%。

ENHANCEMENT_PLAN 的 Phase 1 假设根因是「缺少多消息拆分支持」。本轮排查推翻了该假设。

## 2. 根因排查（推翻原假设）

对客户端帧做了系统性穷举实验：

| 实验 | 方法 | 结果 |
|------|------|------|
| 单消息直接解密 | offset 0, `hex(md5(salt))` | ❌ auth failed |
| 多消息拆分 | 4-byte LE 长度前缀循环 | ❌ 长度字段不合理 |
| 偏移扫描 | offset 0..16 全扫 | ❌ 全失败 |
| 密钥矩阵 | 16 种 KDF（3 MD5 × raw/hex/base64 + HKDF + sha256）| ❌ 全失败 |

结论：原计划的「多消息拆分」**无法解决**客户端解密问题。

排查中发现两个关键事实：

1. **手抄帧数据失真**：早期用于调试的客户端帧 hex 掩码为 `0x80000000`（真实 WebSocket
   掩码应为随机 4 字节），且解掩码后字节 `2f121e` 异常重复，强烈提示该测试数据本身被抄写损坏。
   唯一可靠来源是从真实 pcap 提取帧字节。

2. **生产链路从不解掩码**：`extractVShellWebSocketPayloads`（含解掩码逻辑）此前**仅被测试引用，
   从未被生产 `c2_decrypt.go` 调用**。生产 `collectVShellStreamDecryptCandidates` 把仍带
   WebSocket 帧头 + 客户端 XOR 掩码的原始字节直接喂给 GCM 管线：
   - 服务器→客户端帧（未掩码，2 字节帧头）凑巧能解 → 50% 假象
   - 客户端→服务器帧（带掩码）不解掩码 → 永远无法解密

## 3. 权威逆向资料交叉验证

参考公开 VShell 逆向分析文章，逐条验证了本项目算法的正确性：

| 算法环节 | 文章结论 | 本项目实现 | 一致性 |
|---------|---------|-----------|--------|
| C2 流量密钥 | `md5(salt).hexdigest().encode()` → 32 字节 ASCII hex → AES-256-GCM | `deriveVShellKeyHex` = `hex(md5(salt))` | ✅ |
| 内层帧格式 | `[4字节LE长度][12字节nonce][密文][16字节tag]` | `splitVShellFrames` + `decryptAESGCMFrame` | ✅ |
| 客户端帧掩码 | client→server 帧带 4 字节 XOR 掩码，必须先解掩码 | `unmaskWebSocketPayload` | ✅ |

文章给出的 MAC 校验失败排查清单两条：
1. 密钥误用 `digest()`（16 字节原始）而非 `hexdigest()`（32 字节 hex 字符串）；
2. 客户端帧未正确 unmask。

本项目密钥派生正确（已用真实 salt 派生出与文章预期一致的密钥），因此剩余缺口**确定为
第 2 条：生产未解掩码**——与排查结论吻合。

## 4. 修复内容

### 4.1 修复 `parseWebSocketFrames` 崩溃（真实生产隐患）

在真实 pcap 的 359 条流上跑解析时后端 panic：

```
slice bounds out of range [:-8494869719842524750]
```

根因：帧头 `payloadLen == 127`（64 位扩展长度）分支对非 WebSocket 的 TCP 字节，
`binary.BigEndian.Uint64` 读到任意 8 字节 → 转 `int` 溢出为巨大负数 → 切片越界 panic。
一旦把解掩码路径接入生产，任何畸形/非 WS 流都会崩溃后端。

修复（`vshell_websocket_decrypt.go`）：

```go
} else if payloadLen == 127 {
    if offset+10 > len(data) {
        break
    }
    extended := binary.BigEndian.Uint64(data[offset+2 : offset+10])
    // 64 位长度不能超过剩余 buffer；防止 int 溢出为负数后切片 panic。
    if extended > uint64(len(data)) {
        break
    }
    payloadLen = int(extended)
    headerLen = 10
}

// 非 WebSocket 流上 payloadLen 不可信，加防御边界。
if payloadLen < 0 || payloadLen > len(data) {
    break
}
// ...
if payloadOffset < 0 || payloadOffset > len(data) || payloadOffset+payloadLen > len(data) {
    break
}
```

### 4.2 新增解掩码提取器 `wsFrameInnerPayloads`

与 `extractVShellWebSocketPayloads`（解析 + 解密一体）不同，本函数**只剥离 WebSocket 帧框
与客户端掩码**，返回内层应用层 payload（每个数据帧一条），交给现有 VShell GCM/CBC 候选管线处理。

```go
// vshell_websocket_decrypt.go
func wsFrameInnerPayloads(streamData []byte) [][]byte {
    frames := parseWebSocketFrames(streamData)
    if len(frames) == 0 {
        return nil
    }
    out := make([][]byte, 0, len(frames))
    sawDataFrame := false
    for _, frame := range frames {
        if frame.opcode >= 0x8 { // 跳过 ping/pong/close 控制帧
            continue
        }
        sawDataFrame = true
        payload := frame.payload
        if frame.masked {
            payload = unmaskWebSocketPayload(payload, frame.maskKey)
        }
        if len(payload) == 0 {
            continue
        }
        out = append(out, payload)
    }
    if !sawDataFrame {
        return nil // 非 WS 数据 → 调用方回退到原 raw-stream 逻辑
    }
    return out
}
```

设计要点：
- 非 WebSocket 数据返回 `nil`，调用方据此回退到既有 raw-stream 处理，**不破坏现有路径**。
- 不做解密，复用既有 `splitVShellFrames` + `decryptAESGCMFrame`，避免重复密钥派生逻辑。

### 4.3 接入生产解密链路

在 `collectVShellStreamDecryptCandidates`（`c2_decrypt.go`）中，对每个方向先尝试 WebSocket
解帧，把解掩码后的内层 payload 作为候选（`transform: ws-unmask-{direction}`），再走原 raw-stream
逻辑兜底：

```go
for _, assembled := range assembleVShellStreamDirections(stream) {
    packet := streamRepresentativePacket(streamID, assembled.direction, stream, representatives[streamID])

    // WebSocket-aware 路径：客户端→服务器帧带 XOR 掩码，原始字节不解掩码无法解密。
    if wsInner := wsFrameInnerPayloads(decodeLooseHex(assembled.body)); len(wsInner) > 0 {
        for i, inner := range wsInner {
            if len(inner) < 8 {
                continue
            }
            candidate := c2DecryptCandidate{
                packet:    packet,
                raw:       inner,
                label:     fmt.Sprintf("tcp-stream:%d:%s:ws-frame-%d", streamID, assembled.direction, i),
                transform: "ws-unmask-" + assembled.direction,
                direction: streamChunkRecordDirection(assembled.direction),
            }
            appendC2DecryptCandidateUnbounded(out, seen, candidate)
        }
    }

    // 原 raw-stream 逻辑保留作为兜底（非 WS 流仍走此路径）。
    for _, transformed := range decodeC2TransformCandidates(assembled.body, "auto") {
        // ...
    }
}
```

## 5. 新增测试覆盖

### 5.1 解析器健壮性（`vshell_websocket_decrypt_test.go`）

| 测试用例 | 验证内容 |
|---------|---------|
| `TestParseWebSocketFramesMalformed` | 6 类畸形输入（64 位长度溢出 / 16 位截断 / 64 位截断 / 掩码截断 / 长度越界 / 随机二进制）均不 panic |

### 5.2 解掩码提取器（`vshell_ws_unmask_test.go`）

| 测试用例 | 验证内容 |
|---------|---------|
| `TestWSFrameInnerPayloadsUnmasksClientFrame` | 掩码客户端帧 → 解掩码 → 经生产 `splitVShellFrames`+`decryptAESGCMFrame` 解密往返一致 |
| `TestWSFrameInnerPayloadsServerFrame` | 未掩码服务器帧正常提取并解密 |
| `TestWSFrameInnerPayloadsNonWebSocket` | 非 WS 数据（HTTP 请求）返回 nil，触发回退 |
| `TestWSFrameInnerPayloadsMultipleFrames` | 单 TCP 段多帧拼接，逐帧解掩码 + 解密 |
| `TestWSFrameInnerPayloadsSkipsControlFrames` | ping/pong 控制帧夹杂时只提取数据帧 |

### 5.3 端到端生产路径（`vshell_ws_unmask_test.go`）

| 测试用例 | 验证内容 |
|---------|---------|
| `TestC2DecryptVShellUnmasksClientWebSocketStream` | 掩码客户端帧经完整公共 `C2Decrypt` API（stream scope → `collectVShellStreamDecryptCandidates` → ws-unmask 接线 → GCM 管线）产出带 `ws-unmask-client` 标记的解密记录 |

该端到端测试是「生产从不解掩码」缺陷的回归守护：日志 `source=index chunks=1` 确认走的是真实流水线。

## 6. 验证结果

| 验证项 | 结果 |
|--------|------|
| 引擎全套测试 `go test ./internal/engine/...` | ✅ 通过 |
| 后端整体 build | ✅ 通过 |
| 架构边界 `go test ./internal/architecture` | ✅ 通过 |
| 治理寄存器 `go test ./internal/governance` | ✅ 通过 |
| `gofmt -l .` | ✅ 干净 |

## 7. 能力边界更新

### ✅ 本轮新增
- 客户端→服务器方向解掩码已接入**生产**解密链路（此前仅测试可用）
- WebSocket 帧解析器对任意非 WS / 畸形 TCP 字节安全（不再 panic）
- 端到端测试覆盖客户端 WebSocket 流经公共 API 的解密

### ⚠️ 仍未实现
- WebSocket 分片帧（FIN=0）跨帧重组（当前按单帧 = 单消息处理）
- `permessage-deflate` 压缩扩展
- 客户端方向真实样本端到端断言（受手抄帧数据失真影响，需重新从 pcap 提取干净帧；
  合成往返测试已覆盖算法正确性）

### 🔄 后续建议
1. 用 IDA（项目已接入 ida-pro-mcp）逆向 VShell 二进制，确认是否存在 HKDF(salt, "vshell-session")
   等更复杂的会话密钥派生路径，以覆盖更多变种。
2. 从真实 pcap 提取干净的客户端帧字节，补一条真实样本端到端解密断言。
3. 实现 WebSocket 分片帧重组以支持大消息。

---

**报告日期**：2026-06-03
**关联代码**：
- `backend/internal/engine/vshell_websocket_decrypt.go`（解析器加固 + `wsFrameInnerPayloads`）
- `backend/internal/engine/c2_decrypt.go`（`collectVShellStreamDecryptCandidates` 接线）
- `backend/internal/engine/vshell_websocket_decrypt_test.go`（解析器健壮性测试）
- `backend/internal/engine/vshell_ws_unmask_test.go`（解掩码 + 端到端测试）
