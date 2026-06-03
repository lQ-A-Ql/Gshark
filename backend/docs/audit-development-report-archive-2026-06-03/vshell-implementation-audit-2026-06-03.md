# VShell 检测和解密实现审计报告

## 🔍 审计时间
2026-06-03

## 📋 审计范围
- VShell WebSocket C2 检测逻辑 (`tool_c2.go`)
- VShell 解密实现 (`c2_decrypt.go`, `vshell_websocket_decrypt.go`)
- 端到端测试覆盖 (`vshell_decrypt_e2e_test.go`, `vshell_ws_e2e_test.go`)

---

## ⚠️ 发现的潜在不足

### 1. 【高优先级】客户端掩码帧解密失败

**问题描述**：
测试输出显示客户端→服务器的掩码帧无法解密：
```
Client TCP segment: 171 bytes, found 1 WebSocket frames
Frame 0: masked=true payload=159 bytes mask=80000000
Could not decrypt (data prefix: fc2f121e672f121eb380f0b9289c95eb)
```

**根因分析**：
1. **掩码处理正确但解密逻辑有问题**：
   - `unmaskWebSocketPayload()` 正确执行了 XOR 解掩码
   - 但解密后的数据前缀 `fc2f121e...` 表明可能是：
     - 掩码密钥不正确（测试中硬编码为 `0x80000000`）
     - VShell 消息格式与预期不符
     - 需要额外的协议层处理

2. **缺少对多帧消息的处理**：
```go
// 当前代码只尝试单帧解密
plaintext, ok := decryptVShellWebSocketFrame(payload, gcm)
```
- 客户端帧（159字节）可能包含**多个 VShell 消息**
- 当前实现没有处理"一个 WebSocket 帧包含多个 VShell 加密消息"的情况

**影响**：
- 仅能解密服务器→客户端的 `hb_ack` 消息
- 无法解密客户端→服务器的命令响应
- 实战场景下会漏掉关键的 C2 通信内容

**修复建议**：
```go
// 建议：在解密失败后尝试多消息拆分
func decryptVShellWebSocketFrame(payload []byte, gcm cipher.AEAD) ([][]byte, bool) {
    results := [][]byte{}
    
    // 尝试单消息解密
    if pt, ok := trySingleMessage(payload, gcm); ok {
        return [][]byte{pt}, true
    }
    
    // 尝试多消息拆分（按 4-byte LE length 前缀）
    offset := 0
    for offset+4 <= len(payload) {
        msgLen := binary.LittleEndian.Uint32(payload[offset:offset+4])
        if offset+4+int(msgLen) > len(payload) {
            break
        }
        
        msg := payload[offset+4 : offset+4+int(msgLen)]
        if pt, err := gcmDecrypt(msg, gcm); err == nil {
            results = append(results, pt)
        }
        offset += 4 + int(msgLen)
    }
    
    return results, len(results) > 0
}
```

---

### 2. 【中优先级】密钥派生策略不完整

**问题描述**：
当前仅支持 3 种 KDF：
```go
// 1. md5(salt) → hex(32B)
// 2. md5(salt+vkey) → hex(32B)
// 3. md5(saltPad32+vkey) → hex(32B)
```

**缺失的变体**：
1. **Base64 编码的密钥**：某些 VShell 变种可能使用 Base64 而非 Hex
2. **SHA256 派生**：较新版本可能升级到 SHA256
3. **直接使用原始 MD5 输出**（16字节）而非 Hex 编码（32字节）

**当前代码问题**：
```go
// c2_decrypt.go:812-813
gcmKey: []byte(hex.EncodeToString(sum1[:])),  // 强制 Hex 编码
cbcKey: sum1[:],                               // 原始 16 字节
```
- GCM 模式使用 **Hex 编码（32字节）**
- CBC 模式使用 **原始 MD5（16字节）**

这种不一致可能导致部分变种解密失败。

**修复建议**：
```go
// 增加更多 KDF 变体
keySets = append(keySets, 
    // 原始 MD5（16字节）用于 GCM
    vshellKeySet{
        label:  "md5(salt)-raw",
        gcmKey: sum1[:],
        cbcKey: sum1[:],
    },
    // Base64 编码
    vshellKeySet{
        label:  "md5(salt)-base64",
        gcmKey: []byte(base64.StdEncoding.EncodeToString(sum1[:])),
        cbcKey: sum1[:],
    },
)
```

---

### 3. 【中优先级】缺少分片帧（Fragmented Frames）处理

**问题描述**：
当前 WebSocket 帧解析器不处理分片：
```go
// vshell_websocket_decrypt.go:55-61
frames = append(frames, wsFrame{
    masked:  isMasked,
    maskKey: maskKey,
    payload: data[payloadOffset : payloadOffset+payloadLen],
    opcode:  b0 & 0x0f,  // ← 记录了 opcode 但没使用
})
```

**缺失逻辑**：
- 没有检查 FIN 位（`b0 & 0x80`）
- 没有重组分片帧（FIN=0 的连续帧）
- 大型 VShell 消息可能被拆成多个 WebSocket 帧

**影响**：
- 大于 MTU 的 VShell 消息（如文件传输、大命令输出）会解密失败
- 分片攻击绕过检测

**修复建议**：
```go
type wsFrame struct {
    fin      bool     // FIN bit
    opcode   byte
    masked   bool
    maskKey  []byte
    payload  []byte
}

func parseWebSocketFrames(data []byte) []wsFrame {
    // ...
    fin := (b0 & 0x80) != 0
    frames = append(frames, wsFrame{
        fin:     fin,
        opcode:  b0 & 0x0f,
        // ...
    })
}

// 重组分片帧
func reassembleFragments(frames []wsFrame) [][]byte {
    var buffer []byte
    var messages [][]byte
    
    for _, frame := range frames {
        if frame.opcode >= 0x8 {
            continue // 跳过控制帧
        }
        
        buffer = append(buffer, frame.payload...)
        
        if frame.fin {
            messages = append(messages, buffer)
            buffer = nil
        }
    }
    
    return messages
}
```

---

### 4. 【低优先级】心跳检测阈值可能过于宽松

**问题描述**：
当前心跳检测阈值：
```go
// tool_c2.go:687
if avg >= 8 && avg <= 14 {
    // 识别为 VShell 心跳
}
```

**潜在问题**：
- 阈值 [8, 14] 秒覆盖范围较大
- 可能误报其他定期轮询的正常应用（如邮件客户端、聊天软件）

**改进建议**：
```go
// 增加置信度分级
var confidence int
switch {
case avg >= 9.5 && avg <= 10.5:
    confidence = 90  // 核心心跳区间
case avg >= 8.5 && avg <= 11.5:
    confidence = 75  // 容忍 TCP 重传影响
case avg >= 8 && avg <= 14:
    confidence = 60  // 宽松匹配
}
```

---

### 5. 【低优先级】缺少对压缩扩展的支持

**问题描述**：
WebSocket 可能启用 `permessage-deflate` 压缩扩展，当前代码未处理。

**影响**：
- 如果 VShell 启用了 WebSocket 压缩，解密会失败
- 需要在解密前先解压 payload

**检测方法**：
检查 WebSocket 握手中的 `Sec-WebSocket-Extensions` 头：
```
Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits
```

**修复建议**：
```go
// 检查 RSV1 位（压缩标志）
rsv1 := (b0 & 0x40) != 0
if rsv1 {
    // 需要 DEFLATE 解压
    payload = decompressPayload(payload)
}
```

---

### 6. 【信息】CBC 模式支持但未充分测试

**观察**：
代码同时支持 AES-GCM 和 AES-CBC：
```go
// c2_decrypt.go:1091-1105
if mode == "auto" || mode == "aes_gcm_md5_salt" {
    // 尝试 AES-GCM
}
if mode == "auto" || mode == "aes_cbc_md5_salt" {
    // 尝试 AES-CBC
}
```

但所有测试样本都是 AES-GCM 模式，CBC 模式缺少实战验证。

**建议**：
- 添加 AES-CBC 模式的端到端测试
- 或在文档中明确标注 CBC 模式为实验性支持

---

## ✅ 实现优点

### 1. 协议识别准确
- WebSocket 正确识别为独立协议（不是 HTTP 别名）
- Stream ID 统一分组避免流拆分

### 2. 异常值过滤算法有效
```go
// 过滤 >2x 中位数的异常间隔（TCP 重传）
longIntervals = filterOutlierIntervals(longIntervals)
```
- 成功处理 TCP 重传导致的心跳间隔异常
- 从 avg=12.25s 优化到 avg=10.8s

### 3. Triple-KDF 覆盖常见变种
- 三种密钥派生方式覆盖主流 VShell 变种
- 支持 vkey 验证提升可信度

### 4. 测试覆盖完整
- 7 个单元测试 + 2 个端到端测试
- 真实样本验证（challenge.pcap）

---

## 📊 优先级总结

| 问题 | 优先级 | 影响范围 | 修复复杂度 |
|------|--------|---------|-----------|
| 客户端掩码帧解密失败 | **高** | 漏掉 50% 通信内容 | 中等 |
| 多消息拆分缺失 | **高** | 大流量场景失败 | 中等 |
| 密钥派生不完整 | 中 | 部分变种失败 | 低 |
| 分片帧未处理 | 中 | 大消息/分片攻击 | 高 |
| 心跳阈值过宽 | 低 | 误报率略高 | 低 |
| 压缩扩展缺失 | 低 | 特定配置失败 | 中等 |
| CBC 模式未测试 | 信息 | 潜在隐患 | 低 |

---

## 🎯 修复路线图

### Phase 1 - 关键修复（1-2天）
1. 修复客户端掩码帧解密逻辑
2. 添加多 VShell 消息拆分支持
3. 补充实战测试用例

### Phase 2 - 增强鲁棒性（3-5天）
4. 扩展密钥派生变体（Base64、原始 MD5）
5. 实现 WebSocket 分片帧重组
6. 优化心跳检测置信度分级

### Phase 3 - 完善生态（可选）
7. 添加压缩扩展支持
8. 补充 AES-CBC 模式测试
9. 文档更新和用户指南

---

## 📝 结论

当前 VShell 检测和解密实现**在检测阶段表现优秀**，但**在解密阶段存在关键缺陷**：

✅ **检测能力**：
- WebSocket 协议识别：优秀
- 心跳模式检测：良好
- 流分组逻辑：优秀

⚠️ **解密能力**：
- 服务器→客户端：**可用**
- 客户端→服务器：**失败**（高优先级问题）
- 复杂消息格式：**不支持**（需增强）

**建议优先修复客户端掩码帧解密问题**，以实现完整的双向通信解密能力。

---

**审计人员**: Claude Opus 4.8  
**审计日期**: 2026-06-03  
**置信度**: 高（基于代码审查、测试输出和协议标准）
