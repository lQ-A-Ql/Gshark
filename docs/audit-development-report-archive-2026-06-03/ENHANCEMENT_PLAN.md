# VShell WebSocket C2 解密能力增强计划

> **⚠️ 假设修正（2026-06-03）**
>
> 本计划 Phase 1 Task 1.1 假设客户端解密失败的根因是「缺少多消息拆分支持」。
> 后续排查**推翻了该假设**。真因是：生产路径 `collectVShellStreamDecryptCandidates`
> **从未调用解掩码逻辑**，客户端帧带 XOR 掩码的原始字节直接喂给 GCM 管线，永远无法解密。
>
> 修复详见：[VShell 客户端方向解密接线报告](vshell-client-direction-decrypt-wiring-2026-06-03.md)
>
> Phase 2（密钥派生增强）和 Phase 3（分片帧重组）仍为有效待办。

---

## 📋 执行摘要

基于审计发现的 4 个待修复问题，制定分 3 个阶段的修复计划。预计总工作量：**5-7 天**，核心修复可在 **2-3 天**内完成。

---

## 🎯 待修复问题清单

| # | 问题 | 优先级 | 当前影响 | 修复收益 |
|---|------|--------|---------|---------|
| 1 | 客户端→服务器消息解密失败 | **P0 高** | 漏掉 50% 通信 | 实现双向解密 |
| 2 | 多消息拆分支持缺失 | **P0 高** | 大流量场景失败 | 支持批量通信 |
| 3 | 密钥派生策略不完整 | **P1 中** | 部分变种失败 | 覆盖更多变种 |
| 4 | WebSocket 分片帧未处理 | **P1 中** | 大消息失败 | 完整协议支持 |

---

## 📅 三阶段修复计划

### Phase 1: 核心解密能力修复（P0 高优先级）
**目标**：实现完整的双向通信解密  
**工期**：2-3 天  
**优先级**：立即执行

#### Task 1.1: 多消息拆分支持 ⭐
**问题**：当前假设每个 WebSocket 帧只包含一个 VShell 消息  
**现实**：客户端帧（159字节）可能包含多个 VShell 消息  

**实施细节**：
```go
// 文件：backend/internal/engine/vshell_websocket_decrypt.go

// 修改函数签名，返回多个明文
func decryptVShellWebSocketFrame(payload []byte, gcm cipher.AEAD) ([][]byte, bool) {
    var plaintexts [][]byte
    
    // 策略 1: 尝试单消息解密
    if pt, ok := trySingleVShellMessage(payload, gcm); ok {
        return [][]byte{pt}, true
    }
    
    // 策略 2: 尝试多消息拆分（按 4-byte LE length 前缀）
    offset := 0
    for offset+4 <= len(payload) {
        msgLen := binary.LittleEndian.Uint32(payload[offset : offset+4])
        
        // 验证长度合理性（避免误识别）
        if msgLen == 0 || msgLen > 10*1024*1024 {
            break // 长度不合理，退出循环
        }
        
        if offset+4+int(msgLen) > len(payload) {
            break // 超出边界
        }
        
        // 提取消息体
        msgData := payload[offset+4 : offset+4+int(msgLen)]
        
        // 尝试解密
        if len(msgData) >= 12+gcm.Overhead() {
            nonce := msgData[:gcm.NonceSize()]
            ct := msgData[gcm.NonceSize():]
            if pt, err := gcm.Open(nil, nonce, ct, nil); err == nil {
                plaintexts = append(plaintexts, pt)
            } else {
                break // 解密失败，可能不是多消息格式
            }
        }
        
        offset += 4 + int(msgLen)
    }
    
    // 策略 3: 尝试跳过 1-4 字节头部（协议变种）
    if len(plaintexts) == 0 {
        for skip := 1; skip <= 4 && skip < len(payload); skip++ {
            if pt, ok := trySingleVShellMessage(payload[skip:], gcm); ok {
                plaintexts = append(plaintexts, pt)
                break
            }
        }
    }
    
    return plaintexts, len(plaintexts) > 0
}

func trySingleVShellMessage(payload []byte, gcm cipher.AEAD) ([]byte, bool) {
    // 带长度前缀
    if len(payload) >= 4 {
        msgLen := binary.LittleEndian.Uint32(payload[:4])
        if int(msgLen) == len(payload)-4 && int(msgLen) >= 12+gcm.Overhead() {
            msg := payload[4 : 4+msgLen]
            nonce := msg[:gcm.NonceSize()]
            ct := msg[gcm.NonceSize():]
            if pt, err := gcm.Open(nil, nonce, ct, nil); err == nil {
                return pt, true
            }
        }
    }
    
    // 无长度前缀（直接 nonce + ciphertext）
    if len(payload) >= gcm.NonceSize()+gcm.Overhead() {
        nonce := payload[:gcm.NonceSize()]
        ct := payload[gcm.NonceSize():]
        if pt, err := gcm.Open(nil, nonce, ct, nil); err == nil {
            return pt, true
        }
    }
    
    return nil, false
}
```

**影响范围**：
- `vshell_websocket_decrypt.go` - 核心解密逻辑
- `c2_decrypt.go` - 调用方需要适配多明文返回

**测试用例**：
```go
// 文件：backend/internal/engine/vshell_websocket_decrypt_test.go

func TestDecryptMultipleVShellMessages(t *testing.T) {
    salt := "test_salt"
    key := deriveVShellKeyHex(salt)
    
    // 构造包含 2 个 VShell 消息的 payload
    msg1 := encryptVShellMessage([]byte("message 1"), key)
    msg2 := encryptVShellMessage([]byte("message 2"), key)
    
    combined := append(msg1, msg2...)
    
    plaintexts, ok := decryptVShellWebSocketFrame(combined, createGCM(key))
    require.True(t, ok)
    assert.Len(t, plaintexts, 2)
    assert.Equal(t, "message 1", string(plaintexts[0]))
    assert.Equal(t, "message 2", string(plaintexts[1]))
}
```

**验收标准**：
- [ ] 单消息帧仍然正常工作
- [ ] 多消息帧能够成功拆分并解密
- [ ] 测试输出显示客户端帧解密成功
- [ ] 端到端测试通过

---

#### Task 1.2: 适配上层调用逻辑
**问题**：`c2_decrypt.go` 中的调用方假设每帧只有一个明文  

**实施细节**：
```go
// 文件：backend/internal/engine/c2_decrypt.go

func (s *Service) collectVShellStreamDecryptCandidates(...) error {
    // ...
    for _, assembled := range assembleVShellStreamDirections(stream) {
        for _, transformed := range decodeC2TransformCandidates(assembled.body, "auto") {
            // ... 现有逻辑 ...
            
            // 修改：处理多个明文
            plaintexts := extractVShellWebSocketPayloads(transformed.raw, key)
            for _, msg := range plaintexts {
                candidate := c2DecryptCandidate{
                    packet:    packet,
                    raw:       msg.payload,
                    label:     fmt.Sprintf("tcp-stream:%d:%s-msg-%d", streamID, direction, idx),
                    transform: "raw-stream-" + direction + "-" + transformed.transform,
                    direction: streamChunkRecordDirection(direction),
                }
                appendC2DecryptCandidateUnbounded(out, seen, candidate)
            }
        }
    }
    return nil
}
```

**验收标准**：
- [ ] 解密结果正确展示多个消息
- [ ] 前端页面正常显示所有解密记录
- [ ] 无重复或遗漏

---

#### Task 1.3: 端到端测试验证
**目标**：验证客户端帧解密成功

**测试数据**：
- 使用 `challenge.pcap` 真实样本
- 从客户端帧 3252 提取准确的掩码密钥和 payload

**实施步骤**：
1. 手工提取客户端帧原始数据
2. 验证掩码密钥正确性
3. 逐步调试解密流程
4. 输出解密后的明文内容

**验收标准**：
- [ ] 测试输出显示客户端帧解密成功
- [ ] 明文内容合理（JSON 或可打印字符串）
- [ ] 与服务器帧形成完整对话

---

### Phase 2: 密钥派生增强（P1 中优先级）
**目标**：支持更多 VShell 变种  
**工期**：1-2 天  
**优先级**：Phase 1 完成后执行

#### Task 2.1: 扩展密钥编码格式 ⭐
**问题**：当前仅支持 Hex 编码（GCM）和原始 MD5（CBC）  

**实施细节**：
```go
// 文件：backend/internal/engine/c2_decrypt.go

func buildVShellKeySets(salt, vkey string) []vshellKeySet {
    keySets := []vshellKeySet{}
    
    // KDF 函数列表
    kdfs := []struct {
        label string
        fn    func(string, string) []byte
    }{
        {"md5(salt)", func(s, v string) []byte { 
            sum := md5.Sum([]byte(s))
            return sum[:]
        }},
        {"md5(salt+vkey)", func(s, v string) []byte {
            sum := md5.Sum([]byte(s + v))
            return sum[:]
        }},
        {"md5(saltPad32+vkey)", func(s, v string) []byte {
            pad := make([]byte, 32)
            copy(pad, []byte(s))
            sum := md5.Sum(append(pad, []byte(v)...))
            return sum[:]
        }},
    }
    
    // 为每个 KDF 生成多种编码格式
    for _, kdf := range kdfs {
        raw := kdf.fn(salt, vkey)
        
        // 1. 原始 MD5（16字节）
        keySets = append(keySets, vshellKeySet{
            label:  kdf.label + "-raw",
            gcmKey: raw,
            cbcKey: raw,
        })
        
        // 2. Hex 编码（32字节）
        hexKey := []byte(hex.EncodeToString(raw))
        keySets = append(keySets, vshellKeySet{
            label:  kdf.label + "-hex",
            gcmKey: hexKey,
            cbcKey: raw,
        })
        
        // 3. Base64 标准编码
        b64Key := []byte(base64.StdEncoding.EncodeToString(raw))
        keySets = append(keySets, vshellKeySet{
            label:  kdf.label + "-base64",
            gcmKey: b64Key,
            cbcKey: raw,
        })
    }
    
    return keySets
}
```

**影响**：
- 从 3 种 KDF → **9 种组合**（3 KDF × 3 编码）
- 覆盖更多 VShell 变种

**测试用例**：
```go
func TestVShellMultipleKeyFormats(t *testing.T) {
    salt := "test_salt"
    vkey := "test_vkey"
    
    keySets := buildVShellKeySets(salt, vkey)
    assert.Len(t, keySets, 9) // 3 KDF × 3 编码
    
    // 验证每种编码格式
    for _, ks := range keySets {
        t.Logf("Testing key set: %s", ks.label)
        // 使用该密钥加密后再解密
        // ...
    }
}
```

**验收标准**：
- [ ] 支持 9 种密钥派生组合
- [ ] 现有测试不受影响
- [ ] 新增测试覆盖所有编码格式

---

#### Task 2.2: 性能优化
**问题**：9 种密钥组合会增加解密时间

**实施细节**：
- 缓存密钥派生结果
- 失败快速返回（不遍历所有组合）
- 记录成功的密钥类型，优先尝试

```go
// 记录成功的密钥类型，下次优先尝试
var successfulKeyLabels = []string{}

func tryDecryptWithHeuristic(frame []byte, keySets []vshellKeySet) ([]byte, bool) {
    // 先尝试历史成功的密钥类型
    for _, label := range successfulKeyLabels {
        for _, ks := range keySets {
            if ks.label == label {
                if pt, ok := tryDecrypt(frame, ks); ok {
                    return pt, true
                }
            }
        }
    }
    
    // 再遍历所有密钥
    for _, ks := range keySets {
        if pt, ok := tryDecrypt(frame, ks); ok {
            // 记录成功类型
            if !contains(successfulKeyLabels, ks.label) {
                successfulKeyLabels = append(successfulKeyLabels, ks.label)
            }
            return pt, true
        }
    }
    
    return nil, false
}
```

**验收标准**：
- [ ] 解密时间增幅 < 50%
- [ ] 成功案例的二次解密时间显著降低

---

### Phase 3: WebSocket 协议完整性（P1 中优先级）
**目标**：支持分片帧和高级特性  
**工期**：2-3 天  
**优先级**：Phase 2 完成后执行

#### Task 3.1: 分片帧重组 ⭐
**问题**：当前不处理 FIN=0 的分片帧

**实施细节**：
```go
// 文件：backend/internal/engine/vshell_websocket_decrypt.go

type wsFrame struct {
    fin      bool   // 新增：FIN bit
    rsv      byte   // 新增：RSV bits (用于压缩等扩展)
    opcode   byte
    masked   bool
    maskKey  []byte
    payload  []byte
}

func parseWebSocketFrames(data []byte) []wsFrame {
    var frames []wsFrame
    offset := 0
    
    for offset < len(data) {
        // ...现有解析逻辑...
        
        b0 := data[offset]
        fin := (b0 & 0x80) != 0      // FIN bit
        rsv := (b0 & 0x70) >> 4      // RSV1-3 bits
        opcode := b0 & 0x0f
        
        // ...
        
        frames = append(frames, wsFrame{
            fin:     fin,
            rsv:     rsv,
            opcode:  opcode,
            masked:  isMasked,
            maskKey: maskKey,
            payload: payload,
        })
        
        offset = payloadOffset + payloadLen
    }
    
    return frames
}

// 重组分片帧
func reassembleFragmentedFrames(frames []wsFrame) [][]byte {
    var messages [][]byte
    var buffer []byte
    var currentOpcode byte
    
    for _, frame := range frames {
        // 控制帧不参与分片
        if frame.opcode >= 0x8 {
            continue
        }
        
        // 数据帧或延续帧
        if frame.opcode != 0x0 { // 非延续帧，开始新消息
            currentOpcode = frame.opcode
            buffer = append(buffer[:0], frame.payload...)
        } else { // 延续帧，追加到 buffer
            buffer = append(buffer, frame.payload...)
        }
        
        // FIN=1 表示消息结束
        if frame.fin {
            messages = append(messages, append([]byte(nil), buffer...))
            buffer = buffer[:0]
        }
    }
    
    return messages
}

// 修改主函数
func extractVShellWebSocketPayloads(streamData []byte, key []byte) []vshellWebSocketMessage {
    frames := parseWebSocketFrames(streamData)
    
    // 先重组分片
    messages := reassembleFragmentedFrames(frames)
    
    // 再解密
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    
    var results []vshellWebSocketMessage
    for _, msg := range messages {
        plaintexts, ok := decryptVShellWebSocketFrame(msg, gcm)
        if ok {
            for _, pt := range plaintexts {
                results = append(results, vshellWebSocketMessage{
                    payload:   msg,
                    plaintext: pt,
                })
            }
        }
    }
    
    return results
}
```

**测试用例**：
```go
func TestWebSocketFragmentedFrames(t *testing.T) {
    // 构造分片帧：一个消息被拆成 3 个帧
    frame1 := buildFrame(0x01, false, []byte("part1")) // TEXT, FIN=0
    frame2 := buildFrame(0x00, false, []byte("part2")) // CONTINUATION, FIN=0
    frame3 := buildFrame(0x00, true, []byte("part3"))  // CONTINUATION, FIN=1
    
    combined := append(append(frame1, frame2...), frame3...)
    
    frames := parseWebSocketFrames(combined)
    assert.Len(t, frames, 3)
    
    messages := reassembleFragmentedFrames(frames)
    assert.Len(t, messages, 1)
    assert.Equal(t, "part1part2part3", string(messages[0]))
}
```

**验收标准**：
- [ ] 支持分片帧重组
- [ ] 大消息（>1KB）能正常解密
- [ ] 现有测试不受影响

---

#### Task 3.2: 压缩扩展支持（可选）
**问题**：如果 VShell 启用了 `permessage-deflate`，当前无法解密

**实施细节**：
```go
import "compress/flate"

func decompressWebSocketPayload(payload []byte, rsv byte) ([]byte, error) {
    // 检查 RSV1 位（压缩标志）
    if (rsv & 0x04) == 0 {
        return payload, nil // 未压缩
    }
    
    // DEFLATE 解压
    reader := flate.NewReader(bytes.NewReader(payload))
    defer reader.Close()
    
    decompressed, err := io.ReadAll(reader)
    if err != nil {
        return nil, err
    }
    
    return decompressed, nil
}
```

**优先级**：**低**（仅在发现实战样本使用压缩时实施）

---

## 📊 任务优先级矩阵

| Task | 优先级 | 影响 | 复杂度 | 工期 |
|------|--------|------|--------|------|
| 1.1 多消息拆分 | P0 | 🔴 高 | 中 | 1天 |
| 1.2 上层适配 | P0 | 🔴 高 | 低 | 0.5天 |
| 1.3 端到端验证 | P0 | 🔴 高 | 中 | 0.5天 |
| 2.1 密钥扩展 | P1 | 🟡 中 | 低 | 1天 |
| 2.2 性能优化 | P1 | 🟡 中 | 中 | 0.5天 |
| 3.1 分片帧 | P1 | 🟡 中 | 高 | 2天 |
| 3.2 压缩扩展 | P2 | 🟢 低 | 中 | 可选 |

---

## 🎯 里程碑与交付

### Milestone 1: 双向解密能力（Phase 1）
**交付日期**：D+3  
**交付物**：
- [ ] 多消息拆分功能实现
- [ ] 客户端帧解密成功
- [ ] 7 个单元测试通过
- [ ] 端到端测试通过
- [ ] 技术报告：Phase 1 实施总结

**成功指标**：
- 客户端→服务器解密成功率 ≥ 90%
- 现有测试 100% 通过
- 无性能回归

---

### Milestone 2: 变种覆盖增强（Phase 2）
**交付日期**：D+5  
**交付物**：
- [ ] 9 种密钥派生组合
- [ ] 性能优化实现
- [ ] 3 个新增测试
- [ ] 技术报告：Phase 2 实施总结

**成功指标**：
- 支持 3 种编码格式
- 解密时间增幅 < 50%
- 变种覆盖率提升 200%

---

### Milestone 3: 协议完整性（Phase 3）
**交付日期**：D+7  
**交付物**：
- [ ] 分片帧重组功能
- [ ] 大消息支持（>1KB）
- [ ] 2 个新增测试
- [ ] 技术报告：Phase 3 实施总结

**成功指标**：
- 支持分片帧
- 大消息（>1KB）解密成功
- 符合 RFC 6455 标准

---

## 🧪 测试策略

### 单元测试
- Task 1.1: `TestDecryptMultipleVShellMessages`
- Task 1.1: `TestDecryptSingleVShellMessage`
- Task 1.1: `TestDecryptWithHeaderSkip`
- Task 2.1: `TestVShellMultipleKeyFormats`
- Task 2.1: `TestVShellRawMD5Key`
- Task 2.1: `TestVShellBase64Key`
- Task 3.1: `TestWebSocketFragmentedFrames`
- Task 3.1: `TestFragmentedFrameReassembly`

### 集成测试
- Phase 1: 使用 `challenge.pcap` 验证客户端帧解密
- Phase 2: 使用不同变种的 VShell 样本测试
- Phase 3: 使用大消息样本测试

### 回归测试
- 每个 Phase 完成后运行完整测试套件
- 确保现有功能不受影响

---

## 📝 文档更新计划

每个 Phase 完成后更新：
1. **技术实施报告**：详细记录实施过程和技术决策
2. **CLAUDE.md**：更新 C2 解密章节
3. **用户文档**：更新 VShell 解密使用说明
4. **API 文档**：更新解密接口说明

---

## 🚀 执行建议

### 立即执行（Phase 1）
1. 开始 Task 1.1：多消息拆分支持
2. 预期 2-3 天完成核心解密能力

### 快速迭代
- 每个 Task 完成后立即测试
- 发现问题立即调整
- 每天同步进度

### 风险控制
- 每个 Phase 独立分支开发
- 通过测试后再合并
- 保留回滚能力

---

## 📊 预期成果

### 修复前 vs 修复后

| 指标 | 修复前 | Phase 1 后 | Phase 2 后 | Phase 3 后 |
|------|--------|-----------|-----------|-----------|
| 服务器→客户端 | 100% | 100% | 100% | 100% |
| 客户端→服务器 | 0% | **90%** | 95% | 95% |
| 多消息支持 | ❌ | **✅** | ✅ | ✅ |
| 变种覆盖 | 3种 | 3种 | **9种** | 9种 |
| 分片帧支持 | ❌ | ❌ | ❌ | **✅** |
| 实战可用性 | 50% | **90%** | 95% | **98%** |

---

**制定人员**: Claude Opus 4.8  
**制定日期**: 2026-06-03  
**预计总工期**: 5-7 天  
**核心修复工期**: 2-3 天（Phase 1）
