# Phase 1 实施进度跟踪

## 📅 实施日期：2026-06-03

---

## ✅ Task 1.1: 实现多消息拆分支持（已完成）

### 实施内容

#### 1. 修改核心解密函数
**文件**：`backend/internal/engine/vshell_websocket_decrypt.go`

**关键改动**：
- 修改 `decryptVShellWebSocketFrame()` 返回类型：`[]byte` → `[][]byte`
- 实现三种解密策略：
  1. 单消息解密（原有逻辑）
  2. 多消息拆分（按4字节LE长度前缀）
  3. 跳过1-4字节头部尝试解密

#### 2. 新增辅助函数
```go
func trySingleVShellMessage(payload []byte, gcm cipher.AEAD) ([]byte, bool)
```
- 封装单消息解密逻辑
- 支持带长度前缀和无长度前缀两种格式

#### 3. 适配上层调用
**文件**：`backend/internal/engine/vshell_websocket_decrypt.go`

修改 `extractVShellWebSocketPayloads()` 函数：
```go
// 原来：单个明文
plaintext, ok := decryptVShellWebSocketFrame(payload, gcm)
if ok {
    messages = append(messages, ...)
}

// 现在：多个明文
plaintexts, ok := decryptVShellWebSocketFrame(payload, gcm)
if ok {
    for _, plaintext := range plaintexts {
        messages = append(messages, ...)
    }
}
```

### 验证结果

#### 编译测试
```bash
cd backend && go build ./internal/engine/...
✅ 编译通过，无错误
```

#### 单元测试
```bash
cd backend && go test ./internal/engine/... -run TestVShell -v
```

**预期结果**：
- ✅ 现有测试保持通过
- ⏳ 客户端帧解密状态（待验证）

---

## 🔄 Task 1.2: 适配上层调用逻辑（进行中）

### 待实施内容

#### 需要检查的调用点
1. `c2_decrypt.go` 中的 `collectVShellStreamDecryptCandidates()`
2. 确认是否有其他调用 `extractVShellWebSocketPayloads()` 的地方

#### 实施计划
- [ ] 搜索所有调用点
- [ ] 验证多明文返回是否正确处理
- [ ] 确保前端展示正常

---

## ⏳ Task 1.3: 端到端测试验证（待开始）

### 验证目标
- [ ] 服务器→客户端解密仍然正常（回归测试）
- [ ] 客户端→服务器解密成功（核心目标）
- [ ] 输出明文内容合理

### 测试数据
- 使用 `challenge.pcap` 真实样本
- 客户端帧 3252（159字节 payload）

---

## 📊 Phase 1 整体进度

| Task | 状态 | 进度 | 预计完成 |
|------|------|------|---------|
| 1.1 多消息拆分 | ✅ 完成 | 100% | 已完成 |
| 1.2 上层适配 | 🔄 进行中 | 30% | 今天 |
| 1.3 端到端验证 | ⏳ 待开始 | 0% | 今天 |

**Phase 1 总进度**：**43%** (1/3 完成 + 1/3 进行中)

---

## 🎯 下一步行动

1. **立即执行**：搜索并验证所有调用点
2. **关键验证**：运行完整的 VShell 测试套件
3. **目标确认**：客户端帧解密成功输出

---

**更新时间**：2026-06-03  
**实施人员**：lQ-A-Ql + Claude Opus 4.8
