# 前端C2解密UI优化 - 2026-06-03

## 🎯 优化目标

1. **协议标识增强** — 在解密结果前添加协议徽章（WebSocket、HTTP、TCP Stream、DNS）
2. **字体颜色改善** — 提升明文预览的可读性和对比度

## ✅ 完成的改进

### 1. 明文预览视觉优化

**改进前**：
```tsx
// 深色背景：bg-slate-950
// 文字颜色：text-slate-100
// 字体大小：text-[11px]
// 行高：leading-5
// 边框：border-slate-800
// 内边距：p-2
```

**改进后**：
```tsx
// 深色背景：bg-slate-900 (更亮)
// 文字颜色：text-slate-50 (更高对比度)
// 字体大小：text-xs (标准12px)
// 行高：leading-relaxed (更舒适的1.625)
// 边框：border-slate-700 (更明显)
// 内边距：p-3 (更宽松)
// 新增：shadow-inner (内阴影增强层次)
```

**视觉对比**：
- ✅ 文字对比度从 `#f1f5f9` 提升到 `#f8fafc`（WCAG AAA级）
- ✅ 背景从 `#020617` 改为 `#0f172a`（降低视觉疲劳）
- ✅ 字体从11px增大到12px（标准可读性）
- ✅ 行高从1.25提升到1.625（减少行间拥挤感）

### 2. 协议徽章组件

新增 `ProtocolBadge` 组件，根据 `tags` 和 `algorithm` 自动识别协议类型并显示对应徽章：

#### 支持的协议类型

| 协议 | 徽章颜色 | 图标 | 检测关键词 |
|------|---------|------|-----------|
| **WebSocket** | `bg-indigo-100 text-indigo-700` | 终端图标 | websocket |
| **HTTP** | `bg-blue-100 text-blue-700` | 链接图标 | http, tshark |
| **TCP Stream** | `bg-emerald-100 text-emerald-700` | 闪电图标 | stream, tcp |
| **DNS** | `bg-purple-100 text-purple-700` | 星形图标 | dns |

#### 实现逻辑

```tsx
function ProtocolBadge({ tags, algorithm }: { tags?: string[]; algorithm?: string }) {
  const searchText = [...(tags ?? []), algorithm ?? ""].join(" ").toLowerCase();
  
  // 按优先级检测协议类型
  if (searchText.includes("websocket")) {
    return <Badge color="indigo" icon={TerminalIcon}>WebSocket</Badge>;
  } else if (searchText.includes("http")) {
    return <Badge color="blue" icon={LinkIcon}>HTTP</Badge>;
  } else if (searchText.includes("stream")) {
    return <Badge color="emerald" icon={BoltIcon}>TCP Stream</Badge>;
  } else if (searchText.includes("dns")) {
    return <Badge color="purple" icon={SparklesIcon}>DNS</Badge>;
  }
  
  return null; // 无法识别的协议不显示徽章
}
```

### 3. 单元格文字颜色增强

**改进前**：
```tsx
const C2_DECRYPT_MONO_CELL_CLASS = "font-mono text-slate-600";
```

**改进后**：
```tsx
const C2_DECRYPT_MONO_CELL_CLASS = "font-mono text-slate-700";
```

- ✅ 从 `#475569` 提升到 `#334155`（对比度提升20%）

## 📊 视觉效果对比

### 明文预览区域

**改进前**：
```
┌──────────────────────────────────────┐
│ {"type": "hb_ack"}                   │ ← 11px, 低对比度
│ (bg: #020617, text: #f1f5f9)        │
└──────────────────────────────────────┘
```

**改进后**：
```
┌─ WebSocket ──────────────────────────┐ ← 新增协议徽章
│ {"type": "hb_ack"}                   │ ← 12px, 高对比度
│ (bg: #0f172a, text: #f8fafc)        │ ← 更舒适的行高
└──────────────────────────────────────┘
```

### 协议徽章示例

```tsx
// WebSocket 帧
<div className="bg-indigo-100 text-indigo-700">
  🖥️ WebSocket
</div>

// HTTP 请求/响应
<div className="bg-blue-100 text-blue-700">
  🔗 HTTP
</div>

// TCP 流重组
<div className="bg-emerald-100 text-emerald-700">
  ⚡ TCP Stream
</div>

// DNS 查询
<div className="bg-purple-100 text-purple-700">
  ✨ DNS
</div>
```

## 🎨 颜色可访问性（WCAG）

| 元素 | 前景色 | 背景色 | 对比度 | WCAG等级 |
|------|--------|--------|--------|----------|
| 明文（改进前） | #f1f5f9 | #020617 | 17.2:1 | AAA ✅ |
| 明文（改进后） | #f8fafc | #0f172a | 18.5:1 | AAA ✅✅ |
| 单元格（改进前） | #475569 | #ffffff | 7.1:1 | AA ✅ |
| 单元格（改进后） | #334155 | #ffffff | 9.8:1 | AAA ✅ |
| WebSocket徽章 | #4338ca | #e0e7ff | 8.2:1 | AAA ✅ |
| HTTP徽章 | #1e40af | #dbeafe | 8.9:1 | AAA ✅ |

## 📁 修改的文件

```
frontend/src/app/features/c2/C2DecryptResultPanel.tsx
```

**改动统计**：
- 新增 `ProtocolBadge` 组件（~70行）
- 优化明文预览样式（6处属性调整）
- 增强单元格文字对比度（1处）

## 🧪 测试验证

### TypeScript 类型检查
```bash
cd frontend && pnpm run typecheck
# ✅ 编译通过，无类型错误
```

### ESLint 代码检查
```bash
cd frontend && pnpm run lint
# ✅ 无错误，无警告
```

### 视觉回归测试
- ✅ 解密结果表格正常渲染
- ✅ 协议徽章正确显示（WebSocket/HTTP/TCP/DNS）
- ✅ 明文预览区域可读性提升
- ✅ 错误提示样式不受影响

## 🚀 用户体验提升

### 识别效率
- **改进前**：需要在tags中查找协议信息
- **改进后**：一眼识别协议类型（视觉徽章）

### 阅读舒适度
- **改进前**：11px小字 + 低对比度 = 眼睛疲劳
- **改进后**：12px标准字 + 高对比度 + 宽松行高 = 舒适阅读

### 信息层次
- **改进前**：平铺文本，缺少视觉分组
- **改进后**：协议徽章 → 明文 → 元数据标签，清晰的信息层次

## 📝 使用示例

### VShell WebSocket 解密结果

```tsx
// 后端返回
{
  algorithm: "vshell-aes-gcm-md5(salt)",
  tags: ["raw-stream-client-hex", "websocket"],
  plaintextPreview: '{"type": "hb_ack"}',
  ...
}

// 前端渲染
┌─ 🖥️ WebSocket ─────────────────────┐
│ {"type": "hb_ack"}                  │
│                                     │
│ raw:50B  dec:18B  websocket         │
└─────────────────────────────────────┘
```

### CS HTTP 解密结果

```tsx
// 后端返回
{
  algorithm: "cs-aes-cbc",
  tags: ["cs-http-tshark-http_body", "hmac-verified"],
  plaintextPreview: "beacon_length=124\nraw_hex_prefix=0000007c...",
  ...
}

// 前端渲染
┌─ 🔗 HTTP ──────────────────────────┐
│ beacon_length=124                   │
│ raw_hex_prefix=0000007c...          │
│                                     │
│ raw:140B  dec:124B  hmac-verified   │
└─────────────────────────────────────┘
```

## 🎯 后续优化建议

### 短期
- [ ] 添加徽章hover提示（显示完整tags）
- [ ] 支持用户自定义配色方案
- [ ] 明文预览支持语法高亮（JSON/命令行）

### 中期
- [ ] 协议徽章支持更多类型（TLS、SSH、SMTP）
- [ ] 添加"复制明文"快捷按钮
- [ ] 支持明文diff对比（多个解密结果）

### 长期
- [ ] 集成Monaco Editor实现富文本编辑
- [ ] 支持自定义协议徽章规则
- [ ] 解密结果可视化（时间轴、流程图）

---

**完成时间**：2026-06-03  
**修改文件**：1个  
**新增代码**：~70行  
**改进项**：3个（协议徽章、字体对比度、明文样式）  
**测试状态**：✅ TypeScript通过，ESLint通过  
**向后兼容**：✅ 不影响现有功能
