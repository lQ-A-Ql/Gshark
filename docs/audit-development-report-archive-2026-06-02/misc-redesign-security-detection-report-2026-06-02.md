# MISC 页面重构与安全检测工具开发报告 2026-06-02

## 概述

本次开发包含三个主要方向：MISC 页面布局重构、新增实用小工具、以及全栈安全检测功能（UDP 隧道识别 + 端口/目录爆破识别）。

---

## 一、MISC 页面布局重构

### 变更前

垂直手风琴列表布局：大 Hero 区 → 模块卡片逐个折叠展开，查找工具依赖滚动。

### 变更后

左右分栏布局：

```
┌─────────────────────────────────────────────────┐
│ SlimHeader: 模块计数 + 导入按钮（一行）          │
├────────────┬────────────────────────────────────┤
│ 侧边栏     │                                    │
│ (分组导航)  │  选中模块的工作台（全宽）           │
│            │                                    │
│ ─凭据─     │                                    │
│ ─Payload─  │                                    │
│ ─协议─     │                                    │
│ ─工具─     │                                    │
│ ─自定义─   │                                    │
└────────────┴────────────────────────────────────┘
```

### 新分类体系

| 旧分类 | 新分类 | 包含模块 |
|--------|--------|---------|
| Misc/WinRM/SMB3 | credential（凭据） | WinRM、NTLM、SMB3、Shiro |
| Payload | payload（Payload） | WebShell 解码、Base64 编解码 |
| — | protocol（协议） | HTTP Login、MySQL、SMTP |
| — | utility（工具） | 时间戳转换、哈希计算 |
| Modules | custom（自定义） | 用户导入的 zip 模块 |

### 新增组件

| 文件 | 职责 | 行数 |
|------|------|------|
| `MiscToolsSlimHeader.tsx` | 精简顶栏 | 35 |
| `MiscModuleSidebar.tsx` | 左侧分组导航 | 67 |
| `MiscModuleWorkbench.tsx` | 右侧工作台 | 54 |

---

## 二、新增实用小工具（纯前端）

| 工具 | 文件 | 功能 |
|------|------|------|
| Base64 编解码器 | `Base64CodecModule.tsx` | 双向 Base64/Hex/URL 编解码，实时转换 |
| 时间戳转换器 | `TimestampConverterModule.tsx` | Unix ↔ 人类可读，多格式输出 |
| 哈希计算器 | `HashCalculatorModule.tsx` | CRC32 + SHA-1 + SHA-256（Web Crypto API） |

这三个工具不依赖后端，通过 `frontendModules.ts` 注入到 MISC 模块列表。

---

## 三、安全检测功能（全栈）

### UDP 隧道识别

**检测算法：**

1. DNS 隧道检测：
   - 按 base domain 分组 DNS 查询
   - 计算子域名 Shannon 熵（> 3.5 = 可疑）
   - 检查平均子域名长度（> 20 = 可疑）
   - 检查 payload 大小（> 200 bytes = 可疑）
   - 综合置信度：高熵 80+，中熵 60+，高频 40+

2. 通用 UDP 隧道检测：
   - 按 (src, dst, port) 分组 UDP 包
   - 计算 payload 大小标准差
   - 标记条件：包数 > 100 AND stddev/mean < 0.2 AND avgPayload > 50

### 端口/目录爆破识别

**检测算法：**

1. 端口扫描检测（修订版 — 修复样本 269-lockdown 漏检/误报问题）：
   - 仅追踪 SYN-only 包（排除 SYN-ACK）的目标端口分布
   - RST 回包归因到扫描发起方（反向查找 `(dst, src)` 组）
   - 数据包（非 SYN/RST）独立计数作为反误报信号
   - 标记条件：唯一 SYN 目标端口 > 20 AND dataPackets ≤ synCount × 3
   - 扫描类型：dataPackets < synCount/4 → syn-scan，否则 connect-scan
   - 置信度：500+ 端口 = 95，100+ = 90，50+ = 70，20+ = 50；高 RST 比额外 +10

   修复前的问题：
   - RST 被记入反向组导致正向组不满足 SYN 占比阈值（漏检真实扫描）
   - C2 回连因反向组累积 RST + 混入端口而被误报为扫描

2. 目录爆破检测：
   - 按 (sourceIP, targetHost) 分组 HTTP 请求
   - 统计 404/403/200 响应比例
   - 标记条件：请求数 > 30 AND 失败率 > 70% AND 频率 > 3 req/s

### API 与 MCP

| 路由 | MCP 工具名 | 说明 |
|------|-----------|------|
| `GET /api/tools/udp-tunnel` | `tooling.udp_tunnel` | UDP 隧道检测 |
| `GET /api/tools/bruteforce` | `tooling.bruteforce` | 爆破检测 |

### 桌面 IPC 集成

- `desktop_backend_proxy.go` 新增 `GetUDPTunnelAnalysis()` / `GetBruteforceAnalysis()`
- 前端 typed bridge 完整覆盖（binding 声明 + requirement 映射 + typed override）
- 修复了桌面构建时 generic IPC adapter 策略禁用报错
- 与自定义 zip 模块的 MISC IPC 通道（`ListMiscModules` / `RunMiscModulePackage`）完全独立，互不影响

---

## 四、其他改进

- 创建 `Textarea` 公共 UI 组件（`components/ui/textarea.tsx`）
- 新工具模块全部使用公共 `Input` / `Textarea` 组件
- `TrafficGraphPanels` 拆分为 `TrafficGraphPanels` + `TrafficGraphOverview`，解决 size 超标
- 注册 `dbcMapper.ts` 到 size budget
- 新增 `securityDetectionMapper.ts` 用于安全检测模块的 wire→domain 映射
- `MiscModuleSurface` 新增 `rose` 色调支持

---

## 修改文件清单

### 后端（Go）

| 文件 | 变更 |
|------|------|
| `backend/internal/engine/tool_udp_tunnel.go` | 新增：UDP 隧道检测算法 |
| `backend/internal/engine/tool_bruteforce.go` | 新增：爆破检测算法 |
| `backend/internal/model/types_protocols.go` | 新增 6 个结构体 |
| `backend/internal/transport/services.go` | ToolAnalysisService +2 方法 |
| `backend/internal/transport/http_server.go` | 注册 2 个路由 |
| `backend/internal/transport/http_tools.go` | 新增 2 个 handler |
| `backend/internal/mcp/server.go` | MCP +2 工具 |
| `desktop_backend_proxy.go` | Wails typed binding +2 |
| `desktop_typed_bindings_test.go` | 测试更新 |

### 前端（TypeScript/React）

| 文件 | 变更 |
|------|------|
| `misc/MiscToolsSlimHeader.tsx` | 新增：精简顶栏 |
| `misc/MiscModuleSidebar.tsx` | 新增：分组侧边栏 |
| `misc/MiscModuleWorkbench.tsx` | 新增：工作台面板 |
| `misc/MiscToolsShell.tsx` | 重构为左右分栏 |
| `misc/miscModuleRules.ts` | 新分类体系 |
| `misc/useMiscToolsCatalog.ts` | 新增 selectedModuleId |
| `misc/frontendModules.ts` | +5 模块 manifest |
| `misc/registry.tsx` | +5 lazy 注册 |
| `misc/modules/Base64CodecModule.tsx` | 新增 |
| `misc/modules/TimestampConverterModule.tsx` | 新增 |
| `misc/modules/HashCalculatorModule.tsx` | 新增 |
| `misc/modules/UDPTunnelModule.tsx` | 新增 |
| `misc/modules/BruteforceModule.tsx` | 新增 |
| `misc/modules/MiscModuleSurface.tsx` | +rose tone |
| `integrations/mappers/securityDetectionMapper.ts` | 新增 |
| `integrations/clients/toolClient.ts` | +2 方法 |
| `integrations/bridgeTypes.ts` | +2 接口方法 |
| `integrations/desktopTransportBindingTooling.ts` | +2 binding |
| `integrations/desktopTypedBridgeRequirements.ts` | +2 映射 |
| `integrations/desktopTypedBridgeTooling.ts` | +2 typed override |
| `components/ui/textarea.tsx` | 新增：Textarea 公共组件 |
| `core/types/tools.ts` | +6 类型定义 |
| `scripts/check-size.mjs` | budget 更新 |

---

## 测试验证

- 后端全量测试通过（architecture + engine + governance + transport + tshark + yara）
- 前端 237 文件 / 766 测试全部通过
- 桌面 typed bindings 测试通过
- Wails binding check 通过
- TypeScript / ESLint / boundary / size 全部绿色
