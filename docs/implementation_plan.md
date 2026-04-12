# GShark-Sentinel 项目审计报告与发展方案

## 一、项目概述

**GShark-Sentinel** 是一款面向安全分析师 / CTF 选手 / 应急响应人员的桌面端 PCAP/PCAPNG 离线流量分析工具。

### 技术栈

| 层级 | 技术 | 说明 |
|------|------|------|
| 前端 | React 18 + TypeScript 5.9 + Vite 6 + TailwindCSS v4 | UI 层 |
| 前端组件库 | Radix UI + MUI v7 + Lucide Icons | 混合使用两套组件库 |
| 状态管理 | React Context (单一 [SentinelContext](file:///c:/Users/QAQ/Desktop/gshark/frontend/src/app/state/SentinelContext.tsx#28-58)) | 无 Redux/Zustand |
| 桌面桥接 | Wails v2 | Go-JS IPC |
| 后端引擎 | Go 1.22 | 核心解析 |
| 数据解析 | tshark (`-T ek` JSON 模式) | 协议解包 |
| 前后端通信 | REST API + SSE (Server-Sent Events) | 实时推送 |

### 已实现功能

| 功能 | 前端 | 后端 | 完成度 |
|------|:----:|:----:|:------:|
| PCAP 加载与流式解析 | ✅ | ✅ | 80% |
| 数据包虚拟滚动列表 | ✅ | — | 70% |
| 协议解析树 + 十六进制视图联动 | ✅ | — | 60% |
| 显示过滤器 (tshark 语法) | ✅ | ✅ | 50% |
| 威胁检测 (OWASP/CTF/Flag 嗅探) | ✅ | ✅ | 70% |
| 附件提取 (Object Export) | ✅ | ✅ | 100% |
| HTTP 流重组 | ✅ | ✅ | 60% |
| TCP/UDP 原始流追踪 | ✅ | ✅ | 50% |
| TLS 解密配置管理 | ✅ | ✅ | 80% |
| 插件管理 | ✅ | ✅ | 40% |
| 暗黑模式适配 | ✅ | — | 60% |
| 键盘快捷键 | ✅ | — | 70% |
| Wails 桌面打包 | ✅ | ✅ | 40% |

---

## 二、缺陷与问题分析

### 🔴 严重问题 (Critical)

#### C-1: TLS 解密功能仅有配置页面，后端未实际使用配置

[SetTLSConfig()](file:///c:/Users/QAQ/Desktop/gshark/backend/internal/engine/service.go#115-120) 只是存储了配置到内存中的 `tlsConf` 字段，但 `tshark.StreamPackets()` 调用时完全没有传入 `-o ssl.keylog_file` 或 `-o rsa_keys` 参数。TLS 解密实际上**不生效**。

> [!CAUTION]
> 这是 PRD 中 §2.5 的核心功能，目前属于**形式上完成、实际上不可用**。

#### C-2: 附件提取 (Object Export) 为纯猜测逻辑，无法真正导出文件

[ExtractObjects()](file:///c:/Users/QAQ/Desktop/gshark/backend/internal/engine/analysis.go#128-154) 仅根据 payload 中是否包含 "filename=" 来猜测文件名，文件大小使用 `packet.Length * 12` 粗暴估算，且**没有提供文件下载功能**。应调用 `tshark --export-objects` 来做真正的文件提取。

#### C-3: 前端过滤器在后端模式下需要重新解析整个文件

`applyFilter()` 会调用 `bridge.startStreamingPackets(fileMeta.path, displayFilter)` 重新发起完整解析。对于 GB 级文件，每次修改过滤器都需要等待数分钟重新解析，严重影响体验。应做到在已加载数据上做前端过滤/后端增量过滤。

#### C-4: 所有数据包全量加载到内存中

[service.go](file:///c:/Users/QAQ/Desktop/gshark/backend/internal/engine/service.go) 中 `packets []model.Packet` 将所有解析结果存入切片，前端 Context 也同样用 `useState<Packet[]>` 全量保存。当处理 GB 级 PCAP 文件时，内存将快速爆炸。PRD §3.1 明确要求内存不随数据量线性增长。

### 🟠 重大问题 (Major)

#### M-1: [package.json](file:///c:/Users/QAQ/Desktop/gshark/frontend/package.json) 中 name 字段为 `@figma/my-make-file`

这是一个脚手架遗留问题，应改为 `@gshark/sentinel-frontend`。

#### M-2: 同时依赖 MUI v7 和 Radix UI 两套组件库

[package.json](file:///c:/Users/QAQ/Desktop/gshark/frontend/package.json) 中同时引入了 `@mui/material` (v7.3.5) 和大量 `@radix-ui/*`，但源码中 MUI 似乎**几乎未使用**。这增加了约 2MB+ 的 bundle 体积、降低首屏速度。

#### M-3: 无任何测试

项目中**0 个测试文件**。后端 Go 代码没有 `_test.go`，前端也没有任何 Jest/Vitest 测试。对于安全工具来说，解析准确性和威胁检测规则的正确性需要充分测试。

#### M-4: 隐写术检测为 `SizeBytes % 2 == 1` 占位逻辑

[StegoPrecheck()](file:///c:/Users/QAQ/Desktop/gshark/backend/internal/engine/analysis.go#176-198) 仅判断文件大小是否为奇数，这是一个明显的占位符逻辑，没有真正检查 IHDR 错误或 EOF 附加数据。

#### M-5: go.mod 模块路径不一致

根目录 [go.mod](file:///c:/Users/QAQ/Desktop/gshark/go.mod) 为 `github.com/gshark/sentinel/desktop`，而 [backend/go.mod](file:///c:/Users/QAQ/Desktop/gshark/backend/go.mod) 为 `github.com/gshark/sentinel/backend`，两个独立 Go module 没有 workspace 管理。

#### M-6: 前端 `filteredPackets` 实际上等于 `packets`（未生效过滤）

[SentinelContext.tsx](file:///c:/Users/QAQ/Desktop/gshark/frontend/src/app/state/SentinelContext.tsx) 第 109 行：`const filteredPackets = packets;` — 前端侧的过滤逻辑被完全绕过。[engine.ts](file:///c:/Users/QAQ/Desktop/gshark/frontend/src/app/core/engine.ts) 中已有 [applyDisplayFilter()](file:///c:/Users/QAQ/Desktop/gshark/frontend/src/app/core/engine.ts#147-165) 函数但未调用。

### 🟡 中等问题 (Medium)

#### m-1: SSE 事件流无重连机制
当后端重启或网络中断时，`EventSource` 没有自动重连逻辑。

#### m-2: App.tsx 中禁用了右键菜单和 DevTools 快捷键
在开发/调试阶段这会造成不便，应仅在生产环境下启用。

#### m-3: [guessObjectName()](file:///c:/Users/QAQ/Desktop/gshark/backend/internal/engine/analysis.go#207-223) 过于简单
所有 PNG 文件都叫 "capture.png"，所有 ZIP 都叫 "archive.zip"，无法区分不同文件。

#### m-4: 威胁检测规则过少且存在误报
SQL 注入规则 `\bselect\b` 会匹配所有包含 "select" 的正常 HTTP 请求。应提高规则精准度。

#### m-5: 暗黑模式初步实现 (框架就绪，细节待补)

PRD §3.2 要求暗黑模式支持。目前 `theme.css` 变量体系及 `MainLayout` 切换开关已完成；`ObjectExport`, `Decryption` 已基本适配。**但 `Workspace` 中的 `PacketVirtualTable` 和 `Streams`、`ThreatHunting` 页面仍保留大量硬编码的亮色类 (bg-slate-50, bg-rose-50 等)，在暗色模式下体验不佳。**

#### M-7: PacketVirtualTable 视口高度硬编码 (360px)

[PacketVirtualTable.tsx](file:///c:/Users/QAQ/Desktop/gshark/frontend/src/app/components/PacketVirtualTable.tsx#71) 中 `VIEWPORT_HEIGHT` 为硬编码值，限制了数据包列表在高分辨率屏幕下的展示面积，无法随窗口调整自适应。

#### M-8: HttpStream 二进制数据展示风险

[HttpStream.tsx](file:///c:/Users/QAQ/Desktop/gshark/frontend/src/app/pages/HttpStream.tsx#193-204) 中的 `toHexDump` 使用 `TextEncoder().encode(text)` 处理后端传来的字符串。若原始流中包含非 UTF-8 字符（二进制负载），字符串在传输或转换过程中可能已损坏或产生乱码，前端 Hex 视图将无法准确还原原始字节。

#### m-8: 后端代码风格优化 (Switch 重构) ✅

已将 `http_server.go` 和 `service.go` 中的多余 `if-else` 逻辑重构为更清晰的 `switch` 结构，并清理了 `runner.go` 中的冗余辅助函数。

#### m-9: 前端列设置持久化覆盖逻辑缺陷

[PacketVirtualTable.tsx](file:///c:/Users/QAQ/Desktop/gshark/frontend/src/app/components/PacketVirtualTable.tsx#55) 中加载逻辑会用 `localStorage` 中的旧标签直接覆盖代码中的 `defaults.label`。这意味着如果开发者后续更新了列名（如国际化或功能细化），老用户将永远看不到更新，除非手动重置列配置。

#### m-6: `react` 和 `react-dom` 被列为 `peerDependencies` 而非 `dependencies`
前端可能因此安装不完整。

#### m-7: 协议树和 Hex 视图的字节偏移基于估算，非真实 tshark 输出
[buildProtocolTree()](file:///c:/Users/QAQ/Desktop/gshark/frontend/src/app/core/engine.ts#265-323) 和 [buildFrameBytes()](file:///c:/Users/QAQ/Desktop/gshark/frontend/src/app/pages/Workspace.tsx#326-355) 使用固定偏移量（14 + 20 + 20），不考虑实际的以太网帧变体、TCP 选项等。

---

## 三、下一步发展方案

### Phase 1：基础夯实（1-2 周）✅ 阶段已完成

| # | 任务 | 优先级 |
|---|------|--------|
| 1.1 | **[✅完成] 修复 TLS 解密**：在 `tshark.BuildArgs()` 中注入 `-o tls.keylog_file:xxx` 和 RSA 私钥参数，使 TLS 解密真正生效 | P0 |
| 1.2 | **[✅完成] 修复前端过滤**：恢复 `filteredPackets` 使用 `applyDisplayFilter()` 进行前端侧过滤，避免每次重新解析 | P0 |
| 1.3 | **[✅完成] 修复 package.json**：更正 name 字段，将 `react`/`react-dom` 从 peerDeps 移入 dependencies，移除未使用的 MUI 依赖 | P0 |
| 1.4 | **[✅完成] 补充后端单元测试**：为 `tshark/runner.go` 的 EK 解析、`engine/analysis.go` 的威胁检测规则编写 Go 测试 | P1 |
| 1.5 | **[✅完成] 修复 go.mod 路径**：统一根目录和 backend 的 module 命名，引入 Go workspace | P1 |

### Phase 2：核心功能补全（2-3 周）🚀 当前进行中

| # | 任务 | 优先级 |
|---|------|--------|
| 2.1 | **[✅完成] 真实附件提取**：后端调用 `tshark --export-objects` 提取文件，并提供 ZIP 打包下载 API | P0 |
| 2.2 | **[✅完成] 分页/游标加载**：后端提供 `/api/packets/page` 游标分页，前端按页增量拉取并结合虚拟滚动触底加载，限制前端包窗口大小 | P0 |
| 2.3 | **[✅完成] 暗黑模式深化适配**：将 `PacketVirtualTable`, `Workspace`, `Streams`, `ThreatHunting`, `MainLayout`, `Plugins` 中的硬编码颜色替换为主题变量 | P1 |
| 2.4 | **[✅提前完成] SSE 自动重连**：前端 `subscribeEvents()` 增加断线重连和指数退避逻辑 | P1 |
| 2.5 | **[✅完成] 增强威胁检测规则**：已完成 SQL 规则收紧（降低普通 `select` 误报）与 WebShell 关键特征识别，并补充回归测试 | P1 |
| 2.6 | **[✅完成] 真实隐写初筛**：解析提取的 PNG 文件 IHDR 信息并检查 EOF 附加数据 | P2 |
| 2.7 | **[✅完成] 修复虚表视口高度**：使用 ResizeObserver 动态计算列表容器可用高度，彻底替代 360px 硬编码 | P1 |
| 2.8 | **[✅完成] 修复 Hexdump 00 补位问题**：将 `ReadPacketRawHexFromFile` 解析策略从 `frame.raw` 切换为解析 `tshark -x` 的原生 hexdump 输出 | P1 |

### Phase 3：体验打磨（1-2 周）

| # | 任务 | 优先级 |
|---|------|--------|
| 3.1 | **[✅完成] 协议树精确字节映射**：从 tshark EK 输出提取 IP/L4 头长度，前端协议树与 Hex 视图改为动态偏移映射 | P1 |
| 3.2 | **[✅完成] HTTP 响应自动解压 / 格式化**：已支持 JSON/HTML 自动格式化，并在 Formatted 视图中自动尝试 gzip 解压 | P1 |
| 3.3 | **[✅完成] 过滤器语法高亮和自动补全**：已提供过滤器常用语法自动补全建议 | P2 |
| 3.4 | **[✅完成] 生产环境自动构建脚本**：新增 GitHub Actions CI（前端构建 + 后端格式检查与测试） | P2 |
| 3.5 | **优化流数据传输格式**：处理二进制展示乱码问题 | P1 |

### Phase 4：高级功能（未来规划）

| # | 任务 |
|---|------|
| 4.1 | **插件引擎**：实现真正的 Go DLL / Lua 插件加载和执行 |
| 4.2 | **大文件流式解析（GB级）**：分块 tshark 调度、前端分区虚拟化 |
| 4.3 | **DNS 隧道检测**：分析 DNS 查询长度和频率异常 |
| 4.4 | **ICMP 隧道检测** |
| 4.5 | **数据包时序分析与可视化** |

---

## 四、验证方案

### 自动化测试

目前项目 0 测试覆盖率，建议从以下方面入手：

1. **后端 Go 单元测试**

```bash
cd backend
go test ./internal/...  -v
```

计划为以下模块编写 `_test.go`：
- `tshark/runner_test.go`：测试 [ParsePacketFromEK()](file:///c:/Users/QAQ/Desktop/gshark/backend/internal/tshark/runner.go#26-117) 对各种 EK JSON 的解析
- `engine/analysis_test.go`：测试威胁检测规则的精确匹配和误报控制
- `transport/http_server_test.go`：测试 API 路由返回

2. **前端 Vitest 测试**

```bash
cd frontend
npx vitest run
```

计划添加 `vitest` 依赖并编写：
- `core/engine.test.ts`：测试 [applyDisplayFilter()](file:///c:/Users/QAQ/Desktop/gshark/frontend/src/app/core/engine.ts#147-165)、[buildProtocolTree()](file:///c:/Users/QAQ/Desktop/gshark/frontend/src/app/core/engine.ts#265-323) 等纯函数

### 手动验证

1. 使用项目根目录的 [http.pcap](file:///c:/Users/QAQ/Desktop/gshark/http.pcap) 文件测试完整解析流程
2. 确认 TLS 解密修复后，提供 SSLKEYLOGFILE 可以正确解密 HTTPS 流量
3. 确认过滤器修复后，输入 `http` 可以在已加载的数据上即时过滤
