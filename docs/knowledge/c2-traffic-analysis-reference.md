# C2 流量分析与解密技术参考

> 基于 meow~traffic 项目的 C2 检测/解密功能，整理的相关技术资料。

## 1. VShell RAT 技术分析

### 核心参考

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **NVISO — Decoding VShell** (PDF) | [blog.nviso.eu](https://blog.nviso.eu/wp-content/uploads/2025/11/VShell.pdf) | **最权威的 VShell 分析。** 涵盖 AES-GCM 加密（nknorg/encrypted-stream）、密钥派生（MD5(salt)）、数据包格式（4B LE长度 + 12B nonce + 密文 + 16B auth tag）、Wireshark 解密插件、Suricata 检测规则。 | **关键** — 直接匹配项目的 triple-KDF 和 AES-GCM 实现 |
| **Esonhugh — How-AI-Kills-the-VShell** | [github.com](https://github.com/Esonhugh/How-AI-Kills-the-VShell) | 完整逆向分析：配置加载（AES-CBC，key=IV=前16字节）、WebSocket-over-TCP 伪装、握手流程（版本hash → vkey挑战 → conf上传）、**Python PCAP 解密器**（`pcap_decrypter.py`）。还记录了 Fake Beacon 和 DoS 漏洞。 | **关键** — 包含可工作的解密代码和协议流程 |
| **NVISO 博客** | [nviso.eu](https://www.nviso.eu/blog/nviso-analyzes-vshell-post-exploitation-tool) | 公开摘要，包含可操作的 Suricata 签名（客户端/服务器握手模式、Windows/Linux/macOS stager 规则）。 | 检测签名集成 |
| **Censys — VShell 基础设施** | [censys.com](https://censys.com/blog/vshell/) | 互联网范围扫描：850+ 监听器，默认 TCP/8084，多协议支持（WebSocket, DNS, DoH, DoT, OSS/S3），NPS 代码库复用。 | 基础设施指纹和暴露数据 |
| **Sysdig — UNC5174 VShell 活动** | [sysdig.com](https://www.sysdig.com/blog/unc5174-chinese-threat-actor-vshell) | SNOWLIGHT dropper → 无文件 VShell 投递，WebSocket C2 端口 8443，进程伪装 `[kworker/0:2]`，XOR 0x99 加密，`memfd_create` + `fexecve` 内存执行。 | WebSocket C2 通道分析 |
| **Trellix — VShell 无文件威胁** | [trellix.com](https://www.trellix.com/blogs/research/the-silent-fileless-threat-of-vshell/) | Linux 特定感染链：RAR 档案中的恶意文件名触发 shell 命令注入，XOR 加密 C2，内存驻留执行。 | Linux 感染链细节 |
| **PolySwarm — VShell Linux 后门** | [polyswarm.io](https://blog.polyswarm.io/vshell-linux-backdoor) | 多架构支持（x86/x64/ARM/ARM64），XOR 加密 C2，`fexecve()` 内存执行。 | Linux 后门分析 |

### 关键技术细节（与项目实现匹配）

```
加密算法: AES-256-GCM (via nknorg/encrypted-stream)
密钥派生: MD5(salt_from_config) → 32字节十六进制字符串作为 AES 密钥
数据包格式: [4B LE payload size][12B AES-GCM nonce][可变长密文][16B auth tag]
Nonce 规则: 客户端发送时首字节 < 0x80，服务器发送时首字节 > 0x80
```

### 项目实现对照

| 项目组件 | 参考来源 | 匹配度 |
|----------|----------|--------|
| `c2_decrypt.go` Triple-KDF | NVISO PDF + Esonhugh 仓库 | ✅ 完全匹配 |
| WebSocket 帧解析 | Esonhugh 的协议流程文档 | ✅ 匹配 |
| GCM 扫描策略 | NVISO 的数据包格式说明 | ✅ 匹配 |
| 候选收集预算 | 无直接参考（项目独创） | — |

---

## 2. Cobalt Strike Beacon 检测

### 核心参考

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **JA3/JA3S 原始论文** | [Medium/Salesforce](https://medium.com/salesforce-engineering/tls-fingerprinting-with-ja3-and-ja3s-247362855967) | TLS 指纹方法。CS JA3: `72a589da586844d7f0818ce684948eea`，JA3S: `b742b407517bac9536a77a7b0fee28e9`。 | TLS 指纹检测 |
| **Unit42 — Malleable C2 检测** | [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2/) | 识别 CS Team Server，提取 Malleable C2 配置。涵盖编码（Mask, NetBIOSU）、头部操纵、伪造 Host 头。 | 配置提取和检测 |
| **Unit42 — Malleable C2 配置** | [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2-profile/) | 深入 Malleable C2 配置语言：全局选项（sleeptime, jitter）、事务类型（http-get, http-post）、URI 模式。 | 理解 CS 流量伪装 |
| **TheDFIRReport — 防御者指南** | [thedfirreport.com](https://thedfirreport.com/2022/01/24/cobalt-strike-a-defenders-guide-part-2/) | 实战检测：Sigma 规则、RITA beacon 检测、JA3/JA3S 指纹、JARM TLS 指纹、Arkime 集成、DNS C2 检测。 | 综合检测手册 |
| **NVISO — CS 流量解密** | [blog.nviso.eu](https://blog.nviso.eu/2021/11/03/cobalt-strike-using-process-memory-to-detect-traffic-part-3/) | 从 beacon 进程内存提取 AES/HMAC 密钥。工具：`cs-extract-key.py`、`cs-parse-http-traffic.py`。 | 流量解密方法论 |
| **Netskope — C2 Beacon 检测** | [netskope.com](https://www.netskope.com/blog/advancing-c2-beacon-detection-for-malleable-frameworks) | 基于 ML 的 beacon 检测。240+ 伪装 beacon 配置，加密流量 DPI 挑战，行为分析方法。 | 高级检测技术 |
| **arXiv — ML 检测 CS C2** | [arxiv.org](https://arxiv.org/html/2506.08922v1) | 学术论文：使用网络元数据的监督学习检测 CS C2（无 DPI）。F1 分数 0.78–1.0。测试 120K+ 真实 Beacon。 | 研究级检测方法论 |

### 检测工具

| 工具 | URL | 用途 |
|------|-----|------|
| **RITA** | [github.com/activecm/rita](https://github.com/activecm/rita) | Go 框架，基于 Zeek 日志的 C2 检测 |
| **JA3/JA3S** | [github.com/salesforce/ja3](https://github.com/salesforce/ja3) | TLS 客户端/服务器指纹 |
| **Archer** | [github.com/BushidoCyb3r/Archer](https://github.com/BushidoCyb3r/Archer) | 自托管 NDR 平台 |
| **C2-Profiler** | [github.com/mazen91111/C2-Profiler](https://github.com/mazen91111/C2-Profiler) | PCAP C2 框架指纹识别 |
| **Shrike** | [github.com/fevra-dev/Shrike](https://github.com/fevra-dev/Shrike) | Python 网络取证 |

---

## 3. AES-GCM 在恶意软件中的应用

| 资源 | URL | 摘要 |
|------|-----|------|
| **GHOUL C2** | [az0th.it](https://az0th.it/projects/discord-c2-server_ghoul/) | 使用 AES-256-GCM 的 Discord C2。线格式：`base64(IV[12] + TAG[16] + CIPHERTEXT)` |
| **内核空间 C2 加密** | [hxr1.ghost.io](https://hxr1.ghost.io/kernel-space-c2-encryption-on-rhel-your-edr-cant-see/) | Linux `AF_ALG` 内核 crypto API 的 AES-256-CTR |
| **Havoc C2 PCAP 解析器** | [GitHub](https://github.com/Immersive-Labs-Sec/HavocC2-Forensics) | Python 工具解密 Havoc C2 流量（AES-CTR） |
| **VShell PCAP 解密器** | [GitHub](https://github.com/Esonhugh/How-AI-Kills-the-VShell/blob/Skyworship/pcap_decrypter.py) | **直接相关。** Python 解密器，key = `md5(salt).hexdigest().encode('ascii')`（32 字节） |

---

## 4. WebSocket C2 通道

| 资源 | URL | 摘要 |
|------|-----|------|
| **Patchwork StreamSpy** | [ti.qianxin.com](https://ti.qianxin.com/blog/articles/analysis-of-streamspy-a-new-trojan-using-websocket-by-patchwork-en/) | APT 木马使用 WebSocket + HTTP 混合 C2 |
| **Azure ServiceBus WebSocket C2** | [levelblue.com](https://www.levelblue.com/blogs/spiderlabs-blog/azure-servicebus-websockets-as-a-c2-channel) | CobaltStrike over Azure Service Bus WebSockets |
| **RoadK1ll** | [blackpointcyber.com](https://blackpointcyber.com/blog/roadk1ll-a-websocket-based-pivoting-implant/) | Node.js 反向隧道植入，WebSocket 中继 TCP 连接 |
| **GOVERSHELL WebSocket 变体** | [cyfar.ca](https://cyfar.ca/posts/apt-meets-gpt-targeted-operations-with-untamed-llms) | UTA0388 使用带自定义 AES 的 WebSocket C2 |
| **Lazarus WebSocket C2** | [expel.com](https://expel.com/blog/inside-lazarus-how-north-korea-uses-ai-to-industrialize-attacks-on-developers/) | 朝鲜 Lazarus 组使用 WebSocket 实时文件浏览器和反向 shell |

---

## 5. 开源 C2 检测工具

| 工具 | URL | 用途 |
|------|-----|------|
| **RITA** | [github.com/activecm/rita](https://github.com/activecm/rita) | Go 框架，基于 Zeek 日志的 C2 检测 |
| **Zeek** | [zeek.org](https://zeek.org) | 网络安全监控器 |
| **JA3/JA3S** | [github.com/salesforce/ja3](https://github.com/salesforce/ja3) | TLS 指纹 |
| **Archer** | [github.com/BushidoCyb3r/Archer](https://github.com/BushidoCyb3r/Archer) | 自托管 NDR 平台 |
| **C2-Profiler** | [github.com/mazen91111/C2-Profiler](https://github.com/mazen91111/C2-Profiler) | PCAP C2 框架指纹 |
| **Shrike** | [github.com/fevra-dev/Shrike](https://github.com/fevra-dev/Shrike) | Python 网络取证 |
| **Arkime** | [arkime.com](https://arkime.com) | 全包捕获和索引搜索 |
