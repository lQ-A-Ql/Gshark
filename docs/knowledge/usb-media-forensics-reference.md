# USB 与媒体取证技术参考

> 基于 meow~traffic 项目的 USB 流量分析和媒体分析功能，整理的相关技术资料。

## 1. USB 取证 — 流量捕获与 HID 分析

### 核心参考

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **Wireshark USB 捕获指南** | [wiki.wireshark.org](https://wiki.wireshark.org/CaptureSetup/USB) | 跨平台 USB 流量捕获指南 — Linux (usbmon), Windows (USBPcap), macOS (XHC20)。涵盖软件捕获 (URB) 和硬件嗅探器。 | **核心** — USB 捕获机制参考 |
| **Linux usbmon 内核文档** | [docs.kernel.org](https://docs.kernel.org/6.19-rc7/usb/usbmon.html) | `usbmon` 设施官方文档。涵盖文本 API、二进制 API、ioctl 接口、mmap 环形缓冲区。 | **高** — Linux USB 捕获底层接口 |
| **Windows 10/11 USB 设备取证** | [blog.elcomsoft.com](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/) | Windows USB 工件深入探讨 — `USBSTOR` 注册表键、`Storage-ClassPnP` 事件日志、`SetupAPI.dev.log`、MountPoints2、LNK 文件、Jump Lists、ShellBags。 | **高** — 取证时间线重建 |
| **USB 工件理解：HID, MTP, PTP, MSC** | [cyberengage.org](https://www.cyberengage.org/post/usb-artifacts-what-gets-left-behind-and-where-to-find-it) | USB 设备类别及其取证足迹分类。HID 注册表键、MTP/PTP 便携设备跟踪、MSC 通过 USBSTOR。 | **高** — 直接映射到 HID 分析和 Mass Storage 取证 |
| **击键取证 101** | [infosecwriteups.com](https://infosecwriteups.com/keystroke-forensics-101-extracting-secrets-from-usb-traffic-7fdd4797d1a9) | 从 PCAP 文件解码 USB HID 键盘数据的教程。8 字节 HID 报告结构、tshark 提取、Python 键码映射。 | **高** — 直接适用于 HID 击键提取实现 |
| **CTF USB 键盘识别** | [emree-1.github.io](https://emree-1.github.io/posts/irisctf2025-forensics-deldeldel/) | 从 PCAP 识别 USB 设备的 CTF 解题。区分键盘的启发式方法：8 字节数据长度、第二字节始终 0x00、周期性空报告。 | **高** — 可直接实现的 HID 识别启发式 |

---

## 2. USB 攻击技术 — BadUSB, Rubber Ducky, 注入

### 核心参考

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **USBlock：阻止 USB 击键注入** | [Springer](https://link.springer.com/chapter/10.1007/978-3-319-95729-6_18) | 通过 USB 数据包流量的时间分析检测 BadUSB/Rubber Ducky。恶意设备以 ~6ms 间隔注入击键，人类打字下限 ~80ms。 | **高** — 基于时间的检测启发式 |
| **CIRCL TR-52：HID 攻击取证分析** | [circl.lu](https://circl.lu/pub/tr-52/) | Rubber Ducky 攻击取证分析：HID 设备连接检测、键盘驱动分配痕迹、PowerShell 命令重建、用户帐户创建检测。 | **高** — 端到端取证重建 |
| **DFRWS 2021：Duck Hunt** | [dfrws.org](https://dfrws.org/wp-content/uploads/2021/09/2021-usa-paper-20-duck_hunt_memory_forensics_of_usb_attack_platforms.pdf) | Rubber Ducky 和 Bash Bunny 的 Windows 10 内存分析。关键 IOC：Rubber Ducky 使用 Apple VID `05AC` / PID `0220`。 | **高** — 内存 IOC 互补 USB 流量分析 |
| **USB 路径外注入攻击** | [USENIX](https://www.usenix.org/system/files/usenixsecurity23-dumitru.pdf) | USENIX Security 2023：通过集线器的路径外 USB 注入。29 个测试的 USB 2.0/3.x 集线器中 14 个易受攻击。 | **高** — 新颖的攻击向量 |
| **BadUSB 2.0：USB 固定线路 MITM** | [docs.media.bitpipe.com](https://docs.media.bitpipe.com/io_10x/io_102267/item_1306461/RH-2016-BadUSB-DavidKierznowski.pdf) | 使用 ~$100 硬件在 USB 线缆上进行主动 MITM 攻击。启发式检测方法：端点异常、时序分析。 | **高** — 启发式检测方法适用 |

---

## 3. 开源 USB 分析框架

| 工具 | URL | 用途 | 相关度 |
|------|-----|------|--------|
| **Gallimaufry** | [github.com/bannsec](https://github.com/bannsec/gallimaufry) | Python USB PCAP 解析框架。 | **中** — USB PCAP 解析参考 |
| **usbrply** | [github.com/JohnDMcMaster](https://github.com/JohnDMcMaster/usbrply) | 将 USB PCAP 转换为 Python/C 重放代码。339★。 | **中** — USB 交互重放 |
| **USB-Mouse-Pcap-Visualizer** | [github.com/WangYihang](https://github.com/WangYihang/USB-Mouse-Pcap-Visualizer) | 从 USB 流量 PCAP 提取鼠标移动和点击数据。277★。 | **高** — 鼠标 HID 分析参考实现 |
| **AegisUSB** | [github.com/Soumit-Santra](https://github.com/Soumit-Santra/AegisUSB) | 综合 USB 安全工具：注册表扫描、行为基线、负载检测、YARA、13 条 MITRE ATT&CK 规则。 | **高** — MITRE ATT&CK 映射和风险评分架构 |
| **Low-Cost USB Sniffer** | [github.com/ataradov](https://github.com/ataradov/usb-sniffer) | 开源硬件 USB 2.0 总线嗅探器，Wireshark extcap 集成。 | **中** — 硬件 USB 捕获选项 |
| **USBPcap** | [desowin.org](https://desowin.org/usbpcap/) | Windows 内核模式 USB 流量捕获过滤驱动。 | **高** — Windows USB 捕获格式文档 |

---

## 4. 媒体取证 — 音频/视频分析与语音转文字

### 语音转文字引擎

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **OpenAI Whisper** | [github.com/openai](https://github.com/openai/whisper) | 通用语音识别模型，680,000 小时多语言数据训练。6 种模型大小，支持多语言 ASR、翻译、语言识别。48,000+★。 | **核心** — 媒体分析子系统的语音转文字引擎 |
| **WhisperX** | [github.com/m-bain](https://github.com/m-bain/whisperX) | 70x 实时转录，词级时间戳，说话人分离。21,000+★。 | **高** — 优于原始 Whisper 的取证用途 |
| **whisper.cpp** | [github.com/ggml-org](https://github.com/ggml-org/whisper.cpp) | 高性能 C/C++ Whisper 移植。Apple Silicon 优化，AVX, Vulkan, CUDA 支持。48,000+★。 | **高** — 无 Python 依赖的嵌入式语音转文字 |
| **whisper-timestamped** | [github.com/linto-ai](https://github.com/linto-ai/whisper-timestamped) | 使用交叉注意力权重扩展 Whisper 的词级时间戳和置信度分数。 | **中** — 内存受限时的替代方案 |

### 媒体取证工具

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **VoxTrace-DFIR** | [github.com/redzeptech](https://github.com/redzeptech/VoxTrace-DFIR) | 混合 DFIR 框架：音频取证（FFmpeg → Whisper → 翻译）+ Windows 工件分析。GPU 加速转录，SRT 字幕生成，统一时间线构建。 | **高** — 媒体分析与系统工件关联的架构参考 |
| **Vermanent** | [github.com/Leonardo-Corsini](https://github.com/Leonardo-Corsini/Vermanent) | 语音消息取证搜索。Whisper + spaCy/FastText 词嵌入进行语义相似度搜索。 | **中** — 语义搜索转录音频 |
| **ForensiGuard** | [github.com/hplaksh687](https://github.com/hplaksh687/forensiguard) | 检测 CCTV 篡改、深度伪造、合成语音、元数据操纵。加权真实性评分（0-100）。 | **高** — 音频真实性分析模块 |
| **Palimpsest** | [github.com/ephemera02](https://github.com/ephemera02/Palimpsest) | 视频取证桌面应用：场景匹配、水印检测、编码链分析、音频指纹、ENF 提取。 | **中** — ENF 提取是独特的取证技术 |

### 取证 ASR 限制

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **取证音频 ASR 性能** | [frontiersin.org](https://www.frontiersin.org/journals/communication/articles/10.3389/fcomm.2024.1281407/full) | 在模糊取证音频上评估 ASR 系统。Whisper 表现最佳但在低质量音频上仅达到 50% 词错误率。 | **高** — 设定现实期望 |
| **儿童剥削取证语音识别** | [mdpi.com](https://www.mdpi.com/1424-8220/23/4/1843) | 比较 Wav2Vec2.0 和 Whisper 的取证关键词检测。Whisper 达到 81-98% 真阳性率。 | **中** — 关键词检测方法 |

---

## 5. 网络媒体提取 — RTP/RTSP/VoIP 取证

### 核心参考

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **从网络捕获提取 RTP 流** | [giacomovacca.com](https://www.giacomovacca.com/2021/02/extracting-rtp-streams-from-network.html) | 从 PCAP 提取 RTP/SRTP 流的工具（`pcap_tool`）。SRTP 密钥提取、SILK 编解码器解码。 | **高** — SRTP 密钥提取和编解码器特定解码 |
| **rtpdump** | [github.com/hdiniz](https://github.com/hdiniz/rtpdump) | 从 PCAP 提取音频/视频。支持 IMS 编解码器（VoLTE/VoWiFi）。ESP 解密支持。 | **高** — 加密 VoWiFi 流量分析 |
| **rtpcap（Facebook）** | [github.com/facebookarchive](https://github.com/facebookarchive/rtpcap) | tshark 包装器，分析 RTC PCAP 跟踪。每流统计：网络时间聚合、音频包计时、视频帧聚合。 | **高** — 模块化统计提取模式 |
| **SIP 流量分析器** | [github.com/kambidi1973](https://github.com/kambidi1973/sip-flow-analyzer) | 综合 SIP/VoIP 工具包：RFC 3261 SIP 解析器、RTP/RTCP 分析（抖动、丢包、MOS 估计）。 | **高** — MOS 估计提供客观语音质量指标 |
| **快速 RTP 检测和编解码器分类** | [fit.vut.cz](https://www.fit.vut.cz/research/result-file/c111596/278885/icdf2c2014.pdf) | 无信令的在线 RTP 流检测多阶段方法。10 包阈值实现接近零误报。 | **高** — 可实现的 RTP 检测算法 |
| **Tranalyzer VoIP 插件** | [tranalyzer.org](https://tranalyzer.org/tutorial/voip) | 网络流分析器 VoIP 检测插件。RTP 内容雕刻模式保存为原始音频文件。 | **高** — RTP 内容雕刻方法 |

---

## 6. 与项目子系统的相关性总结

| 子系统 | 关键资源 |
|--------|----------|
| **USB HID 分析** | §1.5（击键取证）、§1.6（CTF 键盘 ID）、§3.3（鼠标可视化器） |
| **USB Mass Storage** | §1.3（Win10/11 取证）、§1.4（USB 工件）、§3.4（AegisUSB） |
| **USB 威胁检测** | §2.1（USBlock 时间）、§2.3（内存 IOC）、§2.4（路径外注入） |
| **语音转文字** | §4.1（Whisper）、§4.2（WhisperX 分离）、§4.3（whisper.cpp） |
| **媒体真实性** | §4.6（ForensiGuard）、§4.7（Palimpsest ENF） |
| **RTP/VoIP 分析** | §5.1（RTP 提取）、§5.4（SIP 分析器 MOS）、§5.6（RTP 检测） |
| **证据聚合** | §4.5（VoxTrace 时间线）、§3.4（AegisUSB MITRE 映射） |
