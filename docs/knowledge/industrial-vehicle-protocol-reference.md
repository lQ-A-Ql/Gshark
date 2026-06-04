# 工业/车辆协议安全技术参考

> 基于 meow~traffic 项目的工业协议（Modbus, DNP3, IEC 104）和车辆协议（CAN bus, UDS）分析功能，整理的相关技术资料。

## 1. ICS/SCADA 安全 — Modbus, DNP3, IEC 104

### 学术论文与技术分析

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **ICS 和关键基础设施漏洞与攻击** | [ResearchGate](https://www.researchgate.net/publication/354493711_Vulnerabilities_and_Attacks_Against_Industrial_Control_Systems_and_Critical_Infrastructures) | 涵盖 Modbus, DNP3, IEC-104, EtherNet/IP, OPC 协议的综合调查。分析真实事件（Stuxnet, Industroyer）。 | **高** — 直接涵盖项目支持的所有工业协议 |
| **DNP3 通信协议漏洞** | [MDPI](https://www.mdpi.com/2673-4591/123/1/17) | DNP3 安全限制：MITM 攻击、从站发现、冷/热重启 DoS。使用 CIC-FlowMeter 和 openDNP3 进行异常检测。 | **高** — DNP3 攻击向量和检测方法 |
| **DNP3 攻击现实检查** | [MDPI](https://www.mdpi.com/2624-6511/7/6/154) | 挑战先前的 DNP3 攻击假设。引入 ARP 欺骗 + 动态 NAT 绕过 IP 白名单。 | **高** — DNP3 MITM 可行性关键洞察 |
| **Modbus TCP vs DNP3 通信故障弹性** | [OSTI](https://www.osti.gov/servlets/purl/3013478) | 测试台比较 SYN-flood、RST 和 PSH+ACK 攻击下的 Modbus TCP 和 DNP3。 | **高** — 直接协议比较 |

### 实用加固与防御

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **Modbus & DNP3 加固** | [Pingdo Labs](https://pingdo.net/security/modbus-dnp3-hardening/) | ISA/IEC 62443 "管道" 模式技术蓝图。涵盖 Modbus TCP MBAP 头利用、PLC 指纹、DNP3-SA v5 HMAC-SHA256 认证。 | **高** — 可操作的加固策略 |
| **ICS-CERT 公告** | [CISA ICS](https://www.cisa.gov/ics-cert/advisories) | 工业控制系统官方漏洞公告。 | **高** — 跟踪工业协议漏洞的主要来源 |

---

## 2. CAN 总线安全 — UDS, CAN 注入, 车辆取证

### 学术研究

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **利用商用车辆诊断协议漏洞** | [NDSS 2024](https://www.ndss-symposium.org/ndss-paper/auto-draft-480/) | 在真实 Freightliner Cascadia 卡车上演示三个 UDS 漏洞和一个 ISO 15765 缺陷。 | **高** — UDS 协议利用与真实 ECU 测试结果 |
| **从 ECU 到 VSOC：UDS 安全监控策略** | [arXiv](https://arxiv.org/html/2510.25375) | 53 种 UDS 攻击技术映射到 MITRE ATT&CK 的 VSOC 检测策略。 | **高** — 检测策略分类法 |
| **CANTXSec：确定性入侵检测** | [arXiv](https://arxiv.org/pdf/2505.09384) | 基于物理 ECU 激活的首个确定性 IDPS。100% 检测准确率。 | **高** — 新颖的 CAN IDS 方法 |
| **CAN-MIRGU：全面 CAN 总线攻击数据集** | [NDSS VehicleSec 2024](https://www.ndss-symposium.org/wp-content/uploads/vehiclesec2024-43-paper.pdf) | 17 小时良性 + 2 小时 54 分钟攻击数据。26 种真实注入攻击（DoS, fuzzing, replay, spoofing）。 | **高** — CAN IDS 开发基准数据集 |
| **使用深度学习保护 CAN 总线** | [Nature](https://www.nature.com/articles/s41598-025-98433-x) | LSTM 达到 99.89% 准确率，VGG-16 达到 100%。 | **中** — CAN 异常检测的 ML 参考 |

### 工具与框架

| 工具 | URL | 用途 | 相关度 |
|------|-----|------|--------|
| **CANToolz** | [GitHub](https://github.com/eik00d/CANToolz) | Python CAN 总线逆向工程框架。模块：MITM, UDS 扫描器, fuzzer, 统计分析。 | **高** — CAN 分析工具参考架构 |
| **SavvyCAN** | [savvycan.com](https://savvycan.com/index.php) | 跨平台 CAN 逆向工程工具。DBC 文件支持, UDS 扫描/解码, 信号绘图。 | **高** — 成熟的开源 CAN 分析平台 |
| **Gallia** | [GitHub](https://github.com/Fraunhofer-AISEC/gallia) | Fraunhofer 渗透测试框架，专注于汽车 UDS。支持 ISO-TP, 可重现测试, 日志记录。 | **高** — 生产质量的 UDS 渗透测试框架 |
| **cantools** | [GitHub](https://github.com/cantools/cantools) | Python CAN 总线工具。DBC/KCD/SYM/ARXML 解析, 消息编码/解码。 | **高** — CAN 协议处理核心库 |

---

## 3. 工业协议解析器

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **marlinspike-dpi** | [GitHub](https://github.com/eris-ot/marlinspike-dpi) | 纯 Rust 被动 DPI，支持 44+ OT 协议：Modbus, DNP3, IEC 60870-5-104, IEC 61850, S7comm, EtherNet/IP, OPC UA 等。 | **关键** — 最全面的 OT 协议解析器库 |
| **Wireshark Modbus/TCP 解析器** | [GitHub](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-mbtcp.c) | 官方 Wireshark C 解析器。 | **高** — Modbus 解析参考实现 |
| **ICSNPP-Modbus (CISA)** | [GitHub](https://github.com/cisagov/icsnpp-modbus/) | Zeek Modbus 扩展脚本。ICSNPP 套件的一部分（也包括 DNP3, EtherNet/IP 等）。 | **高** — 美国政府生产级 Zeek ICS 解析器 |

---

## 4. OT 网络监控

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **资产感知网络监控** | [SANS Institute](https://www.sans.org/white-papers/asset-aware-network-monitoring) | 基于 Zeek 的被动监控，将观察到的流量与资产清单进行比较。 | **高** — 实用的 Zeek OT 监控方法 |
| **ConduitShield** | [GitHub](https://github.com/SiteQ8/ConduitShield) | 开源 OT/ICS 工具：被动资产发现、ISA/IEC 62443 区域/管道策略、MITRE ATT&CK ICS 映射。 | **高** — 完整 OT 安全平台架构参考 |

---

## 5. 车辆安全研究

### DEF CON / Black Hat 演讲

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **CANSPY** (DEF CON 24) | [DEF CON Media](https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEF%20CON%2024%20-%20Demay-CANSPY-a-Platorm-For-Auditing-CAN-Devices-WP-UPDATED.pdf) | CAN MITM 平台。阻塞/转发/修改 CAN 帧。 | **高** — CAN MITM 架构 |
| **TRITON** (Black Hat 2018) | [InfoconDB](https://infocondb.org/con/black-hat/black-hat-usa-2018/triton-how-it-disrupted-safety-systems-and-changed-the-threat-landscape-of-industrial-control-systems-forever) | 针对 Schneider Triconex SIS 的 TRITON 恶意软件分析。 | **高** — 最复杂的 ICS 攻击框架分析 |
| **通过攻击者视角看 ICS** (DEF CON 26) | [InfoconDB](https://infocondb.org/con/def-con/def-con-26/through-the-eyes-of-the-attacker-designing-embedded-systems-exploits-for-industrial-control-systems) | ICS 漏洞开发深入探讨。 | **高** — ICS 漏洞开发方法论 |

### 关键研究论文

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **CAN-MIRGU 数据集** | [NDSS VehicleSec](https://www.ndss-symposium.org/wp-content/uploads/vehiclesec2024-43-paper.pdf) | 现代车辆 CAN 攻击数据集，26 种真实攻击 + 10 种模拟攻击。 | **高** — CAN IDS 开发基准数据集 |
| **PerfektBlue** | [GitHub](https://github.com/Nour833/PerfektBlue) | 汽车蓝牙和 CAN 利用框架。多阶段：BT 指纹 → RCE → CAN 总线分析。 | **中** — BT 到 CAN 攻击链参考 |

---

## 6. 开源工具总结

### 协议解析与分析

| 工具 | 语言 | 协议 | 用途 |
|------|------|------|------|
| [marlinspike-dpi](https://github.com/eris-ot/marlinspike-dpi) | Rust | 44+ OT 协议 | 生产 DPI 引擎 |
| [ICSNPP](https://github.com/cisagov/icsnpp-modbus/) | Zeek script | Modbus, DNP3, EtherNet/IP | 网络监控 |
| [cantools](https://github.com/cantools/cantools) | Python | CAN (DBC/KCD) | CAN 消息解析 |

### CAN 总线安全

| 工具 | 平台 | 能力 |
|------|------|------|
| [CANToolz](https://github.com/eik00d/CANToolz) | Python | MITM, UDS 扫描, fuzz, replay, 模拟器 |
| [SavvyCAN](https://savvycan.com) | C++/Qt | RE, DBC, UDS, 绘图, 多硬件 |
| [Gallia](https://github.com/Fraunhofer-AISEC/gallia) | Python | UDS 渗透测试框架 |

### OT 安全平台

| 工具 | 重点 | 关键特性 |
|------|------|----------|
| [ConduitShield](https://github.com/SiteQ8/ConduitShield) | 完整 OT 安全 | 资产发现, IEC 62443 区域, MITRE ATT&CK ICS |
| [Zeek](https://zeek.org) | 网络分析 | 通过 ICSNPP 插件的 ICS 协议分析器 |
| [Suricata](https://suricata.io) | IDS/IPS | OT 协议规则, 签名匹配 |
