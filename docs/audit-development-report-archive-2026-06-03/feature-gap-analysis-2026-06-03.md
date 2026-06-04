# 功能缺失审计报告

> 依据 `docs/knowledge/` 知识文档，对比项目实际实现，识别功能缺失点。

**审计日期**：2026-06-03  
**审计方法**：知识文档能力清单 vs 代码库实际实现  
**审计范围**：C2/WebShell 检测、协议分析、YARA/威胁狩猎

---

## 一、C2/WebShell 检测缺失

### 1.1 CRITICAL 缺失

| 缺失能力 | 知识文档来源 | 严重度 | 说明 |
|----------|-------------|--------|------|
| **JA3/JA3S TLS 指纹** | c2-traffic-analysis-reference.md | 🔴 CRITICAL | 知识文档明确列出 CS JA3 (`72a589da586844d7f0818ce684948eea`) 和 JA3S 指纹。代码库零实现。无 `tls.handshake.ja3` 字段提取，无 JA3 哈希存储。 |
| **JARM TLS 服务器指纹** | c2-traffic-analysis-reference.md | 🔴 CRITICAL | 知识文档引用 TheDFIRReport 的 JARM 指纹。代码库零实现。 |

### 1.2 HIGH 缺失

| 缺失能力 | 知识文档来源 | 严重度 | 说明 |
|----------|-------------|--------|------|
| **Cobalt Strike Malleable C2 配置匹配** | c2-traffic-analysis-reference.md | 🟠 HIGH | 当前仅有"弱信号"评分（`tool_c2.go:193`）。无已知默认配置的正向匹配（如 `jquery-3.3.1.min.js` URI、Mask/NetBIOSU 编码检测）。 |
| **CS beacon 水印/配置提取** | c2-traffic-analysis-reference.md | 🟠 HIGH | 代码库零实现。知识文档引用 `1768.py` 配置提取器。 |
| **Behinder v2.0 动态密钥协商检测** | behinder-webshell-reference.md | 🟠 HIGH | 知识文档描述 2-GET 握手模式（`pass=645` → session key → `pass=123` → AES key）。Go 代码未检测此两阶段 GET 模式。 |
| **China Chopper / 菜刀 流量解码器** | webshell_management_tools_analysis.md | 🟠 HIGH | YARA 规则存在（`traffic_cve_webshell.yar:356-371`），但无 Go 侧流解码器。`DecodeStreamPayload` switch 无 `china_chopper` case。 |
| **reGeorg / neo-reGeorg 隧道解码器** | webshell_management_tools_analysis.md | 🟠 HIGH | YARA 规则存在，但无 Go 侧隧道解码器。 |

### 1.3 MEDIUM 缺失

| 缺失能力 | 知识文档来源 | 严重度 | 说明 |
|----------|-------------|--------|------|
| **Behinder v1.0 固定 UA 检测** | behinder-webshell-reference.md | 🟡 MEDIUM | 知识文档列出 `Java/1.8.0_211` 等固定 UA。Go 代码无 HTTP 头检查。 |
| **Behinder Accept 头指纹** | behinder-webshell-reference.md | 🟡 MEDIUM | `Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2` 未检测。 |
| **CS sleep time / jitter 分析** | c2-traffic-analysis-reference.md | 🟡 MEDIUM | beacon 间隔检测存在，但不提取 CS 特定的 `sleeptime`/`jitter` 配置值。 |
| **统一 WebShell 家族/版本分类** | webshell_management_tools_analysis.md | 🟡 MEDIUM | `FamilyHint` 存在于每个候选上，但无聚合输出"此流量为 Behinder v3.0"的分析师视图。 |

---

## 二、协议分析缺失

### 2.1 CRITICAL 缺失

| 缺失能力 | 知识文档来源 | 严重度 | 说明 |
|----------|-------------|--------|------|
| **DNS 隧道检测** | pcap-network-forensics-reference.md | 🔴 CRITICAL | 知识文档详述 DNS 隧道检测（Unit 42 活动、DoH 检测）。代码库零实现。 |
| **DGA 域名检测** | pcap-network-forensics-reference.md | 🔴 CRITICAL | 知识文档引用 DGA 检测方法。代码库零实现。 |

### 2.2 HIGH 缺失

| 缺失能力 | 知识文档来源 | 严重度 | 说明 |
|----------|-------------|--------|------|
| **DNP3 协议解析** | industrial-vehicle-protocol-reference.md | 🟠 HIGH | 知识文档详述 DNP3 安全限制、MITM 攻击、异常检测。代码库仅支持 Modbus，无 DNP3。 |
| **IEC 60870-5-104 协议解析** | industrial-vehicle-protocol-reference.md | 🟠 HIGH | 知识文档涵盖 IEC 104。代码库零实现。 |
| **EtherNet/IP 协议解析** | industrial-vehicle-protocol-reference.md | 🟠 HIGH | 知识文档涵盖 EtherNet/IP。代码库零实现。 |
| **OPC UA 协议解析** | industrial-vehicle-protocol-reference.md | 🟠 HIGH | 知识文档涵盖 OPC UA。代码库零实现。 |
| **数据外泄检测** | c2-traffic-analysis-reference.md | 🟠 HIGH | 知识文档描述外泄检测方法。代码库零实现。 |
| **暴力破解检测** | — | 🟠 HIGH | 无登录失败阈值检测、无凭据填充检测。 |

### 2.3 MEDIUM 缺失

| 缺失能力 | 知识文档来源 | 严重度 | 说明 |
|----------|-------------|--------|------|
| **RTP 流提取** | usb-media-forensics-reference.md | 🟡 MEDIUM | 知识文档详述 RTP 流提取工具。代码库有 RTP 端口检测，但无独立 RTP 流提取。 |
| **VoIP MOS 估计** | usb-media-forensics-reference.md | 🟡 MEDIUM | 知识文档引用 SIP 流量分析器的 MOS 估计。代码库零实现。 |
| **SIP 协议解析** | usb-media-forensics-reference.md | 🟡 MEDIUM | 知识文档涵盖 SIP 解析。代码库零实现。 |
| **CAN 总线 DBC 文件支持** | industrial-vehicle-protocol-reference.md | 🟡 MEDIUM | 代码库已有 DBC 支持（`service_analysis.go:769-810`），但知识文档描述的更完整。 |

---

## 三、YARA/威胁狩猎缺失

### 3.1 CRITICAL 缺失

| 缺失能力 | 知识文档来源 | 严重度 | 说明 |
|----------|-------------|--------|------|
| **MITRE ATT&CK 映射** | yara-threat-hunting-reference.md | 🔴 CRITICAL | 知识文档详述 ATT&CK 映射方法。代码库零实现。`ThreatHit` 和 `EvidenceRecord` 结构体无 MITRE 字段。无技术 ID、战术 ID。 |

### 3.2 HIGH 缺失

| 缺失能力 | 知识文档来源 | 严重度 | 说明 |
|----------|-------------|--------|------|
| **社区 YARA 规则集成** | yara-threat-hunting-reference.md | 🟠 HIGH | 知识文档列出 Neo23x0/signature-base（2903★）、Yara-Rules/rules。代码库仅有自定义规则（`default.yar` 5 条 + `traffic_cve_webshell.yar` 20+ 条）。 |
| **YARA 性能优化** | yara-threat-hunting-reference.md | 🟠 HIGH | 知识文档详述性能最佳实践。代码库规则无 `filesize` 预检查、无条件排序优化。 |
| **内存扫描** | yara-threat-hunting-reference.md | 🟠 HIGH | 知识文档描述 VAD 遍历、malfind 检测。代码库仅扫描磁盘文件和重组流，无进程内存扫描。（注：PCAP 分析工具可能超出范围） |

### 3.3 MEDIUM 缺失

| 缺失能力 | 知识文档来源 | 严重度 | 说明 |
|----------|-------------|--------|------|
| **威胁狩猎剧本** | yara-threat-hunting-reference.md | 🟡 MEDIUM | 知识文档描述假设驱动狩猎方法论。代码库仅有基础前缀匹配和 YARA 扫描，无剧本、保存搜索、假设跟踪。 |
| **IOC 源集成** | yara-threat-hunting-reference.md | 🟡 MEDIUM | 知识文档引用 VirusTotal、AbuseIPDB 等。代码库无外部 IOC 源导入或匹配。 |
| **规则更新机制** | yara-threat-hunting-reference.md | 🟡 MEDIUM | 当前规则通过 `//go:embed` 静态嵌入。无规则下载、版本管理、启用/禁用机制。 |

---

## 四、汇总矩阵

### 按严重度统计

| 严重度 | 数量 | 关键项 |
|--------|------|--------|
| 🔴 CRITICAL | 4 | JA3/JA3S、JARM、DNS 隧道、MITRE ATT&CK |
| 🟠 HIGH | 12 | Malleable C2 匹配、CS 水印、Behinder v2.0 协商、China Chopper 解码器、DNP3/IEC104/EtherNet-IP/OPC、数据外泄、暴力破解、社区 YARA、YARA 性能、内存扫描 |
| 🟡 MEDIUM | 10 | Behinder UA/Accept、CS sleep、统一分类、RTP/VoIP/SIP、威胁狩猎剧本、IOC 源、规则更新 |

### 按功能域统计

| 功能域 | 已实现 | 缺失 | 覆盖率 |
|--------|--------|------|--------|
| C2 检测 | beacon 形状、间隔检测、VShell/Godzilla/AntSword 解码 | JA3/JA4、Malleable C2、CS 水印 | ~60% |
| WebShell 检测 | Behinder ECB/CBC、Godzilla XOR/AES、AntSword ROT13/chr | China Chopper、reGeorg、统一分类 | ~70% |
| 协议分析 | Modbus、CAN、UDS、USB HID/Mass Storage、RTP 检测 | DNP3、IEC104、EtherNet/IP、OPC UA、DNS 隧道、DGA | ~40% |
| YARA/狩猎 | 自定义规则、基础前缀匹配、异常检测 | MITRE ATT&CK、社区规则、性能优化、狩猎剧本 | ~30% |

---

## 五、优先修复建议

| 优先级 | 任务 | 预计工时 | 知识文档参考 |
|--------|------|---------|-------------|
| P0 | 实现 JA3/JA3S TLS 指纹提取和匹配 | 2-3 天 | c2-traffic-analysis-reference.md §2 |
| P0 | 实现 MITRE ATT&CK 技术 ID 映射 | 2-3 天 | yara-threat-hunting-reference.md §2 |
| P1 | 实现 DNS 隧道检测 | 1-2 天 | pcap-network-forensics-reference.md §4 |
| P1 | 集成社区 YARA 规则（Neo23x0/signature-base） | 1 天 | yara-threat-hunting-reference.md §5 |
| P1 | 实现 China Chopper 流量解码器 | 1 天 | webshell_management_tools_analysis.md |
| P2 | 实现 DNP3 协议解析 | 2-3 天 | industrial-vehicle-protocol-reference.md §1 |
| P2 | 实现 Malleable C2 配置正向匹配 | 1-2 天 | c2-traffic-analysis-reference.md §2 |
| P2 | 实现 Behinder v2.0 密钥协商检测 | 1 天 | behinder-webshell-reference.md §2.2 |
| P3 | 实现数据外泄检测 | 2-3 天 | c2-traffic-analysis-reference.md |
| P3 | 实现威胁狩猎剧本系统 | 3-5 天 | yara-threat-hunting-reference.md §2 |
