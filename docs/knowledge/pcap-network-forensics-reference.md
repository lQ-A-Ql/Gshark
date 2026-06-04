# PCAP 分析与网络取证技术参考

> 基于 meow~traffic 项目的 tshark 集成和 PCAP 分析功能，整理的相关技术资料。

## 1. tshark 高级用法

### 官方文档

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **tshark(1) 手册页** | [wireshark.org](https://www.wireshark.org/docs/man-pages/tshark.html) | 官方 CLI 参考。328K+ 字段显示过滤器参考。 | **核心** — tshark CLI 基础 |
| **wireshark-filter(4) 语法** | [wireshark.org](https://www.wireshark.org/docs/man-pages/wireshark-filter.html) | 显示过滤器语法规范。 | **高** — 过滤器语法参考 |
| **Wireshark 用户指南** | [wireshark.org](https://www.wireshark.org/docs/wsug_html_chunked/) | 完整用户指南，涵盖捕获、分析、统计。 | **高** — 综合参考 |

### 性能优化

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **大文件处理** | 多个来源 | 内存无限增长 → 使用 `-M N` 会话重置、`editcap` 分割（1-2 GiB 块）、或 `tcpdump` 简单过滤。tshark 在 100GB 文件上会崩溃。 | **高** — 大 PCAP 处理策略 |
| **两遍模式** | 官方文档 | `-2` 标志用于准确过滤（2 倍慢）。 | **中** — 过滤准确性 vs 速度权衡 |
| **基准测试** | 社区 | 替代方案：packetbeat, dnsmonster, Suricata, Snort。 | **中** — 性能比较参考 |

### Lua 脚本

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **Wireshark Lua API** | [wireshark.org](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html) | `Proto`/`ProtoField`/`DissectorTable`/`Listener` API。启发式解析器、后解析器。 | **高** — 自定义协议解析器开发 |
| **Lua 解析器示例** | [GitHub 多个仓库](https://github.com/topics/wireshark-lua-dissector) | 社区维护的 Lua 解析器集合。 | **中** — 协议解析器参考实现 |
| **Lua 解析器教程** | [mika-s.github.io](https://mika-s.github.io/wireshark/lua/dissector/usb/2019/07/23/creating-a-wireshark-usb-dissector-in-lua-1.html) | 编写 Wireshark USB 解析器的 Lua 教程。 | **中** — USB 协议解析器开发 |

### 速查表

| 资源 | URL | 摘要 |
|------|-----|------|
| **NetworkProGuide PDF** | [networkproguide.com](https://www.networkproguide.com/wireshark-cheat-sheet/) | Wireshark/tshark 命令速查表 |
| **StationX 速查表** | [stationx.net](https://www.stationx.net/wireshark-cheat-sheet/) | 过滤器语法、统计命令、协议分析 |

---

## 2. TCP 流重组

### GoPacket reassembly 包

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **GoPacket reassembly** | [github.com/google/gopacket](https://github.com/google/gopacket/tree/master/reassembly) | Go 的 TCP 流重组库。`Assembler` → `StreamPool` → `Stream` 接口（`Accept`, `ReassembledSG`, `ReassemblyComplete`）。处理乱序包、重传、重叠段。 | **高** — Go TCP 流重组参考实现 |
| **reassemblydump 示例** | [GitHub](https://github.com/google/gopacket/blob/master/examples/reassemblydump/main.go) | HTTP + DNS + TCP FSM 的完整工作示例。 | **高** — 流重组工作示例 |
| **httpassembly 示例** | [GitHub](https://github.com/google/gopacket/tree/master/reassembly/httpassembly) | 更简单的 HTTP 专用流重组。 | **中** — HTTP 流重组简化示例 |

### 关键模式

```go
// 内存管理：防止内存泄漏
assembler.FlushCloseOlderThan(time.Now().Add(-timeout))

// 中流捕获支持
SupportMissingEstablishment: true

// 散射聚合处理
func (s *MyStream) ReassembledSG(sg reassembly.ScatterGather, ...) {
    data := sg.Fetch(length)  // 获取重组数据
    // 处理数据...
}
```

### tshark 流重组

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **tshark 流重组选项** | 官方文档 | `-z "follow,tcp,ascii,N"` 跟踪 TCP 流。`tcp.reassembled` 过滤器。 | **高** — tshark 流重组命令 |
| **Wireshark 流重组设置** | [wireshark.org](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvReassemblySection.html) | TCP/UDP/HTTP 流重组配置。 | **中** — 重组设置参考 |

---

## 3. 网络取证方法论

### SANS/GIAC 参考

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **FOR572 课程** | [sans.org](https://www.sans.org/courses/advanced-network-forensics/) | SANS 高级网络取证课程。PCAP 分析、协议分析、时间线重建。 | **高** — 网络取证权威课程 |
| **GNFA 认证** | [sans.org](https://www.giac.org/certifications/network-forensic-analyst-gnfa/) | GIAC 网络取证分析师认证目标。 | **高** — 认证知识体系 |
| **PCAP 威胁狩猎** | [sans.org](https://www.sans.org/white-papers/) | SANS 白皮书：PCAP 威胁狩猎方法论。 | **高** — 威胁狩猎实践 |

### 取证工作流

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **7 步取证流程** | 多个来源 | 识别 → 保存 → 收集 → 检查 → 分析 → 呈现 → 响应。证据链、证据哈希。 | **高** — 标准取证流程 |
| **实用工作流** | 社区博客 | `tshark -q -z io,phs` → DNS 隧道检测 → SMB 重建 → Foremost 雕刻 → 时间线 CSV。 | **高** — 实用分析工作流 |
| **时间线分析** | [SANS](https://www.sans.org/blog/network-forensics-timeline-analysis/) | 网络取证时间线分析方法。将 PCAP 事件与其他取证数据关联。 | **高** — 时间线重建方法 |

### 证据处理

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **证据链** | [nist.gov](https://www.nist.gov/) | NIST 数字取证标准。证据完整性、哈希验证、时间戳同步。 | **高** — 证据处理标准 |
| **PCAP 完整性** | 社区 | SHA-256 哈希、捕获时间验证、数据包计数校验。 | **高** — PCAP 证据完整性验证 |

---

## 4. 协议特定分析

### DNS 隧道检测

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **Unit 42 DNS 隧道活动** | [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/) | Cobalt Strike、RussianSite、8NS、NSfinder 等 DNS 隧道活动。 | **高** — 真实 DNS 隧道案例 |
| **DoH 检测** | [学术论文](https://arxiv.org/) | 基于 ML 的 DoH 检测，F1=0.9905。 | **高** — 加密 DNS 检测方法 |
| **加密 DNS 比较** | 社区 | DoT/DoH/DoQ 检测从内容 → 元数据 → 行为的转变。 | **中** — 加密 DNS 检测策略 |

### TLS 指纹

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **JA3 → JA4 过渡** | [github.com/FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4) | 现代 TLS 指纹方法。比 JA3 更抗混淆。 | **高** — 现代 TLS 指纹 |
| **爆发分布指纹** | [学术论文](https://arxiv.org/) | 抗混淆的 TLS 指纹方法。 | **中** — 高级 TLS 指纹技术 |
| **ECHidna 恶意软件** | [安全研究](https://www.secureworks.com/) | 使用 DoH + ECH 规避的恶意软件。 | **中** — TLS 规避技术案例 |

### HTTP/2 C2

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **SETTINGS 帧分析** | [安全研究](https://www.ndss-symposium.org/) | HTTP/2 SETTINGS 帧用于 C2 检测。 | **中** — HTTP/2 C2 检测 |
| **QUIC 传输参数指纹** | [学术论文](https://arxiv.org/) | QUIC 传输参数用于设备指纹。 | **中** — QUIC 指纹技术 |

---

## 5. PCAP 操作工具

### Wireshark CLI 工具

| 工具 | 用途 | 关键选项 |
|------|------|----------|
| **editcap** | 格式/时间/分割/去重 | `-F pcapng`, `-i interval`, `-c packets`, `-d` 去重 |
| **mergecap** | 合并多个 PCAP | `-w output`, `-a` 追加模式 |
| **reordercap** | 按时间戳重排序 | `-w output` |
| **text2pcap** | 文本转 PCAP | `-q` 静默, `-T port,port` |
| **capinfos** | PCAP 统计信息 | `-M` 最小信息, `-a` 全部信息 |

### tcpreplay 套件

| 工具 | 用途 | 关键选项 |
|------|------|----------|
| **tcpreplay** | 重放 PCAP | `--pps=N`, `--mbps=N`, `--topspeed` |
| **tcprewrite** | L2/L3/L4 头重写 | `--enet-dmac`, `--endpoints`, `--portmap` |
| **tcpprep** | 客户端/服务器分割 | `--auto=first`, `--cidr=...` |

### Scapy

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **Scapy 官方** | [scapy.net](https://scapy.net/) | Python 数据包伪造/捕获。12K+★。替代 85% 的 nmap。 | **高** — 数据包操作参考 |
| **Scapy 文档** | [scapy.readthedocs.io](https://scapy.readthedocs.io/) | 完整 API 文档。协议层、数据包构建、发送/接收。 | **高** — Scapy API 参考 |

---

## 6. 关键实现要点

### 内存管理

```bash
# 大文件处理：使用 -M N 会话重置
tshark -r large.pcap -M 1000

# 分割大文件
editcap -c 100000 large.pcap split.pcap

# 使用 tcpdump 预过滤
tcpdump -r large.pcap -w filtered.pcap 'port 80'
```

### 两遍模式

```bash
# 两遍模式用于准确过滤（2 倍慢）
tshark -2 -r input.pcap -Y "http.request" -w output.pcap
```

### 流跟踪

```bash
# 跟踪 TCP 流
tshark -r input.pcap -z "follow,tcp,ascii,0"

# HTTP 请求/响应统计
tshark -r input.pcap -q -z "http,tree"
```

### 过滤器验证

```bash
# tshark 非零退出码表示无效过滤器
if ! tshark -r input.pcap -Y "invalid.filter" 2>/dev/null; then
    echo "Invalid filter"
fi
```

### Lua 自定义解析器

```lua
-- 加载自定义解析器
-- tshark -X lua_script:my_dissector.lua -r input.pcap

local my_proto = Proto("myproto", "My Custom Protocol")
my_proto.fields.message = ProtoField.string("myproto.message", "Message")

function my_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "MYPROTO"
    local subtree = tree:add(my_proto, buffer())
    subtree:add(my_proto.fields.message, buffer():string())
end

-- 注册到 TCP 端口
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(12345, my_proto)
```
