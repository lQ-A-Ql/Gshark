# PCAP Analysis, tshark, and Network Forensics — Knowledge Base

> Curated 2026-06-03. Covers tshark advanced usage, TCP stream reassembly, network forensics methodology, protocol-specific analysis, and PCAP manipulation tools.
> Relevance: meow~traffic uses tshark as its parsing core with TCP/UDP/HTTP stream reassembly, display filters, and protocol-specific decoders.

---

## 1. tshark Advanced Usage

### 1.1 Official Documentation

| Title | URL | Summary |
|-------|-----|---------|
| **tshark(1) Man Page** | https://www.wireshark.org/docs/man-pages/tshark | Complete reference for all tshark CLI options: -r (read), -Y (display filter), -T fields (field extraction), -e (specific fields), -2 (two-pass analysis), -X lua_script: (Lua extension), -q -z (statistics). Critical for backend integration. |
| **Display Filter Reference (328K+ fields)** | https://www.wireshark.org/docs/dfref/ | Exhaustive index of every filterable protocol field across 3000+ protocols. Use as lookup when building -Y expressions programmatically. |
| **wireshark-filter(4) — Display Filter Syntax** | https://www.wireshark.org/docs/man-pages/wireshark-filter.html | Formal grammar for display filters: comparison operators (eq, ne, gt, lt, contains, matches), logical operators (and, or, not), slice operator, membership operator (in {}), field references. |
| **Building Display Filter Expressions (User Guide)** | https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html | Official guide with examples for combining expressions, field types, the @ layer operator (Wireshark 4.0+), and the membership operator. |
| **Wireshark Performance Wiki** | https://wiki.wireshark.org/performance | Tips for large capture files: disable coloring rules, disable DNS lookups, increase capture buffer, use snap length, prefer capture filters over display filters. |

### 1.2 tshark Performance and Large File Handling

| Title | URL | Summary |
|-------|-----|---------|
| **Running tshark on large pcap files (Wireshark mailing list)** | https://seclists.org/wireshark/2013/Jun/49 | tshark keeps TCP session state in memory, grows until swap. Workarounds: use editcap to split into 1-2 GiB chunks, or use tcpdump for simple port filtering (no state). |
| **tshark memory usage increasing (StackOverflow)** | https://stackoverflow.com/questions/62676968/why-is-tshark-memory-usage-increasing | Use -M (session reset) to truncate internal state: tshark -r file.pcap -M 100000. Also use -b files:N ring buffer to auto-discard state on file rotation. |
| **Reading Large PCAP in Smaller Parts** | https://stackoverflow.com/questions/60579326/reading-large-pcap-with-tshark-in-smaller-parts | For 9GB+ files: use tcpdump -r file -w output -C 2250 to split by size, or editcap for time-based splitting. tshark -Y with frame.time still scans all packets. |
| **Parsing massive DNS PCAP efficiently** | https://blog.n0p.me/2020/08/2020-08-15-analysing-big-pcap/ | Benchmark: tshark dies on 20min capture (~100GB). Alternatives: packetbeat (2x faster, 0.3% RAM), dnsmonster (streaming), Suricata (100% CPU, 22% RAM), Snort (380s, 5% RAM). For huge captures: index with Moloch/Arkime + Clickhouse. |

### 1.3 Lua Scripting for tshark

| Title | URL | Summary |
|-------|-----|---------|
| **Chapter 12: Lua Support in Wireshark** | https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html | Official guide: Lua 5.3/5.4 support, plugin loading order (ASCIIbetical), -X lua_script:file.lua CLI option, init.lua package system. Lua dissectors register after compiled dissectors. |
| **Chapter 13: Lua API Reference** | https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html | Full API: Proto, ProtoField, DissectorTable, Listener (post-dissector taps), TreeItem, Tvb, Pinfo. Key functions: register_postdissector(), dissect_tcp_pdus(), DissectorTable.get(). |
| **13.3: Functions for New Protocols/Dissectors** | https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto | How to create Proto objects, register heuristic dissectors, hook into dissector tables (tcp.port, udp.port), and implement proto.dissector(tvb, pinfo, tree). |
| **12.3: Lua Dissector Example** | https://www.wireshark.org/docs/wsdg_html_chunked/wslua_dissector_example.html | Complete working example: multi-protocol dissector that switches sub-dissector based on first byte, registers in wtap_encap and udp.port tables. |
| **13.8: Post-Dissection Analysis (Listeners)** | https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Listener.html | Listener.new(tap, filter) for packet taps. listener.packet(pinfo, tvb, tapinfo) called per matching packet. Useful for statistics collection without modifying the dissection tree. |
| **filtcols — Filterable Protocol/Info Columns** | https://wiki.wireshark.org/Lua/Examples/filtcols | Post-dissector that makes _ws.col.protocol and _ws.col.info filterable. Shows pinfo.cols usage and the tshark -V / -P requirement for column data in CLI mode. |
| **tshark.dev Lua Scripts** | https://tshark.dev/packetcraft/scripting/lua_scripts/ | Curated list of popular Lua dissectors on GitHub (protobuf, H.264, STOMP, SOME/IP, etc.) and metaprogramming tools (kaitai-to-wireshark, pyreshark). |

### 1.4 Display Filter Cheat Sheets

| Title | URL | Summary |
|-------|-----|---------|
| **Wireshark Display Filters Cheat Sheet (NetworkProGuide)** | https://networkproguide.com/wireshark-display-filters-cheat-sheet/ | Printable PDF + tables organized by protocol (ARP, Ethernet, IP, TCP, HTTP, DNS, etc.) with filter syntax examples. |
| **Wireshark Cheat Sheet (StationX)** | https://www.stationx.net/wireshark-cheat-sheet/ | Operators, filter types, capture vs display filter syntax, common filtering commands (by IP, port, URL, timestamp, flags), keyboard shortcuts. |
| **DisplayFilters Wiki** | https://wiki.wireshark.org/DisplayFilters | Community wiki with protocol-specific filter examples, the matches regex operator, and links to capture filter cheat sheets. |

---

## 2. TCP Stream Reassembly Techniques

### 2.1 GoPacket (Go) — Primary Reference for This Project

| Title | URL | Summary |
|-------|-----|---------|
| **GoPacket reassembly package docs** | https://pkg.go.dev/github.com/google/gopacket/reassembly | Core API: Assembler, StreamPool, Stream interface (Accept, ReassembledSG, ReassemblyComplete), StreamFactory. Handles out-of-order packets, retransmissions, overlapping segments. ScatterGather passes data with metadata (overlap bytes, queued packets). |
| **reassemblydump example** | https://github.com/google/gopacket/blob/master/examples/reassemblydump/main.go | Full working example: TCP reassembly with HTTP parsing, DNS over TCP, TCP FSM validation, option checking, checksum verification. Shows AssemblerContext, TCPSimpleFSM, TCPOptionCheck. |
| **httpassembly example** | https://github.com/google/gopacket/blob/master/examples/httpassembly/main.go | Simpler HTTP-only example: StreamFactory, Stream, tcpreader.ReaderStream, http.ReadRequest(). Shows FlushOlderThan() for periodic cleanup. |
| **Programmatically Analyze PCAPs with GoPacket (Akita)** | https://www.akitasoftware.com/blog-posts/programmatically-analyze-packet-captures-with-gopacket | Tutorial: pcap.OpenLive / pcap.OpenOffline, BPF filters, NewPacketSource, then TCP reassembly with StreamPool + Assembler. Shows the StreamFactory to StreamPool to Assembler architecture. |
| **GoPacket Advanced Features (DeepWiki)** | https://deepwiki.com/google/gopacket/5-advanced-features | Architecture doc: TCP reassembly vs IPv4 defragmentation, DecodingLayerParser for 10x faster decoding, packet serialization, performance optimization (pre-allocated objects). |
| **Go and pcaps tutorial** | https://parsiya.net/blog/2017-12-03-go-and-pcaps/ | Practical Go packet parsing: gopacket.NewPacket, layer extraction, type assertions (*layers.IPv4), BPF filtering, ICMP payload extraction. Good for understanding the layer model. |

### 2.2 TCP Reassembly Concepts

| Title | URL | Summary |
|-------|-----|---------|
| **GoPacket Stream interface** | https://pkg.go.dev/github.com/google/gopacket/reassembly#Stream | Key method: Accept() checks TCP FSM state, options, checksum. ReassembledSG() receives ScatterGather with Info() (dir, start, end, skip), Lengths() (length, saved), Stats() (packets, chunks, queued, overlap). KeepFrom(offset) for partial consumption. |
| **Assembler flush methods** | https://pkg.go.dev/github.com/google/gopacket/reassembly#Assembler | FlushCloseOlderThan(t) flush and close streams idle since time t. FlushWithOptions() for fine-grained control. Critical for memory management in long-running captures. |

---

## 3. Network Forensics Methodologies

### 3.1 SANS/GIAC Resources

| Title | URL | Summary |
|-------|-----|---------|
| **FOR572: Advanced Network Forensics** | https://www.sans.org/cyber-security-courses/advanced-network-forensics-threat-hunting-incident-response | SANS course covering: protocol profiling (HTTP, DNS), NetFlow analysis, file recovery from traffic, protocol reverse engineering, encrypted traffic analysis, scripting for evidence processing. GIAC GNFA certification. |
| **GNFA Certification Objectives** | https://www.giac.org/certifications/network-forensic-analyst-gnfa | Exam domains: common network protocols, encryption/encoding, NetFlow analysis, network architecture, protocol reverse engineering, open-source proxies, security logging, wireless analysis. |
| **Hunting Threats Inside PCAPs (SANS paper)** | https://www.sans.org/white-papers/38440 | Structured PCAP analysis methodology using Bro/Zeek for active threat hunting. Malware must leave network-level traces regardless of system-level evasion. |
| **Forensic Timeline Analysis using Wireshark (GCFA Gold)** | https://www.sans.org/white-papers/36137 | Converting SleuthKit/Log2Timeline timelines to PCAP format for Wireshark analysis. Uses analysis profiles, filtering, colorization, marking, and annotation. |

### 3.2 Methodology Guides

| Title | URL | Summary |
|-------|-----|---------|
| **Network Forensics: Evidence Recovery Guide (Forensic Focus)** | https://www.forensicfocus.com/guides/network-forensics-a-short-guide-to-digital-evidence-recovery-from-computer-networks/ | Comprehensive methodology: collection (FPC, NetFlow, logs), examination (session reconstruction, timeline correlation, anomaly detection), analysis (attack sequence, impact, attribution), presentation. Tool recommendations: Wireshark, tshark, NetworkMiner. |
| **Network Forensics: Data Collection and Preservation (Corelight)** | https://corelight.com/resources/glossary/network-forensics | Evidence sources: full packet capture, network logs, flow records. Collection best practices: secure sensors, document failures, hash evidence, understand best evidence vs derivative evidence, chain of custody. |
| **Logic-Based Network Forensics Model (NIST)** | https://csrc.nist.gov/CSRC/media/Projects/Measuring-Security-Risk-in-Enterprise-Networks/documents/logic_based_network_forensices_model-for_evidence_analysis.pdf | NIST paper: Prolog-based reasoning system using MITRE OVAL database for attack scenario reconstruction. Handles missing/destroyed evidence via anti-forensics database. |

### 3.3 Practical Workflows

| Title | URL | Summary |
|-------|-----|---------|
| **Investigate Network Intrusion from PCAP (Terminal Skills)** | https://terminalskills.io/use-cases/investigate-network-intrusion-from-pcap | Complete workflow: tshark -q -z io,phs (protocol hierarchy), DNS tunneling detection (dns.qry.name length > 60), SMB session reconstruction (--export-objects smb), Foremost file carving, timeline CSV, nmap live check. |

---

## 4. Protocol-Specific Analysis

### 4.1 DNS Tunneling Detection

| Title | URL | Summary |
|-------|-----|---------|
| **Detecting DNS Tunneling Campaigns (Unit 42)** | https://unit42.paloaltonetworks.com/detecting-dns-tunneling-campaigns/ | 4 new campaigns discovered: Cobalt Strike custom DNS beaconing (xds/txt/del prefixes), RussianSite (100+ .site domains, shared aDNS), 8NS (8 NS records per domain), NSfinder (ns500 prefix encoding). Detection: authoritative nameserver correlation, DNS config patterns, payload encoding, domain registration. |
| **MTL-DoHTA: DNS over HTTPS Tunneling Detection** | https://www.mdpi.com/1424-8220/25/4/993 | Multi-task learning framework for DoH traffic classification: (1) DoH vs non-DoH, (2) benign vs malicious, (3) tunneling tool identification (dns2tcp, dnscat2, iodine). 2D-CNN + GradNorm + attention. F1=0.9905. |
| **Encrypted DNS Comparison: Detecting C2 (Active Countermeasures)** | https://www.activecountermeasures.com/malware-of-the-day-encrypted-dns-comparison-detecting-c2-when-you-cant-see-the-queries/ | Plain DNS vs DoT vs DoH vs DoQ comparison. DoT: port 853 visible, SNI leaks domain. DoH: port 443, blends with HTTPS. DoQ: port 853/UDP, QUIC fingerprinting reveals protocol. Detection shifts from content to metadata to behavioral analysis. |

### 4.2 TLS Fingerprinting

| Title | URL | Summary |
|-------|-----|---------|
| **Deep Dive into Traffic Fingerprints (ntop, SharkFest 2024)** | https://www.ntop.org/Sharkfest_EU_2024.pdf | JA3 to JA4 transition (Google randomized extensions in 2023). TLS fingerprinting works even through obfuscation (ShadowSocks, VMess, Trojan) because tunneling does not change packet timing/size. Burst bytes/pkts distribution fingerprint detects obfuscated TLS. FEP (Fully Encrypted Protocols) detected via entropy measurement. |
| **Stealth over TLS: ECH-based C2 (Virus Bulletin)** | https://www.virusbulletin.com/uploads/pdf/conference/vb2025/slides/Slides-Stealth-over-TLS-the-emergence-of-ECH-based-CC-in-ECHidna-malware.pdf | ECHidna malware: DoH + ECH (Encrypted Client Hello) + in-memory DLL. ECH hides hostname; outer SNI = cloudflare-ech.com. Detection: watch for ech= DNS lookups, outer SNI patterns, process tree anomalies. |
| **Shrike: Network Forensics Tool** | https://github.com/fevra-dev/Shrike | Python tool detecting 20+ threat patterns: C2 beaconing, port scans, DNS tunneling, HTTP/2 C2, NTLM relay, WebSocket C2, mTLS C2 (Sliver/Mythic), DNS rebinding, QUIC/HTTP3 C2. MITRE ATT&CK mapping. JA3/JA4/JARM fingerprints. |

### 4.3 HTTP/2 and Modern Protocol Analysis

| Title | URL | Summary |
|-------|-----|---------|
| **HTTP/2 C2 Detection (Shrike)** | https://github.com/fevra-dev/Shrike | http2_c2.py: analyzes SETTINGS frame parameters, ping-based keepalive patterns, stream multiplexing anomalies for covert channel detection. Technique: T1071.001. |
| **QUIC/HTTP3 C2 Detection (Shrike)** | https://github.com/fevra-dev/Shrike | quic_alpn.py + quic_tp.py: transport parameter fingerprinting, ALPN analysis for identifying C2 frameworks using QUIC. Technique: T1095. |

---

## 5. PCAP Manipulation Tools

### 5.1 Wireshark CLI Suite

| Title | URL | Summary |
|-------|-----|---------|
| **editcap(1) Man Page** | https://www.wireshark.org/docs/man-pages/editcap.html | Edit/translate capture files: format conversion (-F), snapshot length (-s), time adjustment (-t), encapsulation type (-T), duplicate removal (-d, -D, -w), packet splitting (-c count, -i interval), secrets injection/extraction, compression. |
| **Wireshark Tools Wiki** | https://wiki.wireshark.org/Tools | Complete tool list: editcap, mergecap, reordercap, text2pcap, capinfos, rawshark, dumpcap. Also lists external tools: Scapy, tcpreplay, NetworkMiner. |
| **Filter, Split, Merge PCAP Files (xmodulo)** | https://www.xmodulo.com/filter-split-merge-pcap-linux.html | Practical tutorials: time-based filtering (-A/-B), packet range extraction, duplicate removal (-D/-w), split by count (-c) or interval (-i), merge with mergecap (-a for append order). |

### 5.2 tcpreplay Suite

| Title | URL | Summary |
|-------|-----|---------|
| **tcpreplay GitHub** | https://github.com/appneta/tcpreplay | Suite: tcpreplay (replay), tcpreplay-edit (replay + modify), tcpliveplay (TCP session replay), tcpprep (client/server split), tcprewrite (header rewriting), tcpbridge (bridge segments). Supports netmap for 10GigE wire-speed. |
| **tcprewrite Man Page** | https://manpages.debian.org/testing/tcpreplay/tcprewrite.1 | Rewrite L2/L3/L4 headers: MAC addresses, VLANs, IPv4/IPv6 addresses (with NAT), ports, TOS/DSCP, TTL. --fixcsum recalculates checksums, --fixlen truncates/pads packets. |

### 5.3 Scapy

| Title | URL | Summary |
|-------|-----|---------|
| **Scapy GitHub (12K+ stars)** | https://github.com/secdev/scapy/ | Python packet manipulation: forge/decode packets, send on wire, capture, match requests/replies. Replaces hping, 85% of nmap, arpspoof, tcpdump, wireshark, p0f. Supports invalid frames, 802.11 injection, VLAN hopping+ARP cache poisoning combinations. |
| **How to Edit PCAP Files (Ostinato)** | https://ostinato.org/guides/how-to-edit-pcap-files | Tool comparison: editcap (format/size/time, no field editing), tcprewrite (L2/L3/L4 field modification with checksum fix), Ostinato (GUI find and replace across protocols), WireEdit (full GUI protocol-aware editor). |

---

## 6. Relevance to meow~traffic

### Direct Applicability

| Area | How It Applies |
|------|----------------|
| **tshark CLI** | meow~traffic uses tshark as its parsing core. -T fields -e for field extraction, -Y for display filters, -q -z for statistics are all used in the backend. |
| **Display Filters** | Frontend passes user-entered filters directly to tshark -Y. The filter reference and cheat sheets are essential for building/discovering available fields. |
| **TCP Reassembly** | GoPacket reassembly package is the primary reference for implementing LoadPCAPWithRun stream reassembly in Go. The Assembler to StreamPool to Stream pattern maps directly. |
| **Lua Dissectors** | Could be used to extend tshark protocol support for custom protocols without modifying tshark source. |
| **Performance** | Large PCAP handling strategies (editcap splitting, -M session reset, streaming alternatives) apply to the capture loading pipeline. |
| **Network Forensics** | The 7-step methodology (identification, preservation, collection, examination, analysis, presentation, response) informs the evidence schema and workflow design. |
| **DNS Tunneling** | Detection patterns (entropy scoring, subdomain length, query frequency) are directly relevant to the threat hunting module. |
| **TLS Fingerprinting** | JA3/JA4/JARM extraction and comparison for C2 detection in the threat hunting and C2 analysis modules. |
| **PCAP Manipulation** | editcap, mergecap, tcprewrite for preprocessing captures before analysis. Scapy for test PCAP generation. |

### Key Takeaways for Implementation

1. **Memory management**: tshark state grows unboundedly. Use -M N session reset or editcap splitting for captures > 2GB.
2. **Two-pass analysis**: -2 flag enables read filter (-R) in first pass + display filter (-Y) in second pass. More accurate but 2x slower.
3. **GoPacket reassembly**: Use FlushCloseOlderThan() periodically to prevent memory leaks. SupportMissingEstablishment: true for mid-stream captures.
4. **Display filter validation**: tshark returns non-zero exit code on invalid filters. Capture this for frontend error reporting.
5. **Field extraction**: -T json or -T jsonraw for structured output. -T fields -e field1 -e field2 for tabular output. -E separator=| for custom delimiters.
6. **Lua in tshark**: -X lua_script:file.lua loads scripts. Scripts can add post-dissectors, custom columns, and heuristic dissectors. Column data requires -V or -P flags in CLI mode.
