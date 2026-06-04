# 功能缺失修补计划

## TL;DR

> **Quick Summary**: 依据知识文档审计发现的 4 CRITICAL + 12 HIGH + 10 MEDIUM 缺失，制定分 4 个阶段的修补计划。
> 
> **Deliverables**:
> - JA3/JA3S TLS 指纹提取和匹配
> - MITRE ATT&CK 技术 ID 映射
> - DNS 隧道/DGA 检测
> - 社区 YARA 规则集成
> - China Chopper/reGeorg 流量解码器
> - DNP3/IEC104 协议解析
> - Malleable C2 配置正向匹配
> - Behinder v2.0 密钥协商检测
> - 数据外泄检测
> - 暴力破解检测
> - 威胁狩猎剧本系统
> 
> **Estimated Effort**: 15-20 天
> **Parallel Execution**: YES - 4 waves

---

## Context

### 审计来源
- `docs/audit-development-report-archive-2026-06-03/feature-gap-analysis-2026-06-03.md`
- `docs/knowledge/c2-traffic-analysis-reference.md`
- `docs/knowledge/behinder-webshell-reference.md`
- `docs/knowledge/yara-threat-hunting-reference.md`
- `docs/knowledge/industrial-vehicle-protocol-reference.md`
- `docs/knowledge/pcap-network-forensics-reference.md`
- `docs/knowledge/usb-media-forensics-reference.md`

### 缺失统计
| 严重度 | 数量 |
|--------|------|
| 🔴 CRITICAL | 4 |
| 🟠 HIGH | 12 |
| 🟡 MEDIUM | 10 |

---

## Work Objectives

### Core Objective
依据知识文档审计发现，补齐项目缺失的关键检测和分析能力。

### Must Have
- 所有新增功能必须有对应测试
- 所有新增功能必须有前端 UI 展示
- 所有新增功能必须与现有证据聚合系统集成

### Must NOT Have
- 不修改现有已通过的测试
- 不引入新的编译错误
- 不破坏现有架构边界

---

## Verification Strategy

### Test Decision
- **Infrastructure exists**: YES
- **Automated tests**: Tests-after
- **Framework**: Go test (backend), Vitest (frontend)

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (P0 — CRITICAL 缺失):
├── Task 1: JA3/JA3S TLS 指纹提取和匹配 [deep]
├── Task 2: MITRE ATT&CK 技术 ID 映射 [deep]
├── Task 3: DNS 隧道检测 [unspecified-high]
└── Task 4: DGA 域名检测 [unspecified-high]

Wave 2 (P1 — HIGH 缺失，WebShell):
├── Task 5: China Chopper 流量解码器 [unspecified-high]
├── Task 6: reGeorg 隧道解码器 [unspecified-high]
├── Task 7: 社区 YARA 规则集成 [quick]
└── Task 8: YARA 性能优化 [quick]

Wave 3 (P1 — HIGH 缺失，协议/检测):
├── Task 9: DNP3 协议解析 [deep]
├── Task 10: IEC 60870-5-104 协议解析 [deep]
├── Task 11: Malleable C2 配置正向匹配 [unspecified-high]
├── Task 12: Behinder v2.0 密钥协商检测 [unspecified-high]
├── Task 13: 数据外泄检测 [unspecified-high]
└── Task 14: 暴力破解检测 [unspecified-high]

Wave 4 (P2 — MEDIUM 缺失):
├── Task 15: 统一 WebShell 家族/版本分类 [unspecified-high]
├── Task 16: CS sleep time / jitter 分析 [quick]
├── Task 17: Behinder UA/Accept 头指纹 [quick]
├── Task 18: RTP 流提取 [unspecified-high]
├── Task 19: 威胁狩猎剧本系统 [deep]
├── Task 20: IOC 源集成 [unspecified-high]
└── Task 21: 规则更新机制 [unspecified-high]

Wave FINAL (After ALL tasks):
├── Task F1: Plan compliance audit (oracle)
├── Task F2: Code quality review (unspecified-high)
├── Task F3: Real manual QA (unspecified-high)
└── Task F4: Scope fidelity check (deep)
-> Present results -> Get explicit user okay
```

### Dependency Matrix

| Task | Depends On | Blocks |
|------|-----------|--------|
| 1 | - | 11, 15 |
| 2 | - | 15, 19 |
| 3 | - | 13 |
| 4 | - | 13 |
| 5 | - | 15 |
| 6 | - | 15 |
| 7 | - | 8 |
| 8 | 7 | - |
| 9 | - | 15 |
| 10 | - | 15 |
| 11 | 1 | 15 |
| 12 | - | 15 |
| 13 | 3, 4 | - |
| 14 | - | - |
| 15 | 1, 2, 5, 6, 9, 10, 11, 12 | - |
| 16 | - | - |
| 17 | - | - |
| 18 | - | - |
| 19 | 2 | - |
| 20 | - | 19 |
| 21 | - | - |

---

## TODOs

- [x] 1. JA3/JA3S TLS 指纹提取和匹配

  **What to do**:
  - 从 tshark 输出中提取 `tls.handshake.ja3` 和 `tls.handshake.ja3s` 字段
  - 在 `model` 包中添加 `TLSFingerprint` 结构体（ja3_hash, ja3s_hash, ja3_raw, ja3s_raw）
  - 在 `Packet` 结构体中添加 `TLSFingerprint` 字段
  - 实现 JA3 哈希匹配逻辑（已知 CS JA3: `72a589da586844d7f0818ce684948eea`）
  - 在前端展示 TLS 指纹信息
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `deep`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: Tasks 11, 15
  - **Blocked By**: None

  **References**:
  - `docs/knowledge/c2-traffic-analysis-reference.md` §2 — JA3/JA3S 技术参考
  - `backend/internal/model/types_packet.go` — Packet 结构体定义
  - `backend/internal/engine/tool_c2.go` — C2 分析引擎

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] Packet 结构体包含 TLSFingerprint 字段
  - [ ] 前端能展示 JA3/JA3S 哈希

  **Commit**: YES
  - Message: `feat(c2): add JA3/JA3S TLS fingerprint extraction and matching`

- [x] 2. MITRE ATT&CK 技术 ID 映射

  **What to do**:
  - 在 `ThreatHit` 结构体中添加 `TechniqueIDs []string` 和 `TacticIDs []string` 字段
  - 在 `EvidenceRecord` 结构体中添加 `TechniqueIDs []string` 字段
  - 创建 MITRE ATT&CK 映射表（规则 → 技术 ID）
  - 为现有检测规则添加 ATT&CK 技术标签
  - 在前端展示 ATT&CK 技术信息
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `deep`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: Tasks 15, 19
  - **Blocked By**: None

  **References**:
  - `docs/knowledge/yara-threat-hunting-reference.md` §2 — MITRE ATT&CK 方法论
  - `backend/internal/model/types_packet.go:66-74` — ThreatHit 结构体
  - `backend/internal/model/types_evidence.go` — EvidenceRecord 结构体

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] ThreatHit 包含 TechniqueIDs 字段
  - [ ] EvidenceRecord 包含 TechniqueIDs 字段
  - [ ] 前端能展示 ATT&CK 技术标签

  **Commit**: YES
  - Message: `feat(detection): add MITRE ATT&CK technique ID mapping`

- [x] 3. DNS 隧道检测

  **What to do**:
  - 实现 DNS 查询频率分析（高频子域名查询）
  - 实现 DNS 查询长度异常检测（长子域名）
  - 实现 DNS 编码模式检测（Base64/Hex 编码的子域名）
  - 在 `ThreatHit` 中添加 DNS 隧道相关分类
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: Task 13
  - **Blocked By**: None

  **References**:
  - `docs/knowledge/pcap-network-forensics-reference.md` §4 — DNS 隧道检测
  - `backend/internal/engine/threat_hunt_stream.go` — 威胁狩猎引擎

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] 能检测 DNS 隧道流量

  **Commit**: YES
  - Message: `feat(detection): add DNS tunneling detection`

- [x] 4. DGA 域名检测

  **What to do**:
  - 实现域名熵值计算
  - 实现域名长度异常检测
  - 实现域名字符分布异常检测
  - 在 `ThreatHit` 中添加 DGA 相关分类
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1
  - **Blocks**: Task 13
  - **Blocked By**: None

  **References**:
  - `docs/knowledge/pcap-network-forensics-reference.md` §4 — DGA 检测

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] 能检测 DGA 域名

  **Commit**: YES
  - Message: `feat(detection): add DGA domain detection`

- [x] 5. China Chopper 流量解码器

  **What to do**:
  - 在 `DecodeStreamPayload` switch 中添加 `china_chopper` case
  - 实现 China Chopper payload 解码（`@eval($_POST[...])` 模式）
  - 实现 China Chopper 参数提取（密码、命令）
  - 在 `stream_payload_inspector.go` 中添加 China Chopper 特征检测
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2
  - **Blocks**: Task 15
  - **Blocked By**: None

  **References**:
  - `docs/knowledge/webshell_management_tools_analysis.md` — China Chopper 技术分析
  - `backend/internal/engine/stream_decoder.go:41-53` — DecodeStreamPayload switch
  - `backend/rules/yara/traffic_cve_webshell.yar:356-371` — China Chopper YARA 规则

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] 能解码 China Chopper 流量

  **Commit**: YES
  - Message: `feat(webshell): add China Chopper stream decoder`

- [x] 6. reGeorg 隧道解码器

  **What to do**:
  - 在 `DecodeStreamPayload` switch 中添加 `regeorg` case
  - 实现 reGeorg 隧道解码（`X-CMD`/`X-TARGET` 头模式）
  - 在 `stream_payload_inspector.go` 中添加 reGeorg 特征检测
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2
  - **Blocks**: Task 15
  - **Blocked By**: None

  **References**:
  - `docs/knowledge/webshell_management_tools_analysis.md` — reGeorg 技术分析
  - `backend/rules/yara/traffic_cve_webshell.yar:428-445` — reGeorg YARA 规则

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] 能解码 reGeorg 隧道流量

  **Commit**: YES
  - Message: `feat(webshell): add reGeorg tunnel decoder`

- [x] 7. 社区 YARA 规则集成

  **What to do**:
  - 下载 Neo23x0/signature-base 规则集
  - 添加规则下载和缓存机制
  - 实现规则启用/禁用配置
  - 在 `embed.go` 中添加社区规则支持
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2
  - **Blocks**: Task 8
  - **Blocked By**: None

  **References**:
  - `docs/knowledge/yara-threat-hunting-reference.md` §5 — 社区 YARA 规则
  - `backend/rules/yara/embed.go` — 规则嵌入

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] 社区规则可用

  **Commit**: YES
  - Message: `feat(yara): integrate community YARA rules (Neo23x0/signature-base)`

- [x] 8. YARA 性能优化

  **What to do**:
  - 为现有规则添加 `filesize` 预检查
  - 优化规则条件排序（廉价检查在前）
  - 考虑使用 Go YARA 绑定（`hillu/go-yara`）替代 CLI 调用
  - 添加规则编译缓存（`.yarc`）
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 2 (after Task 7)
  - **Blocks**: None
  - **Blocked By**: Task 7

  **References**:
  - `docs/knowledge/yara-threat-hunting-reference.md` §1 — YARA 性能最佳实践
  - `backend/internal/engine/yara_batch.go` — YARA 批量扫描

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] YARA 扫描性能提升

  **Commit**: YES
  - Message: `perf(yara): optimize YARA scanning performance`

- [x] 9. DNP3 协议解析

  **What to do**：
  - 实现 DNP3 协议解析器（Function Code、Data Object 解析）
  - 实现 DNP3 异常检测（未授权功能码、异常响应）
  - 在 `model` 包中添加 `DNP3Analysis` 结构体
  - 在前端展示 DNP3 分析结果
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `deep`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 3
  - **Blocks**: Task 15
  - **Blocked By**: None

  **References**:
  - `docs/knowledge/industrial-vehicle-protocol-reference.md` §1 — DNP3 安全分析
  - `backend/internal/engine/analysis_report_industrial_vehicle.go` — 工业协议报告

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] 能解析 DNP3 协议

  **Commit**: YES
  - Message: `feat(protocol): add DNP3 protocol parser`

- [x] 10. IEC 60870-5-104 协议解析

  **What to do**:
  - 实现 IEC 104 协议解析器（ASDU 类型、Cause of Transmission 解析）
  - 实现 IEC 104 异常检测
  - 在 `model` 包中添加 `IEC104Analysis` 结构体
  - 在前端展示 IEC 104 分析结果
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `deep`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 3
  - **Blocks**: Task 15
  - **Blocked By**: None

  **References**:
  - `docs/knowledge/industrial-vehicle-protocol-reference.md` §1 — IEC 104 分析

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] 能解析 IEC 104 协议

  **Commit**: YES
  - Message: `feat(protocol): add IEC 60870-5-104 protocol parser`

- [x] 11. Malleable C2 配置正向匹配

  **What to do**:
  - 创建已知 Malleable C2 配置数据库（默认 URI、头部变换、编码模式）
  - 实现正向匹配逻辑（不仅仅是弱信号评分）
  - 在 `C2FamilyAnalysis` 中添加 `MalleableProfileMatch` 字段
  - 在前端展示匹配的配置文件
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 3
  - **Blocks**: Task 15
  - **Blocked By**: Task 1

  **References**:
  - `docs/knowledge/c2-traffic-analysis-reference.md` §2 — Malleable C2 配置
  - `backend/internal/engine/tool_c2.go:193` — 当前弱信号评分

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] 能正向匹配已知 Malleable C2 配置

  **Commit**: YES
  - Message: `feat(c2): add Malleable C2 profile positive matching`

- [x] 12. Behinder v2.0 密钥协商检测

  **What to do**:
  - 实现两阶段 GET 握手模式检测（`pass=<digits>` → 16 字符十六进制响应）
  - 实现 Session 密钥关联
  - 在 `stream_payload_inspector.go` 中添加 Behinder v2.0 特征
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 3
  - **Blocks**: Task 15
  - **Blocked By**: None

  **References**:
  - `docs/knowledge/behinder-webshell-reference.md` §2.2 — V2.0 动态密钥协商
  - `backend/internal/engine/stream_payload_inspector.go` — Payload 指纹

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] 能检测 Behinder v2.0 密钥协商

  **Commit**: YES
  - Message: `feat(webshell): add Behinder v2.0 key negotiation detection`

- [x] 13. 数据外泄检测

  **What to do**:
  - 实现大文件传输检测（异常大的 HTTP POST/PUT）
  - 实现已知外泄服务域名匹配（Mega、Pastebin、Dropbox 等）
  - 实现 DNS 外泄检测（长 DNS 查询）
  - 在 `ThreatHit` 中添加数据外泄分类
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 3
  - **Blocks**: None
  - **Blocked By**: Tasks 3, 4

  **References**:
  - `docs/knowledge/c2-traffic-analysis-reference.md` — 数据外泄检测

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] 能检测数据外泄行为

  **Commit**: YES
  - Message: `feat(detection): add data exfiltration detection`

- [x] 14. 暴力破解检测

  **What to do**:
  - 实现登录失败阈值检测（同一 IP 短时间内多次失败）
  - 实现凭据填充检测（多个 IP 尝试同一帐户）
  - 实现 HTTP 401/403 异常检测
  - 在 `ThreatHit` 中添加暴力破解分类
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 3
  - **Blocks**: None
  - **Blocked By**: None

  **References**:
  - `backend/internal/engine/analysis.go:79` — findAnomaly404403（现有异常检测）

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] 能检测暴力破解行为

  **Commit**: YES
  - Message: `feat(detection): add brute force detection`

- [x] 15. 统一 WebShell 家族/版本分类

  **What to do**:
  - 实现跨候选的家族聚合逻辑
  - 添加家族置信度排名
  - 实现版本识别（如 Behinder v2.0 vs v3.0 vs v4.0）
  - 在前端展示统一的"检测到工具: X, 版本: Y, 置信度: Z"
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 4 (after Tasks 1,2,5,6,9,10,11,12)
  - **Blocks**: None
  - **Blocked By**: Tasks 1, 2, 5, 6, 9, 10, 11, 12

  **References**:
  - `backend/internal/engine/stream_payload_sources.go` — 信号聚合
  - `backend/internal/model/types_packet.go` — FamilyHint 字段

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] 前端展示统一的家族分类结果

  **Commit**: YES
  - Message: `feat(detection): add unified WebShell family/version classification`

- [x] 16. CS sleep time / jitter 分析

  **What to do**：
  - 从 beacon 间隔中提取 sleep time 估计值
  - 实现 jitter 百分比计算
  - 在 `C2BeaconPattern` 中添加 `SleepTime` 和 `Jitter` 字段
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4
  - **Blocks**: None
  - **Blocked By**: None

  **References**:
  - `backend/internal/engine/tool_c2.go:685-718` — beacon 间隔检测

  **Acceptance Criteria**：
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] 能提取 sleep time 和 jitter

  **Commit**: YES
  - Message: `feat(c2): add CS sleep time and jitter analysis`

- [x] 17. Behinder UA/Accept 头指纹

  **What to do**:
  - 实现 Behinder 特定 UA 检测（`Java/1.8.0_211` 等）
  - 实现 Behinder Accept 头检测
  - 在 `stream_payload_inspector.go` 中添加 HTTP 头指纹
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4
  - **Blocks**: None
  - **Blocked By**: None

  **References**：
  - `docs/knowledge/behinder-webshell-reference.md` §3 — 各版本流量特征

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] 能检测 Behinder HTTP 头指纹

  **Commit**: YES
  - Message: `feat(webshell): add Behinder UA/Accept header fingerprinting`

- [x] 18. RTP 流提取

  **What to do**:
  - 实现 RTP 流提取（基于 SSRC 分离）
  - 实现 RTP 编解码器识别
  - 实现 RTP 统计信息（丢包、抖动、乱序）
  - 在前端展示 RTP 流信息
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4
  - **Blocks**: None
  - **Blocked By**: None

  **References**:
  - `docs/knowledge/usb-media-forensics-reference.md` §5 — RTP/VoIP 分析
  - `backend/internal/engine/service_analysis.go:232` — RTP 端口检测

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] 能提取 RTP 流

  **Commit**: YES
  - Message: `feat(media): add RTP stream extraction`

- [x] 19. 威胁狩猎剧本系统

  **What to do**：
  - 设计剧本模型（YAML/JSON 模板）
  - 实现剧本执行引擎
  - 实现保存搜索功能
  - 实现假设跟踪
  - 在前端添加剧本管理 UI
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `deep`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4
  - **Blocks**: None
  - **Blocked By**: Task 2

  **References**:
  - `docs/knowledge/yara-threat-hunting-reference.md` §2 — 威胁狩猎框架
  - `frontend/src/app/features/hunting/` — 威胁狩猎 UI

  **Acceptance Criteria**：
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] 前端能管理狩猎剧本

  **Commit**: YES
  - Message: `feat(hunting): add threat hunting playbook system`

- [x] 20. IOC 源集成

  **What to do**:
  - 实现 IOC 源导入接口（STIX/CSV/JSON）
  - 实现 IOC 匹配引擎（IP/域名/哈希/URL）
  - 实现 VirusTotal/AbuseIPDB 集成（可选，需 API key）
  - 在前端展示 IOC 匹配结果
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4
  - **Blocks**: Task 19
  - **Blocked By**: None

  **References**:
  - `docs/knowledge/yara-threat-hunting-reference.md` §5 — IOC 源

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] 能导入和匹配 IOC

  **Commit**: YES
  - Message: `feat(hunting): add IOC feed integration`

- [x] 21. 规则更新机制

  **What to do**：
  - 实现规则版本管理
  - 实现规则下载和缓存
  - 实现规则启用/禁用配置
  - 在前端添加规则管理 UI
  - 添加测试用例

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4
  - **Blocks**: None
  - **Blocked By**: None

  **References**:
  - `docs/knowledge/yara-threat-hunting-reference.md` §5 — 规则管理

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] 前端能管理规则

  **Commit**: YES
  - Message: `feat(yara): add rule update mechanism`

---

## Final Verification Wave

- [x] F1. **Plan Compliance Audit** — `oracle`
- [x] F2. **Code Quality Review** — `unspecified-high`
- [x] F3. **Real Manual QA** — `unspecified-high`
- [x] F4. **Scope Fidelity Check** — `deep`

---

## Commit Strategy

| Task | Commit Message |
|------|---------------|
| 1 | `feat(c2): add JA3/JA3S TLS fingerprint extraction and matching` |
| 2 | `feat(detection): add MITRE ATT&CK technique ID mapping` |
| 3 | `feat(detection): add DNS tunneling detection` |
| 4 | `feat(detection): add DGA domain detection` |
| 5 | `feat(webshell): add China Chopper stream decoder` |
| 6 | `feat(webshell): add reGeorg tunnel decoder` |
| 7 | `feat(yara): integrate community YARA rules` |
| 8 | `perf(yara): optimize YARA scanning performance` |
| 9 | `feat(protocol): add DNP3 protocol parser` |
| 10 | `feat(protocol): add IEC 60870-5-104 protocol parser` |
| 11 | `feat(c2): add Malleable C2 profile positive matching` |
| 12 | `feat(webshell): add Behinder v2.0 key negotiation detection` |
| 13 | `feat(detection): add data exfiltration detection` |
| 14 | `feat(detection): add brute force detection` |
| 15 | `feat(detection): add unified WebShell family/version classification` |
| 16 | `feat(c2): add CS sleep time and jitter analysis` |
| 17 | `feat(webshell): add Behinder UA/Accept header fingerprinting` |
| 18 | `feat(media): add RTP stream extraction` |
| 19 | `feat(hunting): add threat hunting playbook system` |
| 20 | `feat(hunting): add IOC feed integration` |
| 21 | `feat(yara): add rule update mechanism` |

---

## Success Criteria

### Verification Commands
```bash
cd backend && go test ./...         # Expected: all packages PASS
cd backend && go vet ./...          # Expected: PASS
cd frontend && pnpm run typecheck   # Expected: PASS
cd frontend && pnpm run test:run    # Expected: all suites PASS
```

### Final Checklist
- [x] 所有 CRITICAL 缺失已修补
- [x] 所有 HIGH 缺失已修补
- [x] 所有新增功能有测试覆盖
- [x] 所有新增功能有前端 UI 展示
- [x] 所有新增功能与证据聚合系统集成
