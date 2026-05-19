# 日期: 2026-04-30
# 署名: Codex

# C2 样本分析与 APT 组织画像合并摘要

## 一、合并范围

本文件按“C2 / APT 分析能力”方向合并 2026-04-29 C2 样本分析系列报告、APT 组织画像扩展报告，以及本轮 C2/APT 前端冗余清理结论。原始逐轮报告保留在 2026-04-29 归档目录。

## 二、能力定位

- C2 样本分析页负责从抓包中提取 Cobalt Strike、VShell 等 C2 通信候选、通道画像、Beacon/Heartbeat 形态、Host/URI 聚合、DNS 聚合和 Stream 聚合。
- APT 组织画像页负责消费 C2、对象提取、威胁狩猎、认证或投递链证据，形成组织/活动簇层面的解释面板。
- 两个页面均强调“证据链”和“弱信号不要强归因”，避免把端口、路径、单一字符串当成强结论。

## 三、已完成能力

### 1. C2 页面

- 建立 C2 样本分析页骨架，覆盖 CS / VShell 双 tab。
- 完成候选证据表、Family 分布、会话概览、Channel 分布和指标类型展示。
- 增加 CS Host / URI 聚合画像，展示 GET/POST、时间范围、平均间隔、jitter、stream 和 packet 列表。
- 增加 CS DNS Beacon 聚合画像，展示 qname、query type、TXT/NULL/CNAME 形态、间隔和 jitter。
- 增加 VShell Stream 聚合画像，展示 TCP 心跳、短长包、长度前缀、WebSocket 提示、架构标记和 listener 线索。
- 候选证据支持展开详情、结构化预览、证据定位和过滤联动。

### 2. APT 页面

- 建立 APT 组织画像页骨架，当前以 Silver Fox / 银狐作为优先画像样例。
- 引入样本家族、投递阶段、传输特征、基础设施线索和 C2 技术证据来源。
- 增加归因解释面板，区分 Supporting Evidence、Weak Observations、Missing Evidence、Suppression / Caveat。
- 增加证据来源 tab，支持 C2、Delivery / Object、Threat Hunting、Credential / Auth 分类查看。
- 增加 Evidence Timeline，按当前 actor 与证据来源展示可读时间线。

### 3. 前后端协作

- 后端 C2/APT 类型结构持续扩展，支持 actorHints、sampleFamily、campaignStage、transportTraits、infrastructureHints、ttpTags 和 scoreFactors。
- 前端引入缓存 key，按 captureRevision、filePath 和 totalPackets 避免重复请求。
- 请求接入 AbortController，切换或刷新时避免过期结果覆盖当前页面。

### 4. 本轮冗余清理

- C2 页面不再维护本地通用 `StatCard`、`BucketList`、`ConversationList`。
- APT 页面不再维护本地通用 `StatCard`、`MiniMetric`、`BucketList`。
- 分布图改为共享 `AnalysisBucketChart`，列表改为共享 `AnalysisList`，小指标改为共享 `AnalysisMiniStat`。
- 页面只保留带业务语义的 `C2Panel` / `AptPanel` 默认图标封装。

## 四、当前缺陷

1. C2 聚合表仍包含大量页面内手写 table 和展开面板，后续应迁移到更强的共享数据表体系。
2. APT 归因依赖当前证据字段质量，缺少跨模块证据的统一 schema 约束和冲突解释。
3. CS / VShell 检测仍以候选画像和公开流量特征为主，需要更多真实样本回放测试。
4. APT 画像目前以单一优先 actor 骨架为主，多 actor 冲突、排除和合并策略仍待实现。
5. 当前分数因子已结构化，但 UI 对权重来源、负向抑制和缺失项的解释仍可继续增强。

## 五、下一步建议

1. 抽象 C2/APT 复杂证据表，给 `AnalysisDataTable` 增加展开行、列配置和 actions slot。
2. 补充 C2 聚合画像的后端单测，覆盖空数据、弱信号、强信号和误报抑制。
3. 将 APT 证据 schema 与 C2、对象提取、威胁狩猎输出进一步统一。
4. 引入“归因 caveat 面板”，明确哪些证据只能作为活动簇弱观察。
5. 为多 actor 场景增加并列画像、冲突提示和证据来源权重说明。
