# 日期: 2026-04-28
# 署名: Codex

# C2 样本分析页实现说明

## 一、页面定位

`C2 样本分析` 是一个侧边栏一级专题页，路由为：

```text
/c2-analysis
```

当前页面包含两个同级页内标签：

- `CS`：面向 Cobalt Strike / Beacon 相关候选流量
- `VShell`：面向公开研究中那类 Mandarin-language C2 framework 的候选流量

银狐 / Silver Fox 不作为当前页第三个标签。当前页只输出技术证据，并通过 `actorHints`、`sampleFamily`、`campaignStage`、`transportTraits`、`infrastructureHints` 等字段为后续独立 APT 组织画像页提供输入。

## 二、数据链路

当前链路为：

```text
前端 C2Analysis.tsx
  ↓ bridge.getC2SampleAnalysis(signal)
GET /api/c2-analysis
  ↓
Service.C2SampleAnalysis(ctx)
  ↓
packetStore.All(nil)
  ↓
buildC2SampleAnalysisFromPackets(ctx, packets)
```

本接口接入了现有取消机制：

- 前端使用 `AbortController`
- 后端使用 `r.Context()`
- 切换抓包或关闭抓包后旧请求不会回落到页面
- `LoadPCAP()` / `ClearCapture()` 会清理 C2 分析缓存

## 三、当前已实现规则

当前规则全部是“候选证据”级别，不直接给出最终定性。

### 1. CS / Cobalt Strike 候选

当前支持：

- HTTP / HTTPS 请求形态
  - GET 拉任务形态
  - POST 回传形态
  - `/submit.php?id=` 等默认 profile 弱线索
  - Host / URI / User-Agent / Header hints
- DNS C2 弱特征
  - DNS TXT
  - 长 label / suspicious qname
  - query name 与最大 label 长度
- SMB / Pivot 占位
  - SMB / NBSS 相关包进入 SMB pivot-like 候选
- Beacon 周期行为
  - 同一 stream 内固定或近固定间隔
  - sleep / jitter-like 回连
  - 约 45-75 秒间隔会带上 SilverFox-compatible 弱提示

注意：

- Cobalt Strike Malleable C2 可修改 URI、Header、UA、证书与 metadata 位置。
- 因此静态路径、端口、UA 都只作为弱信号。
- 实战判断应优先组合周期性、Host/URI 重复、GET/POST 配对、DNS 形态与上下文。

### 2. VShell 候选

当前支持：

- WebSocket 握手候选
  - `/?a=l64&h=...&t=ws_&p=...`
  - 参数位：`a` / `h` / `t` / `p`
  - `/ws` 路径与 8084 / 8088 listener 端口作为辅助线索
- TCP 架构标记
  - `l64`
  - `w64`
- 4 字节长度前缀
  - Big-endian / little-endian 都会尝试
  - 声明长度接近实际剩余长度时输出候选
- 短包 / 长包交替
  - 短包偏心跳
  - 长包偏命令或结果
- 约 10 秒心跳
  - 同一 stream 中固定或近固定 8-12 秒间隔会输出 VShell heartbeat 候选
- 管理面 / listener 端口观察
  - 8082：management surface 弱线索
  - 8084 / 8088：listener port 弱线索

注意：

- 端口只作为中弱信号。
- WebSocket 参数、架构标记、长度前缀与心跳组合出现时置信度更高。

## 四、银狐 / Silver Fox 兼容字段

当前 C2 证据记录预留了以下字段：

```ts
actorHints?: string[];
sampleFamily?: string;
campaignStage?: string;
transportTraits?: string[];
infrastructureHints?: string[];
ttpTags?: string[];
attributionConfidence?: number;
```

这些字段用于后续独立 APT 页聚合：

- ValleyRAT / Winos 4.0
- Gh0st 系变种
- HFS / HTTP File Server 下载链
- HTTPS C2
- TCP 长连接
- fallback C2
- 约 60 秒周期回连

当前实现中：

- `18856` / `9899` 等端口只进入 `silverfox-case-port-weak`
- `HFS` 相关线索进入 `hfs-delivery`
- 约 45-75 秒周期回连进入 `silverfox-60s-compatible`

这些只是画像兼容线索，不单独构成银狐定性。

## 五、前端展示

页面分区包括：

- 总览统计卡
- Family 分布
- 会话概览
- `CS / VShell` tabs
- 当前 family 概览
- 公开流量特征基线卡片
- Channel 分布
- 指标类型
- Beacon / Heartbeat 模式
- APT 兼容扩展口
- 候选证据表
- Family Notes
- 全局 Notes

候选证据表预留列：

- 包号
- Family
- Channel
- 指标类型
- 指标值
- 置信度
- 摘要
- 标签
- 归因提示

## 六、测试覆盖

后端：

- C2 空骨架返回
- context cancel
- VShell WebSocket 参数识别
- VShell TCP 架构标记 / 长度前缀 / 心跳识别
- CS HTTP / DNS 候选识别
- `/api/c2-analysis` payload 结构验证

前端：

- C2 页面渲染
- CS / VShell tab 切换
- tab 切换不重复请求
- cache key 生成
- 空 path 返回空 cache key

## 七、下一步建议

下一轮建议继续深化：

1. CS GET/POST 请求-响应配对与 Host/URI 聚合
2. DNS Beacon 的 qname entropy、label 分布与 request/response ratio
3. VShell TCP stream 级别更精确的 client/server 方向判断
4. C2 证据点击跳包 / 跳流
5. 独立 `APT 组织画像` 页，首个 actor 支持银狐 / Silver Fox


## 八、2026-04-29 复核优化记录：候选证据联动

本轮复核重点是把上一轮已经产出的 C2 候选命中，从“静态表格结果”推进到“可复核证据链”。结论如下：

- 原有 C2 页面已经具备 CS / VShell 双标签、规则候选、Beacon / Heartbeat 分区、APT 兼容字段与缓存链路。
- 但候选证据表此前只能展示 `packetId` / `streamId` / `indicator`，分析人员需要手动回到工作区查包或查流，复盘成本较高。
- 本轮已将候选证据表接入现有 `EvidenceActions` 组件，命中项现在可以直接执行：
  - `定位到包`：调用 `locatePacketById(packetId)` 并跳回主工作区。
  - `打开关联流`：调用 `preparePacketStream(packetId, preferredProtocol)` 并跳转到 `/http-stream`、`/tcp-stream` 或 `/udp-stream`。

### 协议偏好策略

候选证据打开关联流时会根据 C2 channel 选择一个保守的 preferred protocol：

- `method` 存在、`http`、`websocket`、`doh`：优先 HTTP 流。
- `dns`、`kcp_udp`、`udp`：优先 UDP 流。
- `tcp`、`smb`、`dot`：优先 TCP 流。
- `https` 但无 HTTP method 时不强行指定协议，交由 `preparePacketStream` 按实际 packet proto / streamId 推断，避免把原始 TLS 流错误塞入 HTTP 追踪页。

### 回归覆盖

前端测试新增覆盖：

- C2 候选证据点击 `定位到包` 时，会调用 `locatePacketById(42)` 并 `navigate("/")`。
- C2 候选证据点击 `打开关联流` 时，会按 HTTP 候选调用 `preparePacketStream(42, "HTTP")`，并跳转 `/http-stream`。

### 下一步建议

1. 在候选详情中展示 `source / destination / host / uri / evidence`，减少打开流前的信息缺口。
2. 为 CS GET/POST 配对增加“同一端点聚合视图”，并从候选表跳转到聚合详情。
3. 为 VShell TCP 规则增加 stream 方向判断，将 `client -> server` 与 `server -> client` 的心跳 / 负载模式拆开展示。
4. 独立 APT 页落地后，复用当前候选证据的 `actorHints / transportTraits / infrastructureHints` 做跨模块聚合。

## 九、2026-04-29 第二轮复核优化记录：候选上下文内嵌展示

上一轮已经补齐 C2 候选的跳包 / 跳流能力。本轮复核后继续优化候选证据表的“表内初判”能力：分析人员不必每条命中都先打开流，也能先看到关键上下文。

### 复核结论

`C2IndicatorRecord` 后端模型已经输出了较完整的证据字段：

- `time`
- `streamId`
- `source`
- `destination`
- `host`
- `uri`
- `method`
- `evidence`
- `transportTraits`
- `infrastructureHints`
- `ttpTags`

但前端候选表此前主要展示 `indicatorValue`、`summary`、`tags` 与 `actorHints`，源/目的端点、Host/URI 和 Evidence 仍然隐藏在结构化 JSON 中，导致用户必须打开流才能完成初步判断。

### 本轮优化

候选证据表的 `摘要 / 上下文 / 标签` 列新增内嵌上下文块，当前展示：

- 时间
- Stream ID
- 源端点 → 目的端点
- Host
- URI
- Method
- Evidence

标签行同步扩展，除原有 `tags` / `actorHints` / `sampleFamily` 外，继续展示：

- `campaignStage`
- `transportTraits`
- `infrastructureHints`
- `ttpTags`

### 效果

现在 C2 分析页可以形成两级复核体验：

1. 表内初判：直接查看端点、Host、URI、Evidence、TTP / 基础设施标签。
2. 深入复核：点击 `定位到包` 或 `打开关联流` 回到原始证据。

### 测试补充

前端测试已新增候选上下文断言，覆盖：

- `source -> destination`
- `host`
- `uri`
- `evidence`
- `infrastructureHints`
- `ttpTags`

### 下一步建议

1. 为候选表增加“展开详情”模式，主行只展示核心字段，展开区展示完整证据 JSON。
2. 将 CS 候选按 Host / URI 聚合，增加 GET/POST 配对与时间间隔视图。
3. 将 VShell 候选按 Stream 聚合，形成 stream-level 心跳 / 长度前缀 / WebSocket 参数画像。

## 十、2026-04-29 第三轮复核优化记录：候选行可展开详情

上一轮将端点、Host、URI、Evidence 等字段直接嵌入候选表，解决了“表内初判”问题。本轮继续复核发现：当候选数量较多、Evidence 较长或标签较多时，直接内嵌会让表格行高膨胀，不利于快速浏览。因此本轮将候选表升级为“主行精简 + 展开详情”的两层结构。

### 复核结论

- 主行应该只负责快速扫视：包号、Family、Channel、类型、值、置信度、摘要、少量标签和证据动作。
- 详情区再承载完整上下文：时间、Stream、端点、Host、URI、Method、Evidence、完整标签与 typed record preview。
- 这样既保留上一轮的上下文可见性，又避免候选行默认过高导致页面拥挤。

### 本轮优化

候选表新增 `展开详情 / 收起详情` 控制：

- 默认状态：只展示摘要与最多 5 个紧凑标签，超过部分显示 `+N more`。
- 展开状态：显示完整 `Evidence Context` 与 `Typed Record Preview`。
- 展开详情区带轻量边框、白底、过渡效果，保持与当前分析页风格一致。

详情区包含：

- 时间
- Stream
- 端点
- Host
- URI
- Method
- Evidence
- 完整标签集合
- typed record JSON 预览

### 测试补充

前端测试从“直接显示上下文”调整为“点击展开后显示上下文”，覆盖：

- 默认不显示端点详情，主行保持精简。
- 点击 `展开 C2 候选详情 #42` 后显示端点、Host、URI、Evidence、基础设施标签与 TTP 标签。
- 详情区显示 `Typed Record Preview`。

### 下一步建议

1. 将 CS Host / URI 聚合视图落地为独立分区。
2. 将 VShell 的单包候选提升到 stream-level 画像。
3. 为候选详情添加复制 JSON / 导出证据片段按钮。

## 十一、2026-04-29 第四轮复核优化记录：CS Host / URI 聚合画像

前几轮已经完成 C2 候选表、跳包/跳流、候选详情展开。本轮开始把 CS 从“单包候选列表”推进到“HTTP/HTTPS Beacon 会话画像”，新增 Host / URI 聚合视图。

### 复核结论

Cobalt Strike HTTP/HTTPS Beacon 不应只依赖默认 URI、User-Agent 或 Header 等弱静态特征。更有价值的是同一 Host / URI 下的重复 GET / POST 行为、时间间隔与 jitter。此前页面虽然能展示每条候选，但缺少按端点聚合的视角。

### 本轮优化

新增后端结构化模型：

- `C2HTTPEndpointAggregate`
- `C2FamilyAnalysis.hostUriAggregates`

聚合维度：

- Host
- URI

聚合字段：

- channel
- total
- GET 数量
- POST 数量
- method 分布
- firstTime / lastTime
- avgInterval
- jitter
- streams
- packets
- confidence
- summary

当前聚合只消费 `http-beacon-shape` 候选，避免周期性规则或其它派生命中重复计数。

### 前端展示

CS 标签页新增 `CS Host / URI 聚合画像` 分区。该分区展示：

- Host / URI
- GET / POST 计数
- 平均间隔 / jitter
- 首次 / 最后时间
- stream 列表
- packet 列表
- method bucket
- summary

VShell 标签页不显示该分区，避免跨 family 语义混淆。

### 测试补充

后端新增聚合测试，覆盖同一 Host / URI 下 2 次 GET + 2 次 POST，并验证：

- total = 4
- GET = 2
- POST = 2
- avgInterval = 60.0s
- jitter = 0%
- stream / packet 引用正确

前端新增聚合展示测试，覆盖：

- `CS Host / URI 聚合画像`
- 聚合 summary
- GET / POST 计数
- avgInterval
- method bucket

### 下一步建议

1. 将 CS Host / URI 聚合行增加“打开代表流 / 定位首包”操作。
2. 增加 DNS Beacon 聚合：qname、label 长度、qtype、request/response ratio。
3. 开始 VShell stream-level 聚合画像。

## 十二、2026-04-29 第五轮复核优化记录：CS HTTP 误报抑制

本轮根据实测反馈优化 CS 筛选规则：此前 `inspectHTTPPacket` 对任意 HTTP method 都直接生成 `http-beacon-shape` 候选，导致普通网页访问、登录请求、静态资源请求也会进入 CS 候选表，误报率偏高。

### 复核结论

- 单个 GET / POST 本身不能作为 CS HTTP Beacon 候选。
- Cobalt Strike Malleable C2 的强判断应来自“相关性”：重复 Host / URI、GET/POST 组合、稳定间隔、默认 profile 强线索、DNS / SMB / 周期性上下文。
- 页面已有 Host / URI 聚合，因此后端应该先记录 HTTP observation，再把满足条件的 observation 提升为候选。

### 本轮优化

CS HTTP 检测从“一阶段命中”改为“两阶段提升”：

1. `inspectHTTPPacket` 只记录 HTTP observation。
2. 仅在以下条件下生成 `http-beacon-shape`：
   - 强静态线索：例如 `POST` 路径包含 `submit` 或 `id=`，或 `GET __utm.gif` 这类默认 profile 线索。
   - 聚合提升：同一 Host / URI 重复通信，且满足高频或稳定间隔条件。

聚合提升条件：

- 同一 Host / URI 至少 4 条 observation；并且
  - 有稳定时间间隔：interval 数量 >= 3、avg >= 5s、jitter <= 35%；或
  - 样本量 >= 6。

### 效果

- 普通一次性 `GET /index.html` 不再进入 CS 候选。
- 普通一次性 `POST /login` 不再进入 CS 候选。
- 重复且稳定的 Host / URI 仍会被提升为 CS HTTP 候选。
- `POST /submit.php?id=` 等默认 profile 风格仍保留为弱候选，但 notes 明确需要结合上下文确认。

### 测试补充

新增后端误报回归：

- `TestBuildC2SampleAnalysisSuppressesBenignSingleHTTPRequests`

覆盖普通一次性 GET / POST 不应生成：

- `http-beacon-shape`
- Host / URI aggregate

### 下一步建议

1. 增加 CS 聚合行的定位首包 / 打开代表流动作。
2. 引入 HTTP response size / status code / content-type 差异作为二级过滤条件。
3. 对常见静态资源扩展名增加默认降权策略，例如 `.css`、`.png`、`.ico`、`.woff`。

## 十三、2026-04-29 第六轮复核优化记录：CS 聚合行证据联动与报告归档

本轮继续完善上一轮的 CS Host / URI 聚合画像：聚合行现在不只展示 Host、URI、GET/POST、间隔与 packet 列表，还能直接回溯证据。

### 复核结论

- 聚合画像已经能帮助用户判断 Beacon-like 会话，但此前仍需要手动去候选表或主工作区查找代表包。
- 聚合行本身已经包含 `packets` 与 `streams`，可以直接用首个 packet 作为代表证据入口。
- 项目已有 `EvidenceActions` 组件，应继续复用统一的“定位到包 / 打开关联流”交互，避免新建孤立按钮风格。

### 本轮优化

`CS Host / URI 聚合画像` 表新增证据联动：

- 使用聚合行 `packets[0]` 作为代表 packet。
- preferred protocol 固定为 `HTTP`。
- 复用 `EvidenceActions`：
  - `定位到包`
  - `打开关联流`

### 测试补充

前端测试更新：

- 聚合画像测试现在会确认页面存在证据联动按钮。
- 候选证据联动测试改为使用 `getAllByRole(...).at(-1)`，避免聚合行与候选行同时存在按钮时发生多元素匹配冲突。

### 报告归档

本轮还创建统一报告归档目录，用于存放今日所有 C2 报告、C2 综合实现说明，以及既有审计开发报告。归档目录：

```text
docs/audit-development-report-archive-2026-04-29
```

目录内包含索引文件 `README.md`，用于说明文件来源与用途。

### 下一步建议

1. 为聚合行增加复制 Host / URI 与生成过滤器能力。
2. 开始做 CS DNS Beacon 聚合画像。
3. 开始做 VShell stream-level 聚合画像。

## 十四、2026-04-29 第七轮复核优化记录：聚合画像深化

本轮继续深化 C2 分析页的聚合画像能力，完成上一轮提出的三项建议，并补充缓存优化、代表 packet 选择优化和缺失测试。

### 复核结论

- CS 聚合行已具备证据联动，但缺少过滤器生成能力，用户仍需手动构建 tshark 过滤器。
- DNS 检测只输出单包候选，缺少按 qname 聚合的视角。
- VShell 检测主要是单包级别，缺少 stream 级别的聚合画像。
- 前端缓存无大小限制，长时间运行可能导致内存泄漏。
- 聚合行代表 packet 选择粗糙，优先选择 POST 类型更合理。

### 本轮优化

#### 1. CS 聚合行过滤器生成

新增 `FilterActions` 组件，支持：
- 复制 Host 到剪贴板
- 复制 URI 到剪贴板
- 生成 tshark 显示过滤器（格式：`http.host == "xxx" && http.request.uri contains "xxx"`）

集成到 CS Host / URI 聚合表的证据列。

#### 2. CS DNS Beacon 聚合画像

后端新增 `C2DNSAggregate` 模型和 `buildCSDNSAggregates` 聚合函数，聚合维度：
- qname
- query types（A / TXT / NULL / CNAME）
- TXT / NULL / CNAME 计数
- request / response 比例
- 时间间隔与 jitter

前端新增 `CSDNSAggregates` 组件，展示 DNS 聚合画像。

#### 3. VShell Stream-level 画像

后端新增 `C2StreamAggregate` 模型和 `buildVShellStreamAggregates` 聚合函数，按 stream 聚合：
- 架构标记（l64 / w64）
- 长度前缀计数
- 短包 / 长包交替与 transitions
- 心跳间隔与 jitter
- WebSocket 参数
- Listener / management 端口提示

前端新增 `VShellStreamAggregates` 组件，展示 VShell stream 画像。

#### 4. 缓存 LRU 优化

新增 `LRUCache` 工具类，将 `c2AnalysisCache` 从无限 `Map` 替换为 `LRUCache(10)`。

#### 5. 聚合行代表 packet 选择优化

后端聚合优先选择 POST 类型 packet 作为代表，新增 `RepresentativePacket` 字段。

#### 6. 补充缺失测试

- 后端：`TestBuildC2SampleAnalysisBuildsCSDNSAggregates`
- 前端：`renders CS DNS Beacon aggregation profile`

### 测试补充

后端测试覆盖：
- DNS 聚合（qname、TXT 计数、request 计数）
- Host/URI 聚合（representativePacket 为 POST 类型）

前端测试覆盖：
- DNS 聚合画像展示
- FilterActions 按钮存在性验证

### 当前收益

本轮后，C2 分析页具备完整的聚合画像能力：

```text
CS 标签页：
  -> Host / URI 聚合画像（HTTP Beacon 会话级）
     -> 证据联动（定位包 / 打开流）
     -> 过滤器生成（复制 Host / URI / tshark 过滤器）
  -> DNS Beacon 聚合画像（qname 级）
     -> 证据联动
     -> 过滤器生成

VShell 标签页：
  -> Stream 聚合画像（stream 级）
     -> 架构标记 / 长度前缀 / 短长包交替 / 心跳
     -> 证据联动
```

### 下一步建议

1. 为 DNS 聚合行增加 DNS 类型过滤器（`dns.qname contains "xxx"`）。
2. 为 VShell stream 聚合行增加 stream 过滤器（`tcp.stream == N`）。
3. 开始设计独立 APT 组织画像页，首个 actor 使用银狐 / Silver Fox。
4. 为 DNS 和 VShell 聚合行增加"展开详情"功能。


---

## 2026-04-29 第八轮复查评论与优化记录（署名：Codex）

### 对上一轮结论的评论

上一轮 `round7` 已经把 C2 页从候选表推进到聚合画像阶段，但复查发现两个证据联动细节仍需补齐：

- CS DNS 聚合行继续复用 HTTP Host 过滤器会导致语义错误，qname 应生成 DNS 专用过滤器。
- VShell Stream 聚合只提供代表包定位，缺少 `tcp.stream` 级复核入口，不利于观察心跳、长度前缀与短长包交替。

### 本轮优化

- `FilterActions` 扩展为协议感知组件，支持 `http` / `dns` / `tcp`。
- CS DNS 聚合行新增 `QName` 复制与 `dns.qry.name contains "..."` 过滤器；当 TXT 命中时附加 `dns.qry.type == 16`。
- VShell Stream 聚合行新增 `Stream` 复制与 `tcp.stream == N` 过滤器。
- 显示过滤器值增加引号与反斜杠转义。
- C2 family 空结构补齐 `dnsAggregates` 与 `streamAggregates`。

### 验证

- `cd frontend && npx tsc --noEmit`
- `cd frontend && npm test -- C2Analysis`
- `cd frontend && npm test`
- `cd frontend && npm run build`
- `cd backend && go test ./...`
- C2Analysis 专项测试：7 项通过。
- 前端全量测试：10 个测试文件、39 项通过。
- 前端生产构建与后端全量 Go 测试均通过。

### 后续建议

下一轮优先为 DNS / VShell 聚合行增加展开详情，同时把候选证据表也接入协议化过滤器生成；随后可以进入独立 APT 组织画像页骨架设计。


---

## 2026-04-29 第九轮复查评论与优化记录（署名：Codex）

### 对上一轮结论的评论

第八轮已经修正 DNS 与 VShell 的过滤器语义，但聚合画像仍停留在摘要层，候选证据表也尚未复用协议化过滤器。因此本轮优先补齐“展开详情”和“candidate 行过滤器”两条证据复核链路。

### 本轮优化

- CS DNS 聚合行新增详情展开，展示 qname、时间范围、avg interval、jitter、request/response、query type 分布、TXT/NULL/CNAME 形态和 packet 时间序列。
- VShell Stream 聚合行新增详情展开，展示 stream、协议、总包数、长度前缀、短/长包、transitions、心跳、架构标记、listener hints 和 packet 时间序列。
- C2 候选证据表接入协议化 `FilterActions`，按 DNS / TCP-like / HTTP 自动生成显示过滤器。
- 新增统一聚合展开按钮与 metric grid 详情布局，保持白底与轻量卡片风格。

### 验证

- `cd frontend && npx tsc --noEmit`
- `cd frontend && npm test -- C2Analysis`
- `cd frontend && npm test`
- `cd frontend && npm run build`
- `cd backend && go test ./...`
- C2Analysis 专项测试：9 项通过。
- 前端全量测试：10 个测试文件、41 项通过。
- 前端生产构建与后端全量 Go 测试均通过。

### 后续建议

下一轮建议优先继续降低 CS 误报，在后端评分中增加多信号门槛；同时为 DNS / VShell 详情加入 interval sparkline 或最小时间线表达。


---

## 2026-04-29 第十轮复查评论与优化记录（署名：Codex）

### 对上一轮结论的评论

第九轮已经完成前端聚合详情和候选过滤器联动，C2 页的复核体验已经成形。本轮复查确认下一步收益最大的点是后端 CS 误报压降，尤其是静态 URI 单点命中、浏览器 polling 与原始 TCP 周期流误归入 CS 的问题。

### 本轮优化

- 静态 HTTP profile-like 线索不再即时生成 CS 候选，仅作为聚合评分因子。
- Host/URI 聚合改为多信号评分：stable interval、GET/POST 互补、default-profile-like、high-volume、non-browser context、browser context penalty。
- 高频重复不再单独作为强信号，仅作为加分项。
- CS 周期性 stream 检测新增适用性门槛：仅 HTTP-like / TLS / 443 可进入 CS 周期候选，普通原始 TCP 周期流不再提升为 CS。
- CS notes 更新为多信号门槛说明。

### 验证

- `cd backend && go test ./internal/engine -run C2`
- `cd frontend && npm test -- C2Analysis`
- `cd frontend && npx tsc --noEmit`
- `cd frontend && npm test`
- `cd frontend && npm run build`
- `cd backend && go test ./...`
- 后端 C2 专项测试通过。
- 前端 C2Analysis 专项测试：9 项通过。
- 前端类型检查通过。
- 前端全量测试：10 个测试文件、41 项通过。
- 前端生产构建与后端全量 Go 测试均通过。

### 后续建议

下一轮建议把评分因子透出到前端详情中，并继续加入响应侧信号，例如状态码稳定性、响应体大小稳定性和请求/响应配对。

---

## 2026-04-29 第十一轮复查评论与优化记录（署名：Codex）

### 对上一轮结论的评论

第十轮已经把 CS 误报治理的重点从前端展示推进到后端多信号门槛，方向正确。本轮复查发现新的瓶颈是“评分不可见”：Host/URI 聚合虽然已降低误报，但前端仍只展示 confidence 与摘要，无法解释具体由哪些行为因子支撑。

### 本轮优化

- `C2HTTPEndpointAggregate` 新增 `signal_tags` / `signalTags` 字段。
- `buildCSHostURIAggregates` 聚合候选时收集 `candidate.Tags`，去重并限制最多 12 个信号标签。
- CS Host/URI 聚合画像新增 `Scoring Signals` 证据块，展示 `stable-interval`、`get-post-tasking-shape`、`non-browser-context` 等评分因子。
- 后端测试补充 Host/URI 聚合 `SignalTags` 断言。
- 前端测试补充评分因子渲染断言。

### 验证

- `cd backend && go test ./internal/engine -run C2`
- `cd frontend && npm test -- C2Analysis`
- `cd frontend && npx tsc --noEmit`
- `cd frontend && npm test`
- `cd frontend && npm run build`
- `cd backend && go test ./...`
- 后端 C2 专项测试通过。
- 前端 C2Analysis 专项测试：9 项通过。
- 前端类型检查通过。
- 前端全量测试：10 个测试文件、41 项通过。
- 前端生产构建与后端全量 Go 测试均通过。

### 后续建议

下一轮建议把 `signalTags` 进一步升级为结构化 `scoreFactors`，区分正向加分与负向抑制，并加入响应侧稳定性信号，形成完整的 `Why hit / Why suppressed` 解释面板。

---

## 2026-04-29 第十二轮复查评论与优化记录（署名：Codex）

### 对上一轮结论的评论

第十一轮已完成 CS Host/URI 评分因子前端可见化，但复查发现真实 bridge 层尚未把后端 `signal_tags` 映射为前端 `signalTags`，因此真实运行时可能看不到评分标签。本轮已补齐该映射。

同时，上一轮关于“APT 组织画像应独立成页”的方向继续成立：C2 页只负责技术证据，APT 页负责组织 / 活动簇画像、投递链、样本家族和基础设施关联。

### 本轮优化

- 后端新增 `APTAnalysis`、`APTActorProfile`、`APTEvidenceRecord` 数据契约。
- 后端新增 `APTAnalysis(ctx)` service、`/api/apt-analysis` 接口和请求取消处理。
- 后端打开 / 关闭抓包时清理 `aptAnalysis` 缓存，避免旧包画像污染新包。
- 预置 Silver Fox / 银狐 actor profile 骨架，包含 ValleyRAT、Winos 4.0、Gh0st variant、HFS 下载链、fallback C2、HTTPS/TCP C2 等证据位。
- 前端新增 `/apt-analysis` 一级页面、侧边栏入口和顶部“分析”菜单入口。
- 前端新增 APT 页面骨架：总览卡、actor tabs、画像概览、Silver Fox 基线、分布区、证据表和证据跳转动作。
- `AnalysisHero` 新增 indigo 主题。
- `wailsBridge` 新增 `getAPTAnalysis(signal?)`，并修复 C2 `signal_tags` → `signalTags` 映射。

### 验证

- `cd frontend && npx tsc --noEmit`
- `cd backend && go test ./internal/engine -run 'C2|APT'`
- `cd backend && go test ./internal/transport -run 'C2|APT'`
- `cd frontend && npm test -- AptAnalysis C2Analysis`
- `cd frontend && npm test`
- `cd frontend && npm run build`
- `cd backend && go test ./...`
- 前端全量测试：11 个测试文件、43 项通过。
- 后端全量 Go 测试通过。
- 前端生产构建通过。

### 后续建议

下一轮建议让 C2 真实规则开始填充 APT 兼容字段，并在 APT 页增加 evidence source tabs；同时将 CS `signalTags` 升级为结构化 `scoreFactors`，使 APT 画像能区分正向证据、负向抑制和缺失证据。

---

## 2026-04-29 第十三轮复查评论与优化记录（署名：Codex）

### 对上一轮结论的评论

第十二轮完成了独立 APT 组织画像页和 Silver Fox / 银狐 profile 骨架，但仍缺少真实 C2 字段填充。本轮确认应优先从 C2 candidate 生成层补齐 APT 兼容字段，让 APT 页能消费真实 typed evidence，而不是只显示静态 profile。

### 本轮优化

- `APTEvidenceRecord` 新增 `source_module` / `sourceModule` 字段，当前 C2 生成的 APT evidence 标记为 `c2-analysis`。
- C2 candidate 生成新增 `c2APTEnrichmentForCandidate`，自动补充 Silver Fox 兼容字段。
- 支持 HFS / HTTP File Server / Rejetto、Winos、ValleyRAT、Gh0st、443、周期回连、18856 / 9899 等弱画像线索。
- `addCSCandidate` 与 `addVShellCandidate` 均接入 APT enrichment。
- HFS 基础设施线索统一补充 `hfs-download-chain`。
- APT 页面新增证据来源 tabs：全部证据、C2 Evidence、Delivery / Object、Threat Hunting、Credential / Auth。
- APT 证据表展示 `sourceModule · evidenceType · confidence`，便于区分证据来源。
- 后端新增 C2 → APT Silver Fox 兼容字段流转测试；前端更新 APT tabs 与 sourceModule 渲染测试。

### 验证

- `cd frontend && npx tsc --noEmit`
- `cd backend && go test ./internal/engine -run 'C2|APT'`
- `cd backend && go test ./internal/transport -run 'C2|APT'`
- `cd frontend && npm test -- AptAnalysis C2Analysis`
- `cd frontend && npm test`
- `cd frontend && npm run build`
- `cd backend && go test ./...`
- 前端全量测试：11 个测试文件、43 项通过。
- 后端全量 Go 测试通过。
- 前端生产构建通过。

### 后续建议

下一轮建议把 CS `signalTags` 升级为结构化 `scoreFactors`，并在 APT 页新增归因解释面板，明确 supporting evidence、weak observations、missing evidence 与 confidence rationale。


---

## 2026-04-29 第十四轮复查评论与优化记录（署名：opencode）

### 对上一轮结论的评论

第十三轮已完成 C2 → APT 证据流转和 APT 证据来源 tabs，本轮确认应优先实现 CS 评分因子结构化和 APT 归因解释面板。

### 本轮优化

#### 1. CS 评分因子结构化

- 后端新增 `C2ScoreFactor` 模型，包含 `name`、`weight`、`direction`、`summary` 字段
- `C2HTTPEndpointAggregate` 新增 `ScoreFactors` 字段
- 新增 `classifyScoreFactor` 函数，将 tag 分类为正向/负向评分因子
- 正向因子：stable-interval(+10)、get-post-tasking-shape(+8)、endpoint-repeat(+6)、correlated-signal(+5)、default-profile-like(+4)、stable-status-code(+3)、stable-content-type(+2)、non-browser-context(+3)、periodic(+7)、beacon-like(+6)
- 负向因子：browser-context(-4)、needs-correlation(-2)、weak-signal(-1)、malleable-profile-weak(-1)
- 前端新增 "Scoring Factors" 面板，展示正向/负向评分因子及其权重

#### 2. 响应侧信号

- `c2HTTPObservation` 新增 `statusCode`、`contentType`、`responseSize` 字段
- `inspectHTTPPacket` 收集 HTTP 响应侧信息
- `promoteCSHTTPObservations` 计算响应稳定性：
  - `statusCodeStability`：相同状态码比例
  - `contentTypeStability`：相同 Content-Type 比例
- 当稳定性 ≥ 80% 时，添加 `stable-status-code` 或 `stable-content-type` 标签

#### 3. APT 证据源扩展

- 新增 `tool_apt.go`，实现 `buildAPTAnalysisFromThreatHits` 和 `buildAPTAnalysisFromObjects`
- 接入 ThreatHunting 模块的 YARA 命中、规则匹配等证据
- 接入 Object Export 模块的可执行文件、脚本、文档等证据
- `APTAnalysis` 函数调用新创建的证据接入函数

#### 4. 聚合详情可视化增强

- 新增 `Sparkline` 组件，支持 SVG 折线图
- 已导入到 C2Analysis.tsx，但因后端未返回原始 intervals 数据，暂未使用

#### 5. APT 归因解释面板

- 新增 `AttributionExplainer` 组件，展示：
  - Supporting Evidence（置信度 ≥ 60 的正向证据）
  - Weak Observations（置信度 30-59 的弱信号）
  - Missing Evidence（预期但未检测到的证据）
  - Confidence Rationale（置信度计算逻辑）
- 新增 `buildMissingEvidence` 函数，根据 actor profile bucket 判断缺失证据

### 验证

- `cd backend && go test ./internal/engine/... -run C2 -v`
- `cd backend && go test ./internal/engine/... -run APT -v`
- `cd frontend && pnpm run test -- --run src/app/pages/C2Analysis.test.tsx`
- `cd frontend && pnpm run test -- --run src/app/pages/AptAnalysis.test.tsx`
- 后端 C2 专项测试：11 项通过
- 后端 APT 专项测试：2 项通过
- 前端 C2Analysis 专项测试：9 项通过
- 前端 AptAnalysis 专项测试：2 项通过

### 后续建议

1. 修改后端聚合函数返回原始 intervals 数组，使 Sparkline 组件能够展示 interval 分布
2. 将 APT 证据的 confidence 升级为结构化 scoreFactors
3. 改进 `buildMissingEvidence` 函数，基于实际证据分布动态判断缺失项
4. 为归因解释面板增加证据时间线可视化


---

# 日期: 2026-04-29
# 署名: Codex

## Round15 续写：C2 intervals 可视化与 APT 结构化评分

本轮在 C2 样本分析页与 APT 组织画像页之间继续强化“可解释、可复核、可视化”的证据链。

### 已完成

- 后端 C2 聚合模型新增 `intervals`：`C2HTTPEndpointAggregate.intervals`、`C2DNSAggregate.intervals`、`C2StreamAggregate.intervals`。
- 前端 C2 页面启用 `Sparkline`：CS Host/URI、CS DNS detail、VShell stream detail 均可展示 interval sparkline。
- APT typed model 新增 `APTScoreFactor`。
- `APTEvidenceRecord` 与 `APTActorProfile` 支持 `scoreFactors`。
- APT 后端生成 evidence-level score factors，并汇总到 profile-level。
- APT Missing Evidence 从静态 bucket 判断改为真实 evidence + profile bucket 混合判断。
- APT 页面新增 `Evidence Timeline`，展示当前 actor 与当前 evidence tab 下的前 50 条证据。

### 验证

- `npx tsc --noEmit`：通过。
- `npm test -- C2Analysis AptAnalysis`：通过。
- `npm test`：通过。
- `npm run build`：通过。
- `go test ./internal/engine -run 'C2|APT'`：通过。
- `go test ./internal/transport -run 'C2|APT'`：通过。
- `go test ./...`：通过。

### 后续

下一轮建议围绕 APT 总分解释、Timeline 分页/分阶段视图、actor matcher 泛化、Object/Threat evidence 反跳定位继续推进。

---

# 日期: 2026-04-29
# 署名: Codex

## Round16 续写：前端全站设计缺陷复核与 UI 基线收敛

本轮将重心转到前端全站设计缺陷治理。复核结论是：C2 / APT / MISC 等页面能力增长后，局部 `Panel`、`StatCard`、表格壳、空态、折叠动画重复实现，正在形成新的维护债。默认策略改为先建立共享 UI 基线，再逐页迁移。

### 已完成

- 新增 `DesignSystem.tsx`，提供 `SurfacePanel`、`MetricCard`、`StatusHint`、`EmptyState`、`DataTableShell`、`CollapsibleContent`。
- C2 页面本地统计卡、主面板、加载/错误提示、候选表壳和主要空态开始迁移到共享组件。
- APT 页面本地统计卡、主面板、加载/错误提示、Evidence table 壳和主要空态开始迁移到共享组件。
- MISC 页面模块展开区接入共享折叠动画，loading / empty 状态接入共享提示组件。
- Payload WebShell 解码模块在 embedded 模式下改为轻量 flat surface，并避免重复显示完整模块标题，缓解卡片套卡片问题。

### 验证

- `npx tsc --noEmit`：通过。
- `npm test -- C2Analysis AptAnalysis MiscTools`：通过，3 个测试文件、22 项测试通过。
- `npm run build`：通过。
- `npm test`：通过，11 个测试文件、43 项测试通过。

### 后续

下一轮建议继续推进 `WorkbenchTitleBar`，专门统一工作区与 TCP/HTTP/UDP 流追踪的白底工作台标题区；同时把 USB、Vehicle、Industrial、ThreatHunting、ObjectExport 的本地 panel/stat/table 逐步迁移到共享组件，避免继续产生页面级样式分叉。

---

# 日期: 2026-04-29
# 署名: Codex

## Round17 续写：工作区与流追踪白底标题区统一

本轮继续前端全站设计收敛，重点处理用户要求保留白底的工作台类页面。

### 已完成

- `DesignSystem.tsx` 新增 `WorkbenchTitleBar` 与 `WorkbenchChip`。
- `Workspace.tsx` 根容器显式保持白底，顶部文件/分页/定位工具迁移到白底工作台标题区。
- `TcpStream.tsx` 顶部栏迁移到 `WorkbenchTitleBar`，endpoint 与加载状态进入统一标题区。
- `HttpStream.tsx` 顶部栏迁移到 `WorkbenchTitleBar`，stream switch 与 view mode 控件进入 actions 插槽。
- `UdpStream.tsx` 顶部栏迁移到 `WorkbenchTitleBar`，endpoint 与加载状态进入统一标题区。

### 验证

- `npx tsc --noEmit`：通过。
- `npm test`：通过，11 个测试文件、43 项测试通过。
- `npm run build`：通过。

### 后续

下一轮建议继续抽象 `StreamControlBar`、`StreamNavigator` 与 `StreamChunkCard`，统一 TCP / HTTP / UDP 的底部工具区、切流控件与片段卡片；同时继续迁移 USB / Vehicle / Industrial 的本地 panel/stat 组件。

---

# 日期: 2026-04-29
# 署名: Codex

## Round18 续写：流追踪 StreamNavigator / ViewModeToggle / ControlBar 收敛

本轮继续白底工作台路线，将 TCP / HTTP / UDP 三个流追踪页中重复散写的切流控件与视图模式切换抽象为共享组件。

### 已完成

- `DesignSystem.tsx` 新增 `StreamNavigator`、`ViewModeToggle`、`StreamControlBar`。
- `HttpStream.tsx` 顶部 actions 改用 `StreamNavigator` 与 `ViewModeToggle<HTTPViewMode>`。
- `TcpStream.tsx` 底部工具条改用 `StreamControlBar`，切流改用 `StreamNavigator`，视图切换改用 `ViewModeToggle<RawViewMode>`。
- `UdpStream.tsx` 底部工具条同样迁移到共享流追踪控件。

### 验证

- `npx tsc --noEmit`：通过。
- `npm test`：通过，11 个测试文件、43 项测试通过。
- `npm run build`：通过。
- 注：沙箱下 npm test / build 首次因 esbuild 子进程 `spawn EPERM` 失败，已按授权流程在沙箱外重跑通过。

### 后续

下一轮建议新增 `StreamChunkCard` 与 `StreamSearchBar`，继续统一 TCP / HTTP / UDP 的片段卡片、搜索栏与 payload 展开入口；随后拆分 Workspace 顶部 actions，降低主工作区 JSX 复杂度。

---

# 日期: 2026-04-29
# 署名: Codex

## Round19 续写：StreamChunkCard 与 StreamSearchBar 收敛

本轮继续流追踪工作台收敛，将 TCP / HTTP / UDP 三个页面的片段卡片与 HTTP 搜索栏迁移到共享组件。

### 已完成

- `DesignSystem.tsx` 新增 `StreamChunkCard` 与 `StreamSearchBar`。
- `TcpStream.tsx` 删除本地 `RawStreamChunkCard`，chunk 列表改用 `StreamChunkCard`。
- `UdpStream.tsx` 删除本地 `RawStreamChunkCard`，chunk 列表改用 `StreamChunkCard`。
- `HttpStream.tsx` 删除本地 `HTTPChunkCard`，chunk 列表改用 `StreamChunkCard`；HTTP 搜索栏改用 `StreamSearchBar`。
- 保留 TCP / HTTP / UDP 原有 payload 渲染、搜索、切流、导出与完整 payload 弹层行为。

### 验证

- `npx tsc --noEmit`：通过。
- `npm test`：通过，11 个测试文件、43 项测试通过。
- `npm run build`：通过。

### 后续

下一轮建议把 `StreamSearchBar` 扩展到 TCP / UDP，新增 `StreamPayloadDialog` 统一完整 payload 弹层；同时拆分 Workspace 顶部 actions，降低主工作区 JSX 复杂度。
