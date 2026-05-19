# 日期: 2026-04-29
# 署名: Codex

# C2 样本分析页第四轮复核、优化与报告

## 1. 本轮目标

上一轮完成了候选表的“主行精简 + 可展开详情 + 证据联动”。本轮开始进入 C2 行为画像层，优先落地 CS / Cobalt Strike 的 Host / URI 聚合。

本轮目标：

```text
从单包 CS 候选
  -> 提升为 Host / URI 维度的 HTTP/HTTPS Beacon 会话画像
```

## 2. 复核评论

Cobalt Strike 的 Malleable C2 可以修改 URI、Header、User-Agent、证书、metadata 放置位置。因此静态 IOC 只能作为弱信号。更适合 gshark 当前定位的分析方式是：

- 同一 Host / URI 是否重复出现；
- 是否存在 GET 拉任务与 POST 回传组合；
- 是否存在固定或近固定时间间隔；
- jitter 是否较低；
- 是否集中在同一 stream 或少量 stream；
- packet 列表是否能回溯。

此前 C2 页面已经能显示单包候选，但缺少按 Host / URI 聚合的视角。本轮补齐这一层。

## 3. 后端优化内容

### 3.1 新增模型

修改文件：

- `C:\Users\QAQ\Desktop\gshark\backend\internal\model\types.go`

新增：

```go
type C2HTTPEndpointAggregate struct {
    Host        string
    URI         string
    Channel     string
    Total       int
    GetCount    int
    PostCount   int
    Methods     []TrafficBucket
    FirstTime   string
    LastTime    string
    AvgInterval string
    Jitter      string
    Streams     []int64
    Packets     []int64
    Confidence  int
    Summary     string
}
```

并在 `C2FamilyAnalysis` 中新增：

```go
HostURIAggregates []C2HTTPEndpointAggregate `json:"host_uri_aggregates,omitempty"`
```

### 3.2 新增聚合逻辑

修改文件：

- `C:\Users\QAQ\Desktop\gshark\backend\internal\engine\tool_c2.go`

新增：

- `buildCSHostURIAggregates()`
- `uniqueInt64s()`
- `limitInt64List()`

聚合规则：

- 只处理 `family = cs`。
- 只处理 `channel = http / https`。
- 只处理 `indicatorType = http-beacon-shape`，避免周期性派生命中重复计数。
- 聚合 key 为 `Host + URI`。
- 统计 method 分布、GET / POST、time interval、jitter、streams、packets。

### 3.3 聚合置信度

聚合置信度以候选最大置信度为基础：

- 同一 Host / URI 同时出现 GET 和 POST：加权。
- 存在可计算的 interval / jitter：加权。
- 最终通过 `clampConfidence()` 限制范围。

## 4. 前端优化内容

### 4.1 类型与 bridge

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\core\types.ts`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\integrations\wailsBridge.ts`

新增前端类型：

```ts
export interface C2HTTPEndpointAggregate { ... }
```

bridge 新增 `host_uri_aggregates` 到 `hostUriAggregates` 的映射。

### 4.2 页面展示

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.tsx`

CS 标签页新增分区：

```text
CS Host / URI 聚合画像
```

该分区展示：

- Host / URI
- channel / confidence
- GET / POST / total
- avgInterval / jitter
- firstTime / lastTime
- streams
- packets
- method buckets
- summary

VShell 标签页不显示该分区，避免协议语义混淆。

## 5. 测试补充

### 5.1 后端测试

修改文件：

- `C:\Users\QAQ\Desktop\gshark\backend\internal\engine\c2_analysis_test.go`

新增测试：

```text
TestBuildC2SampleAnalysisBuildsCSHostURIAggregates
```

覆盖同一 Host / URI 下：

- GET 2 次
- POST 2 次
- total 4
- avgInterval 60.0s
- jitter 0%
- stream = 8
- packets = 41, 42, 43, 44

### 5.2 前端测试

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.test.tsx`

新增测试：

```text
renders CS Host and URI aggregation profile
```

覆盖：

- 聚合分区标题
- 聚合 summary
- GET / POST 计数
- avgInterval
- method bucket

## 6. 风险与边界

- 当前聚合只针对 CS HTTP/HTTPS，不处理 DNS Beacon，也不处理 VShell。
- 当前聚合只消费 `http-beacon-shape`，这是有意设计，避免周期性候选重复计入同一 Host / URI。
- 当前聚合表尚未提供“定位首包 / 打开代表流”操作，下一轮可以补。
- 时间间隔基于候选时间字段解析，如果上游 timestamp 格式不可解析，则 avgInterval / jitter 为空，但聚合仍可展示计数与 packet / stream。

## 7. 当前收益

本轮后，C2 分析页已经具备：

```text
单包候选表
  -> 可展开候选详情
  -> 证据跳包 / 跳流
  -> CS Host / URI 聚合画像
```

这使 CS 分析从“单点命中”开始升级为“会话级行为判断”。

## 8. 下一轮建议

### P0：聚合行证据联动

为 Host / URI 聚合行增加：

- 定位首包
- 打开代表 stream
- 复制 Host / URI
- 从聚合生成过滤器

### P1：CS DNS Beacon 聚合

新增 DNS 聚合：

- qname
- qtype
- max label length
- request / response ratio
- TXT / NULL 类型统计
- endpoint / packet 引用

### P1：VShell Stream-level 画像

新增 VShell stream 聚合：

- arch marker
- length prefix
- heartbeat interval
- short / long alternation
- websocket params
- listener / management hints
