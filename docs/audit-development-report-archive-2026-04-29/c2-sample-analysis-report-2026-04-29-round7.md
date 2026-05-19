# 日期: 2026-04-29
# 署名: opencode

# C2 样本分析页第七轮优化与报告：聚合画像深化

## 1. 本轮目标

上一轮已完成 CS Host / URI 聚合行的证据联动与报告归档。本轮继续深化 C2 分析页的聚合画像能力，目标包括：

1. CS 聚合行过滤器生成（复制 Host / URI、生成 tshark 显示过滤器）
2. CS DNS Beacon 聚合画像（qname 聚合、label 分布、TXT 统计）
3. VShell Stream-level 画像（按 stream 聚合 arch / length-prefix / heartbeat）
4. 缓存 LRU 优化
5. 聚合行代表 packet 选择优化
6. 补充缺失测试

## 2. 复核评论

对现有代码进行全面复核后，发现以下改进点：

### 2.1 前端缓存无大小限制

`c2AnalysisCache` 是全局 `Map<string, C2SampleAnalysis>`，没有 LRU 或容量上限，长时间运行可能导致内存泄漏。

### 2.2 DNS 检测粒度不足

`inspectDNSPacket` 只提取 qname 和 max label length，缺少：
- TXT / NULL / CNAME 类型分布
- request / response ratio
- 同一 qname 的重复查询聚合

### 2.3 VShell 缺少 stream-level 聚合

当前 VShell 检测主要是单包级别（arch-marker、length-prefix、websocket-handshake），`inspectVShellShortLongStream` 虽然是 stream 级别，但结果仍作为单个候选输出，没有按 stream 聚合形成画像。

### 2.4 聚合行代表 packet 选择粗糙

`firstNumber(item.packets)` 取第一个有效 packet，不一定是置信度最高或最典型的 packet。

## 3. 本轮优化内容

### 3.1 CS 聚合行过滤器生成

新增文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\FilterActions.tsx`

新增 `FilterActions` 组件，支持：
- 复制 Host 到剪贴板
- 复制 URI 到剪贴板
- 生成 tshark 显示过滤器并复制（格式：`http.host == "xxx" && http.request.uri contains "xxx"`）

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.tsx`

在 CS Host / URI 聚合表的证据列中集成 `FilterActions`：

```tsx
<div className="flex flex-wrap items-center gap-2 pt-1">
  <EvidenceActions
    packetId={item.representativePacket || firstNumber(item.packets)}
    preferredProtocol="HTTP"
  />
  <FilterActions
    host={item.host === "(no-host)" ? "" : item.host}
    uri={item.uri === "(no-uri)" ? "" : item.uri}
  />
</div>
```

### 3.2 CS DNS Beacon 聚合画像

#### 后端模型

修改文件：`backend/internal/model/types.go`

新增 `C2DNSAggregate` 结构体：

```go
type C2DNSAggregate struct {
    QName           string          `json:"qname"`
    Total           int             `json:"total"`
    MaxLabelLength  int             `json:"max_label_length"`
    QueryTypes      []TrafficBucket `json:"query_types"`
    TxtCount        int             `json:"txt_count"`
    NullCount       int             `json:"null_count"`
    CnameCount      int             `json:"cname_count"`
    RequestCount    int             `json:"request_count"`
    ResponseCount   int             `json:"response_count"`
    FirstTime       string          `json:"first_time,omitempty"`
    LastTime        string          `json:"last_time,omitempty"`
    AvgInterval     string          `json:"avg_interval,omitempty"`
    Jitter          string          `json:"jitter,omitempty"`
    Packets         []int64         `json:"packets,omitempty"`
    Confidence      int             `json:"confidence,omitempty"`
    Summary         string          `json:"summary"`
}
```

在 `C2FamilyAnalysis` 中新增 `DNSAggregates` 字段。

#### 后端聚合逻辑

修改文件：`backend/internal/engine/tool_c2.go`

- 新增 `c2DNSObservation` 结构体，用于收集 DNS 观察数据
- 修改 `inspectDNSPacket` 函数，收集 DNS 观察数据而非直接生成候选
- 新增 `buildCSDNSAggregates` 函数，按 qname 聚合 DNS 查询

聚合维度：
- qname
- query types（A / TXT / NULL / CNAME）
- TXT / NULL / CNAME 计数
- request / response 比例
- 时间间隔与 jitter

#### 前端类型与桥接

修改文件：
- `frontend/src/app/core/types.ts`：新增 `C2DNSAggregate` 接口
- `frontend/src/app/integrations/wailsBridge.ts`：新增 `asC2DNSAggregate` 映射函数

#### 前端展示

修改文件：`frontend/src/app/pages/C2Analysis.tsx`

新增 `CSDNSAggregates` 组件，展示：
- QName 与 max_label_length
- 查询类型分布
- TXT / NULL / CNAME 计数
- 请求 / 响应比例
- 时间间隔与 jitter
- Packets 列表
- 证据联动（EvidenceActions）与过滤器生成（FilterActions）

### 3.3 VShell Stream-level 画像

#### 后端模型

修改文件：`backend/internal/model/types.go`

新增 `C2StreamAggregate` 结构体：

```go
type C2StreamAggregate struct {
    StreamID        int64           `json:"stream_id"`
    Protocol        string          `json:"protocol,omitempty"`
    TotalPackets    int             `json:"total_packets"`
    ArchMarkers     []TrafficBucket `json:"arch_markers,omitempty"`
    LengthPrefix    int             `json:"length_prefix_count"`
    ShortPackets    int             `json:"short_packets"`
    LongPackets     int             `json:"long_packets"`
    Transitions     int             `json:"transitions"`
    HeartbeatAvg    string          `json:"heartbeat_avg,omitempty"`
    HeartbeatJitter string          `json:"heartbeat_jitter,omitempty"`
    HasWebSocket    bool            `json:"has_websocket"`
    WSParams        string          `json:"ws_params,omitempty"`
    ListenerHints   []TrafficBucket `json:"listener_hints,omitempty"`
    FirstTime       string          `json:"first_time,omitempty"`
    LastTime        string          `json:"last_time,omitempty"`
    Packets         []int64         `json:"packets,omitempty"`
    Confidence      int             `json:"confidence,omitempty"`
    Summary         string          `json:"summary"`
}
```

在 `C2FamilyAnalysis` 中新增 `StreamAggregates` 字段。

#### 后端聚合逻辑

修改文件：`backend/internal/engine/tool_c2.go`

- 新增 `c2VShellStreamWork` 结构体，用于收集 stream 级别的 VShell 数据
- 修改 `inspectVShellTCPPacket` 函数，同时收集 stream 级别数据
- 修改 `inspectVShellShortLongStream` 函数，更新 stream 数据
- 修改 `inspectPeriodicStream` 函数，更新心跳数据
- 新增 `buildVShellStreamAggregates` 函数，按 stream 聚合 VShell 特征

聚合维度：
- stream ID 与协议
- 架构标记（l64 / w64）
- 长度前缀计数
- 短包 / 长包交替与 transitions
- 心跳间隔与 jitter
- WebSocket 参数
- Listener / management 端口提示

#### 前端类型与桥接

修改文件：
- `frontend/src/app/core/types.ts`：新增 `C2StreamAggregate` 接口
- `frontend/src/app/integrations/wailsBridge.ts`：新增 `asC2StreamAggregate` 映射函数

#### 前端展示

修改文件：`frontend/src/app/pages/C2Analysis.tsx`

新增 `VShellStreamAggregates` 组件，展示：
- Stream ID 与协议
- 架构标记分布
- 长度前缀计数
- 短包 / 长包与 transitions
- 心跳间隔与 jitter
- WebSocket 标记
- Packets 列表
- Listener hints 标签
- 证据联动（EvidenceActions）

### 3.4 缓存 LRU 优化

新增文件：`frontend/src/app/utils/lruCache.ts`

实现 `LRUCache<K, V>` 类，支持：
- 容量限制（默认 10）
- LRU 淘汰策略
- get / set / has / delete / clear 操作

修改文件：`frontend/src/app/pages/C2Analysis.tsx`

将 `c2AnalysisCache` 从 `Map` 替换为 `LRUCache(10)`：

```typescript
const c2AnalysisCache = new LRUCache<string, C2SampleAnalysis>(10);
```

### 3.5 聚合行代表 packet 选择优化

修改文件：`backend/internal/model/types.go`

在 `C2HTTPEndpointAggregate` 中新增 `RepresentativePacket` 字段：

```go
RepresentativePacket int64 `json:"representative_packet,omitempty"`
```

修改文件：`backend/internal/engine/tool_c2.go`

在 `c2EndpointAggregateWork` 中新增 `postPacket` 字段，优先选择 POST 类型 packet 作为代表：

```go
if candidate.PacketID > 0 {
    item.packets = append(item.packets, candidate.PacketID)
    if method == "POST" && item.postPacket <= 0 {
        item.postPacket = candidate.PacketID
    }
}
```

构建聚合结果时：

```go
representativePacket := item.postPacket
if representativePacket <= 0 && len(item.packets) > 0 {
    representativePacket = item.packets[0]
}
```

前端使用 `representativePacket` 字段：

```tsx
<EvidenceActions
  packetId={item.representativePacket || firstNumber(item.packets)}
  preferredProtocol="HTTP"
/>
```

### 3.6 补充缺失测试

修改文件：`backend/internal/engine/c2_analysis_test.go`

新增测试：

```go
func TestBuildC2SampleAnalysisBuildsCSDNSAggregates(t *testing.T) {
    // 测试 DNS 聚合：qname、TXT 计数、request 计数
}

func TestBuildC2SampleAnalysisBuildsCSHostURIAggregates(t *testing.T) {
    // 更新：验证 representativePacket 为 POST 类型 packet
}
```

修改文件：`frontend/src/app/pages/C2Analysis.test.tsx`

新增测试：

```typescript
it("renders CS DNS Beacon aggregation profile", async () => {
    // 验证 DNS 聚合画像展示
});
```

更新测试：

```typescript
it("renders CS Host and URI aggregation profile", async () => {
    // 验证 FilterActions 按钮存在
});
```

## 4. 修改文件清单

### 后端

- `backend/internal/model/types.go`
  - 新增 `C2DNSAggregate` 结构体
  - 新增 `C2StreamAggregate` 结构体
  - `C2HTTPEndpointAggregate` 新增 `RepresentativePacket` 字段
  - `C2FamilyAnalysis` 新增 `DNSAggregates` 和 `StreamAggregates` 字段

- `backend/internal/engine/tool_c2.go`
  - 新增 `c2DNSObservation` 结构体
  - 新增 `c2VShellStreamWork` 结构体
  - `c2AnalysisBuilder` 新增 `dnsObservations` 和 `vshellStreamData` 字段
  - 修改 `inspectDNSPacket` 收集 DNS 观察数据
  - 修改 `inspectVShellTCPPacket` 收集 stream 级别数据
  - 修改 `inspectVShellShortLongStream` 更新 stream 数据
  - 修改 `inspectPeriodicStream` 更新心跳数据
  - 新增 `getOrCreateVShellStream` 辅助函数
  - 新增 `buildCSDNSAggregates` 聚合函数
  - 新增 `buildVShellStreamAggregates` 聚合函数
  - 修改 `finish` 调用新的聚合函数

- `backend/internal/engine/c2_analysis_test.go`
  - 新增 `TestBuildC2SampleAnalysisBuildsCSDNSAggregates` 测试
  - 更新 `TestBuildC2SampleAnalysisBuildsCSHostURIAggregates` 测试

### 前端

- `frontend/src/app/core/types.ts`
  - 新增 `C2DNSAggregate` 接口
  - 新增 `C2StreamAggregate` 接口
  - `C2HTTPEndpointAggregate` 新增 `representativePacket` 字段
  - `C2FamilyAnalysis` 新增 `dnsAggregates` 和 `streamAggregates` 字段

- `frontend/src/app/integrations/wailsBridge.ts`
  - 新增 `asC2DNSAggregate` 映射函数
  - 新增 `asC2StreamAggregate` 映射函数
  - `asC2HTTPEndpointAggregate` 新增 `representativePacket` 映射
  - `asC2Family` 新增 `dnsAggregates` 和 `streamAggregates` 映射

- `frontend/src/app/misc/FilterActions.tsx`（新增）
  - 实现复制 Host / URI / 生成过滤器功能

- `frontend/src/app/utils/lruCache.ts`（新增）
  - 实现 LRU 缓存类

- `frontend/src/app/pages/C2Analysis.tsx`
  - 导入 `FilterActions`、`LRUCache`、新类型
  - `c2AnalysisCache` 替换为 `LRUCache(10)`
  - CS Host / URI 聚合表集成 `FilterActions`
  - 新增 `CSDNSAggregates` 组件
  - 新增 `VShellStreamAggregates` 组件
  - 使用 `representativePacket` 作为代表 packet

- `frontend/src/app/pages/C2Analysis.test.tsx`
  - 新增 `renders CS DNS Beacon aggregation profile` 测试
  - 更新 `renders CS Host and URI aggregation profile` 测试

## 5. 风险与边界

- 本轮修改了后端 DNS 检测逻辑，从"直接生成候选"改为"收集观察数据 + 聚合"，但最终候选生成逻辑保持不变。
- VShell stream 聚合依赖 `inspectVShellTCPPacket` 收集数据，如果 stream ID 为 0 则不会进入聚合。
- LRU 缓存容量为 10，对于频繁切换抓包文件的场景足够；如果需要更大缓存，可调整 `LRUCache` 构造参数。
- `representativePacket` 优先选择 POST 类型 packet，如果没有 POST 则选择第一个 packet。

## 6. 测试覆盖

后端新增测试：
- `TestBuildC2SampleAnalysisBuildsCSDNSAggregates`：验证 DNS 聚合（qname、TXT 计数、request 计数）
- `TestBuildC2SampleAnalysisBuildsCSHostURIAggregates` 更新：验证 `representativePacket` 为 POST 类型

前端新增测试：
- `renders CS DNS Beacon aggregation profile`：验证 DNS 聚合画像展示
- `renders CS Host and URI aggregation profile` 更新：验证 FilterActions 按钮

## 7. 当前收益

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

## 8. 下一轮建议

### P0：聚合行过滤器增强

为 DNS 聚合行增加 DNS 类型过滤器：
- `dns.qname contains "xxx"`
- `dns.txt`

### P1：VShell 聚合行过滤器生成

为 VShell stream 聚合行增加过滤器：
- `tcp.stream == N`

### P1：APT 组织画像独立页

开始设计独立 `APT 组织画像` 页，首个 actor 可使用银狐 / Silver Fox，并消费当前 C2 技术证据。

### P2：聚合详情展开

为 DNS 和 VShell 聚合行增加"展开详情"功能，展示完整 typed record preview。
