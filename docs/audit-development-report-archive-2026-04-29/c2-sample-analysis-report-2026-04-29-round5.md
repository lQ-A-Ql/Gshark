# 日期: 2026-04-29
# 署名: Codex

# C2 样本分析页第五轮复核、优化与报告

## 1. 本轮目标

用户反馈当前 CS 筛选误报率偏高。本轮复核后确认：主要原因是早期规则为了打通骨架，把任意 HTTP method 都直接提升为 `http-beacon-shape` 候选，导致普通网页访问、普通登录请求、普通静态资源请求都会进入 CS 候选表。

本轮目标：

```text
降低 CS HTTP 候选误报
  -> 从单包即命中改为 observation + correlation 提升
```

## 2. 复核评论

Cobalt Strike HTTP/HTTPS Beacon 的 Malleable C2 特性决定了：

- 静态 URI / UA / Header 只能作为弱信号；
- 单个 GET 或 POST 本身没有足够判别力；
- 更可靠的证据来自同一 Host / URI 的重复通信、GET/POST 组合、稳定时间间隔、stream 聚集度、DNS / SMB / 周期性上下文。

此前规则的问题是：

```text
任意 HTTP method != ""
  -> addCSCandidate(http-beacon-shape)
```

这会让正常 HTTP 流量过度进入 CS 候选。

## 3. 本轮后端优化

### 3.1 新增 HTTP observation 阶段

修改文件：

- `C:\Users\QAQ\Desktop\gshark\backend\internal\engine\tool_c2.go`

新增内部结构：

```go
type c2HTTPObservation struct {
    packet     model.Packet
    method     string
    path       string
    host       string
    channel    string
    userAgent  string
    evidence   string
    confidence int
    tags       []string
}
```

`inspectHTTPPacket` 现在会先把 HTTP 请求记录为 observation，而不是直接生成 CS 候选。

### 3.2 强静态线索仍可直接提升

新增：

```go
strongCSHTTPStaticSignal()
```

当前保留的强静态弱候选包括：

- `POST` 路径包含 `submit`
- `POST` 路径包含 `id=`
- `GET` 路径包含 `__utm.gif`

这些仍然只是候选，不直接定性。

### 3.3 新增聚合提升

新增：

```go
promoteCSHTTPObservations()
```

提升条件：

- 只处理 `GET / POST`。
- 按 `Host + URI` 聚合。
- 同一 Host / URI 至少 4 条 observation。
- 同时满足以下之一：
  - interval 数量 >= 3、avg >= 5s、jitter <= 35%；
  - 样本量 >= 6。

满足条件后，才把 observation 提升为：

```text
http-beacon-shape
```

并添加标签：

- `endpoint-repeat`
- `correlated-signal`
- `stable-interval`，如果存在稳定间隔
- `get-post-tasking-shape`，如果同一组同时存在 GET 与 POST

### 3.4 Notes 更新

CS Notes 已调整为说明：

- 普通一次性 GET/POST 已默认抑制；
- HTTP 候选优先来自强静态线索、重复 Host/URI 或周期行为；
- Malleable C2 仍需结合上下文确认。

## 4. 测试补充

修改文件：

- `C:\Users\QAQ\Desktop\gshark\backend\internal\engine\c2_analysis_test.go`

新增误报回归测试：

```text
TestBuildC2SampleAnalysisSuppressesBenignSingleHTTPRequests
```

测试输入：

- 一次普通 `GET /index.html`
- 一次普通 `POST /login`

验证：

- 不生成 `http-beacon-shape`
- 不生成 Host / URI aggregate

同时调整旧 CS HTTP / DNS 测试，使其匹配更保守的新策略：静态强线索 + DNS 仍可命中，但普通 GET 不再自动计入。

## 5. 当前收益

本轮后，CS HTTP 检测从：

```text
单个 GET/POST 即候选
```

升级为：

```text
HTTP observation
  -> 强静态线索提升
  -> 重复 Host/URI + 周期/高频提升
  -> 候选表 / 聚合画像
```

直接收益：

- 降低普通浏览流量误报；
- 保留默认 profile 弱线索；
- 保留重复稳定 Host / URI 的 Beacon 行为证据；
- Host / URI 聚合画像更干净。

## 6. 风险与边界

- 更保守的规则可能减少部分低样本 CS HTTP 命中。
- 只有 1-2 个包的 CS 流量，如果没有默认 profile 线索，可能暂时不会进入 HTTP 候选；但周期性 stream、DNS、SMB、其它上下文仍可输出证据。
- 后续如果接入 response size、status code、content-type、header entropy，可以进一步提高判别力。

## 7. 下一轮建议

### P0：聚合行证据联动

给 CS Host / URI 聚合行增加：

- 定位首包；
- 打开代表 stream；
- 复制 Host / URI；
- 从聚合生成过滤器。

### P1：HTTP 响应侧过滤

继续降低误报：

- status code 分布；
- response size 稳定性；
- content-type 异常；
- set-cookie / authorization / beacon metadata hints。

### P1：静态资源降权

对普通静态资源路径进行默认降权或抑制：

- `.css`
- `.png`
- `.jpg`
- `.ico`
- `.woff`
- `.map`

但需保留重复、周期、低 jitter 情况下的行为提升能力。
