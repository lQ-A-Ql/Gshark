# 日期: 2026-04-29
# 署名: Codex

# C2 样本分析页第二轮复核、优化与报告

## 1. 本轮目标

上一轮已经完成 C2 候选证据的 `定位到包` 与 `打开关联流`，解决了候选命中无法快速回溯原始证据的问题。本轮继续复核发现：候选表虽然能跳转，但表内上下文仍不足，分析人员无法在不打开流的情况下快速判断命中质量。

因此本轮目标是：

```text
让 C2 候选表自身具备初步研判能力
```

即在同一行中展示端点、Host、URI、Method、Evidence 与 TTP / 基础设施标签。

## 2. 复核评论

后端 `C2IndicatorRecord` 已经具备较完整字段，包括：

- `packetId`
- `streamId`
- `time`
- `source`
- `destination`
- `host`
- `uri`
- `method`
- `evidence`
- `transportTraits`
- `infrastructureHints`
- `ttpTags`

前端此前只消费了其中一部分，主要展示：

- 包号
- Family
- Channel
- Indicator 类型
- Indicator 值
- 置信度
- Summary
- tags / actorHints

这会导致大量高价值上下文隐藏，尤其是：

- CS 候选的 Host / URI / Method。
- VShell 候选的 Evidence 形态，例如参数、长度前缀、心跳间隔。
- 银狐兼容方向的基础设施弱线索，例如 `https-c2-compatible`、`hfs-delivery`、`silverfox-case-port-weak`。

## 3. 本轮优化内容

### 3.1 候选表新增上下文块

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.tsx`

在候选证据表的 `摘要 / 上下文 / 标签` 列内新增 `CandidateContext` 组件，展示：

- 时间
- Stream
- 端点：`source → destination`
- Host
- URI
- Method
- Evidence

这个设计保留了表格结构，不额外增加大量列，避免横向越界。

### 3.2 标签行扩展

候选标签行从原来的：

- `tags`
- `actorHints`
- `sampleFamily`

扩展为：

- `tags`
- `actorHints`
- `sampleFamily`
- `campaignStage`
- `transportTraits`
- `infrastructureHints`
- `ttpTags`

这使未来独立 APT 页需要消费的网络画像字段，也能先在 C2 页直接露出，便于人工复核。

### 3.3 测试补充

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.test.tsx`

新增测试：

```text
renders candidate context without opening a stream
```

覆盖断言：

- `10.0.0.5:443 → 10.0.0.8:51512`
- `c2.example.test`
- `/submit.php?id=42`
- `samples=4 avg=60s jitter=0.05`
- `https-c2-compatible`
- `periodic-callback`

## 4. 修改文件

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.tsx`
  - 新增 `CandidateContext`。
  - 候选表摘要列改为 `摘要 / 上下文 / 标签`。
  - 展示时间、Stream、端点、Host、URI、Method、Evidence。
  - 标签行增加 campaign / transport / infrastructure / TTP 字段。
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.test.tsx`
  - 扩充 mock C2 candidate 字段。
  - 新增候选上下文渲染测试。
- `C:\Users\QAQ\Desktop\gshark\docs\c2-sample-analysis.md`
  - 追加第二轮复核优化记录。
- `C:\Users\QAQ\Desktop\gshark\docs\c2-sample-analysis-report-2026-04-29-round2.md`
  - 新增本轮报告。

## 5. 风险与边界

- 本轮没有修改后端检测逻辑，不改变 CS / VShell 候选规则输出。
- 表内上下文块会增加单行高度，但比新增大量横向列更不容易造成前端越界。
- Evidence 文本可能较长，当前采用 `break-all`，后续如果出现超长 JSON 或 base64，建议改为展开详情区。

## 6. 当前收益

本轮后，C2 页面具备两层研判能力：

```text
表内初判：端点 / Host / URI / Method / Evidence / 标签
深入复核：定位包 / 打开关联流
```

这比单纯跳转更适合大量候选命中的场景，分析人员可以先筛掉明显弱信号，再打开高价值流。

## 7. 下一轮建议

### P0：候选行可展开详情

下一步建议把候选行改成：

```text
主行：包号、Family、Channel、类型、置信度、摘要、证据动作
展开行：完整上下文、Evidence、actor hints、transport traits、infra hints、原始字段 JSON
```

这样可以进一步减少表格拥挤。

### P0：CS Host / URI 聚合

增加 CS 聚合视图：

- Host
- URI
- GET 数量
- POST 数量
- 首次时间
- 最后时间
- 平均间隔
- jitter
- 候选 stream 列表

### P1：VShell Stream-level 画像

增加 VShell Stream 聚合视图：

- 架构标记
- 4 字节长度前缀
- 短包 / 长包交替
- 心跳间隔
- WebSocket 参数
- listener / management surface 弱线索

### P1：APT 页消费准备

继续保持当前 C2 页输出技术证据，后续独立 APT 页消费：

- `actorHints`
- `sampleFamily`
- `campaignStage`
- `transportTraits`
- `infrastructureHints`
- `ttpTags`
