# 日期: 2026-04-29
# 署名: Codex

# C2 样本分析页第十一轮复查评论、优化与开发报告

## 1. 本轮目标

本轮承接第十轮“降低 CS 误报”的结果，重点解决一个可复核性缺口：后端已经采用多信号评分来减少误报，但前端 Host/URI 聚合画像只展示总置信度和摘要，用户无法直接看到该聚合是由哪些评分因子支撑的。

因此本轮目标为：

- 将 CS Host/URI 聚合候选的评分因子从后端结构化透出。
- 在 C2 样本分析页的 CS Host/URI 聚合画像中展示 scoring signals。
- 用前后端测试覆盖信号透传与渲染。
- 保持第十轮的低误报策略不回退。

## 2. 对上一轮报告的复查评论

第十轮报告判断正确：误报率高的根因不在前端展示，而在后端早期把静态 profile-like URI / Header、浏览器轮询、普通 TCP 周期流等弱现象直接提升为 CS 候选。上一轮已经把这些弱信号降级为评分因子，并建立了组合门槛。

本轮复查认为第十轮仍有两个后续问题：

1. 评分因子不可见会影响人工复核。即使候选已经更稳健，用户仍需要知道命中的依据是 `stable-interval`、`get-post-tasking-shape` 还是 `browser-context-penalty`。
2. 前端若只显示 confidence，后续很难解释“为什么它是 CS 候选 / 为什么某个浏览器 polling 没命中”。因此应先把信号标签作为结构化字段输出，下一轮再扩展为更完整的 why-hit / suppression 解释面板。

## 3. 本轮代码变更

### 3.1 后端模型扩展

文件：`C:\Users\QAQ\Desktop\gshark\backend\internal\model\types.go`

- 在 `C2HTTPEndpointAggregate` 中新增：
  - `SignalTags []string json:"signal_tags,omitempty"`
- 该字段用于承载 Host/URI 聚合背后的评分因子，例如：
  - `stable-interval`
  - `get-post-tasking-shape`
  - `non-browser-context`
  - `browser-context-penalty`
  - `default-profile-like`
  - `high-volume-repeat`

### 3.2 后端聚合逻辑增强

文件：`C:\Users\QAQ\Desktop\gshark\backend\internal\engine\tool_c2.go`

- 在 `c2EndpointAggregateWork` 中新增 `signalTags` 暂存字段。
- `buildCSHostURIAggregates` 聚合候选时收集 `candidate.Tags`。
- 输出 `C2HTTPEndpointAggregate` 时对标签执行：
  - 去重：`uniqueStrings(...)`
  - 截断：`limitStringList(..., 12)`
- 新增 `limitStringList`，避免聚合行标签无限膨胀。

设计结果：Host/URI 聚合现在不仅输出摘要和置信度，也输出可审计的“命中组成”。

### 3.3 前端类型扩展

文件：`C:\Users\QAQ\Desktop\gshark\frontend\src\app\core\types.ts`

- 在 `C2HTTPEndpointAggregate` 中新增：
  - `signalTags?: string[]`

保持与后端 `signal_tags` 字段的前端 camelCase 数据模型一致。

### 3.4 前端 UI 展示

文件：`C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.tsx`

- 在 CS Host/URI 聚合画像行的摘要区域增加 `Scoring Signals` 证据块。
- 当 `signalTags` 非空时展示标签列表。
- 样式采用 rose 浅色证据块，不引入卡片套卡片式重布局，保持当前 C2 页白底、轻量边框、可读性优先的风格。

该区域用于快速回答：

- 该 Host/URI 为什么进入 CS 聚合画像？
- 当前置信度主要来自行为周期、GET/POST 互补还是上下文特征？
- 是否存在 `browser-context-penalty` 这类抑制因子？

### 3.5 测试增强

文件：`C:\Users\QAQ\Desktop\gshark\backend\internal\engine\c2_analysis_test.go`

- 在 `TestBuildC2SampleAnalysisBuildsCSHostURIAggregates` 中增加 `SignalTags` 断言。
- 校验稳定周期 + GET/POST 互补样本应至少透出：
  - `stable-interval`
  - `get-post-tasking-shape`
- 新增辅助函数 `stringSliceContains`。

文件：`C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.test.tsx`

- Mock 的 Host/URI 聚合样本增加 `signalTags`。
- `renders CS Host and URI aggregation profile` 测试增加断言：
  - 渲染 `Scoring Signals`
  - 渲染 `stable-interval`
  - 渲染 `get-post-tasking-shape`
  - 渲染 `non-browser-context`

## 4. 验证结果

本轮执行的验证命令如下：

```powershell
cd C:\Users\QAQ\Desktop\gshark\backend; go test ./internal/engine -run C2
cd C:\Users\QAQ\Desktop\gshark\frontend; npm test -- C2Analysis
cd C:\Users\QAQ\Desktop\gshark\frontend; npx tsc --noEmit
cd C:\Users\QAQ\Desktop\gshark\frontend; npm test
cd C:\Users\QAQ\Desktop\gshark\frontend; npm run build
cd C:\Users\QAQ\Desktop\gshark\backend; go test ./...
```

结果：

- 后端 C2 专项测试通过。
- 前端 C2Analysis 专项测试通过：9 项通过。
- 前端 TypeScript 类型检查通过。
- 前端全量测试通过：10 个测试文件、41 项测试通过。
- 前端生产构建通过。
- 后端全量 Go 测试通过。

`go test ./...` 期间后端 transport 测试生成的临时 `echo-demo-test-*` 插件目录已安全清理，仅删除未跟踪临时目录。

## 5. 当前效果

CS Host/URI 聚合画像现在具备更完整的证据链：

```text
Host / URI / Channel / Confidence
  -> Method distribution
  -> Avg interval / jitter
  -> Summary
  -> Scoring Signals
       stable-interval
       get-post-tasking-shape
       non-browser-context
       ...
  -> Streams / Packets
  -> 定位包 / 打开关联流 / 复制过滤器
```

相比上一轮，本轮没有改变候选准入策略，而是在不提高误报率的前提下提高了“可解释性”。这对于后续继续微调 CS 规则非常重要：用户可以直接看到命中因子，开发侧也能根据真实样本反馈调整各因子权重。

## 6. 风险与边界

- `signalTags` 当前仍是标签级解释，不是完整规则树。它能说明命中因子，但还不能说明每个因子的分值贡献。
- `browser-context-penalty` 若未来进入聚合标签，也需要在 UI 上区分“正向加分”和“负向抑制”，否则用户可能误解为命中证据。
- 当前聚合仍主要基于请求侧。响应侧稳定性、状态码、body size、请求/响应配对尚未进入评分。

## 7. 下一轮建议

建议第十二轮继续做 CS 误报治理与解释面板：

1. 新增 Host/URI 聚合详情中的 `Why hit / Why suppressed` 面板。
2. 将 `signalTags` 扩展为结构化 `scoreFactors`，包含：
   - label
   - direction: positive / negative
   - weight
   - evidence
3. 加入响应侧信号：
   - 状态码稳定性
   - 响应体大小稳定性
   - 请求/响应时序配对
4. 在前端增加 CS 候选本地过滤器：按 channel、confidence、signal tag、host/uri 关键字过滤。
5. 为 `browser-context-penalty` 增加显式 UI 标识，避免把抑制信号误读为支持信号。
