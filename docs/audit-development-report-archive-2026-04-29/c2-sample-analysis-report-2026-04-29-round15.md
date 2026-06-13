# 日期: 2026-04-29
# 署名: Codex

# C2 样本分析页 + APT 组织画像页 round15 复核、优化与开发报告

## 一、本轮目标

本轮基于最新归档报告 `c2-sample-analysis-report-2026-04-29-round14.md` 继续推进。round14 后两个页面已经具备 C2 技术证据、Host/URI 聚合画像、APT profile 与归因解释雏形；本轮重点是把“可解释”继续推进到“可视化 + 可量化”：

- C2 聚合结果返回原始 interval 数组，并启用前端 `Sparkline` 轻量可视化。
- APT evidence / profile 接入结构化 `scoreFactors`。
- APT Missing Evidence 从静态 profile bucket 判断升级为“真实 evidence + profile bucket”混合判断。
- APT 归因解释面板新增 Evidence Timeline。
- 保持现有 `/api/c2-analysis` 与 `/api/apt-analysis` 路径不变，只扩展响应字段。

## 二、上一轮复核评论

### 1. C2 页面复核

上一轮完成了 `scoreFactors`、响应侧信号与 Host/URI / DNS / Stream 聚合画像，但 `Sparkline` 组件虽已存在，后端未返回 `intervals`，导致周期行为仍停留在文字描述（`avgInterval` / `jitter`）阶段。

本轮修正：

- `C2HTTPEndpointAggregate` 新增 `intervals`。
- `C2DNSAggregate` 新增 `intervals`。
- `C2StreamAggregate` 新增 `intervals`。
- 前端在 Host/URI、DNS detail、VShell stream detail 中展示 `Interval Sparkline`。

### 2. APT 页面复核

上一轮 APT 页面已经能消费 C2 / Threat Hunting / Object Export 证据，但归因解释仍主要依赖 confidence 分段与静态缺失项。该模式的问题是：

- 解释面板不能清楚表达“为什么加分”。
- Missing Evidence 不能区分真实缺失与 profile 预置但未命中的 bucket。
- 证据时间顺序不可见，不利于复盘多阶段投递 → 下载器 → C2 的链路。

本轮修正：

- 新增 `APTScoreFactor` typed model。
- `APTEvidenceRecord` 与 `APTActorProfile` 均支持 `scoreFactors`。
- Attribution Explainer 优先使用 profile-level `scoreFactors` 渲染 Supporting / Weak / Missing / Caveat。
- 新增 Evidence Timeline，按当前 actor 与当前 source tab 过滤后的证据排序展示。

## 三、后端开发内容

### 1. C2 intervals 字段

扩展模型：

```go
type C2HTTPEndpointAggregate struct {
    ...
    Intervals []float64 `json:"intervals,omitempty"`
}

type C2DNSAggregate struct {
    ...
    Intervals []float64 `json:"intervals,omitempty"`
}

type C2StreamAggregate struct {
    ...
    Intervals []float64 `json:"intervals,omitempty"`
}
```

实现规则：

- HTTP Host/URI 聚合：复用同 Host/URI 候选的时间序列，计算相邻正间隔。
- DNS 聚合：复用同 qname 的 DNS observation 时间序列，计算相邻正间隔。
- VShell stream 聚合：从 stream packet 时间序列计算相邻正间隔。
- 新增 `limitFloat64List(values, 64)`，最多返回 64 个 interval，控制 JSON 体积。

### 2. APT scoreFactors 模型

新增模型：

```go
type APTScoreFactor struct {
    Name         string `json:"name"`
    Weight       int    `json:"weight"`
    Direction    string `json:"direction"`
    SourceModule string `json:"source_module,omitempty"`
    Summary      string `json:"summary,omitempty"`
}
```

扩展：`APTEvidenceRecord.ScoreFactors` 与 `APTActorProfile.ScoreFactors`。

### 3. Evidence-level factor 生成

C2 evidence 因子：

- `hfs-download-chain`：+8
- `valleyrat-family-hint`：+7
- `winos-family-hint`：+7
- `gh0st-family-hint`：+6
- `https-c2`：+3
- `periodic-callback`：+4
- `silverfox-case-port-weak`：+2，并在 summary 中标记为 weak observation

Threat Hunting evidence 因子：`yara-hit` +8、`rule-match` +5、`anomaly` +3。

Object Export evidence 因子：`object-executable` +5、`object-script` +4、`object-archive` +3、`object-suspicious-document` +3。

### 4. Profile-level factor 汇总与 Missing Evidence

新增 `finalizeAPTAnalysis()`：

- 对 evidence 补全 Silver Fox 兼容 hint。
- 汇总 actor / sample family / campaign stage / transport / infrastructure / TTP bucket。
- 汇总 evidence-level scoreFactors 到 profile-level。
- 动态生成 missing factor：`missing-sample-family`、`missing-delivery-chain`、`missing-c2-evidence`、`missing-threat-hunting-evidence`、`missing-object-evidence`。
- 当只有端口弱观察时生成 negative caveat：`port-only-weak-observation`。

## 四、前端开发内容

### 1. 类型与 bridge

扩展 TypeScript 类型：

```ts
C2HTTPEndpointAggregate.intervals?: number[]
C2DNSAggregate.intervals?: number[]
C2StreamAggregate.intervals?: number[]

APTScoreFactor {
  name: string
  weight: number
  direction: "positive" | "negative" | "missing" | string
  sourceModule?: string
  summary?: string
}

APTEvidenceRecord.scoreFactors?: APTScoreFactor[]
APTActorProfile.scoreFactors?: APTScoreFactor[]
```

`wailsBridge.ts` 已映射 `intervals`、`score_factors` 与 `source_module`。

### 2. C2 Sparkline 可视化

前端新增/接入 `IntervalSparkline` 包装组件：

- CS Host/URI 聚合行展示 interval sparkline。
- CS DNS 聚合详情展示 interval sparkline。
- VShell stream 聚合详情展示 interval sparkline。
- `intervals` 不足 2 个点时不显示空图。

### 3. APT Attribution Explainer

解释面板现在优先使用 `profile.scoreFactors`：

- positive 且 weight ≥ 5 → Supporting Evidence。
- positive 且 weight < 5 → Weak Observations。
- missing → Missing Evidence。
- negative → Suppression / Caveat。

当旧数据没有 `scoreFactors` 时，仍回退到 confidence 分段与动态 Missing Evidence。

### 4. Evidence Timeline

新增轻量 Evidence Timeline：

- 位于 Attribution Explainer 下方。
- 使用当前 actor + 当前 evidence source tab 的证据。
- 按 `time` 排序。
- 无 `time` 的 evidence 放到末尾，并显示 `no-time`。
- 最多展示前 50 条。
- 每条展示：time、sourceModule、evidenceType、confidence、summary、tags、sampleFamily、campaignStage。

## 五、测试与验证

### 已执行命令

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npx tsc --noEmit
npm test -- C2Analysis AptAnalysis
npm test
npm run build

cd C:\Users\QAQ\Desktop\gshark\backend
go test ./internal/engine -run 'C2|APT'
go test ./internal/transport -run 'C2|APT'
go test ./...
```

### 验证结果

- `npx tsc --noEmit`：通过。
- `npm test -- C2Analysis AptAnalysis`：通过，11 tests passed。
- `npm test`：通过，43 tests passed。
- `npm run build`：通过。
- `go test ./internal/engine -run 'C2|APT'`：通过。
- `go test ./internal/transport -run 'C2|APT'`：通过。
- `go test ./...`：通过。

### 新增/增强测试点

- C2 Host/URI 聚合 raw intervals：`[60, 60, 60]`。
- C2 DNS 聚合 raw intervals：`[60, 60]`。
- VShell stream aggregate raw intervals：`[10, 10, 10]`。
- APT evidence-level scoreFactors：HFS + Winos 等因子可生成。
- C2 页面显示 `Interval Sparkline`。
- APT 页面显示 `Evidence Timeline`、profile score factors 与 Missing Evidence。

## 六、风险与后续建议

### 当前风险

- VShell stream 聚合依赖 streamData 已形成；如果某些样本只有单点 TCP 形态而未形成 stream aggregate，则不会出现 sparkline，这是符合预期的弱信号保守策略。
- APT `scoreFactors` 仍是解释辅助，不应被 UI 展示为强归因 verdict。
- Threat Hunting / Object Export 证据只有在文本中出现 Silver Fox / ValleyRAT / Winos / Gh0st / HFS / Rejetto 相关 hint 时才自动挂到 Silver Fox profile，避免无依据地把所有对象归入银狐。

### 下一轮建议

1. APT 页面增加 profile-level 总分解释：将 positive / negative / missing 分数汇总为“候选兼容度”，但仍避免输出强 verdict。
2. C2 页面将 sparkline 与 `avgInterval` / `jitter` 组合为更明确的“周期稳定度”小组件。
3. APT Timeline 支持分页与按 stage 分组。
4. 引入更多 actor profile 时，将 `applySilverFoxEvidenceHints()` 泛化为 actor registry / actor matcher。
5. 对 Threat Hunting / Object Export evidence 增加更强的 source link，支持从 APT 页面反跳到对象详情或规则命中详情。
