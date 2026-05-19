# 日期: 2026-04-29
# 署名: Codex

# C2 样本分析页第十轮复查评审、优化与开发报告

## 1. 本轮复查对象

- 上一轮报告：`c2-sample-analysis-report-2026-04-29-round9.md`
- 重点实现文件：
  - `backend/internal/engine/tool_c2.go`
  - `backend/internal/engine/c2_analysis_test.go`

## 2. 对上一轮报告的评审评论

第九轮已经补齐前端证据展开和 candidate 过滤器联动，C2 页的复核体验已基本可用。本轮复查重点转向上一轮 P0：**CS 误报压降**。

复查后确认当前 CS 误报主要来自三类后端规则过宽：

1. **静态 HTTP profile 线索即时出候选**：例如单个 `POST /submit.php?id=...` 会直接生成 `http-beacon-shape`，容易把普通表单、接口提交或埋点请求误认为 CS。
2. **Host/URI 重复聚合允许 high-volume 单信号提升**：仅凭同一 endpoint 高频重复即可提升，容易误报浏览器轮询、前端 polling、监控接口和长轮询。
3. **任意 TCP 周期流可提升为 CS beacon interval**：非 HTTP/TLS 的普通 TCP 心跳也可能进入 CS 候选，和 VShell/自定义业务心跳存在边界混淆。

因此本轮将 CS HTTP 检测改为组合评分，而不是单点命中。

## 3. 本轮完成的开发优化

### 3.1 静态 HTTP 线索不再即时出候选

`strongCSHTTPStaticSignal` 仍保留为 profile-like 特征识别函数，但 `inspectHTTPPacket` 不再因为单条静态 URI/Header 命中就直接调用 `emitCSHTTPCandidate`。

现在静态线索只作为后续 Host/URI 聚合评分中的一个加权因子：

- `default-profile-like`
- `post-result-shape`
- `get-tasking-shape`

这样可以避免单包 `submit` / `id=` 类型请求直接污染候选表。

### 3.2 Host/URI 聚合改为多信号评分

`promoteCSHTTPObservations` 现在按以下信号组合评分：

- 稳定周期：`stable-interval`
- GET / POST 互补：`get-post-tasking-shape`
- 默认 profile-like 形态：`default-profile-like`
- 高频重复：`high-volume-repeat`
- 非浏览器上下文：`non-browser-context`
- 浏览器上下文惩罚：`browser-context-penalty`

提升门槛：

```text
signalScore >= 4
且至少具备 stable interval 或 GET/POST 互补之一
```

额外约束：

```text
如果全部请求都来自明显浏览器 UA，则必须同时满足：
  stable interval
  GET/POST 互补
  default-profile-like 形态
否则不提升为 CS HTTP 候选
```

这会明显降低普通浏览器轮询和前端 polling 的误报。

### 3.3 高频重复不再单独作为强信号

原逻辑中 `len(group) >= 6` 可作为 high-volume 单信号通过初筛。本轮调整为：

- high-volume 阈值提高到 `>= 8`
- high-volume 只加分，不再单独决定提升
- 必须与周期、GET/POST、静态形态或非浏览器上下文组合

### 3.4 周期性 TCP 流增加 CS 适用性门槛

新增 `c2CSPeriodicStreamEligible`：

- HTTP-like 包、TLS 或 443 流量才允许继续作为 CS HTTP/HTTPS 周期候选。
- 原始 TCP 周期流不再直接提升为 CS `beacon-interval`。
- 如果周期流全部是浏览器 UA 且缺少 GET/POST + profile-like 组合，则抑制。

这样 CS 周期检测和 VShell / 原始 TCP 心跳检测边界更清晰。

### 3.5 CS notes 更新

CS notes 更新为明确说明：

- 一次性普通 HTTP 请求会被抑制。
- 浏览器轮询会被抑制。
- HTTP 候选采用多信号门槛。
- 静态 URI/Header、重复 Host/URI、周期性与非浏览器上下文需要组合复核。

## 4. 测试补充

新增/更新后端测试：

1. `TestBuildC2SampleAnalysisDetectsCSHTTPAndDNS`
   - 更新为重复 GET/POST + 稳定周期 + DNS TXT 的组合样例。
   - 不再依赖单条静态 POST 即时出候选。

2. `TestBuildC2SampleAnalysisSuppressesBrowserPollingAsCSHTTP`
   - 构造 8 条稳定间隔的浏览器 UA `GET /api/poll`。
   - 断言不会生成 `http-beacon-shape` 或 `beacon-interval`。
   - 断言不会形成 CS Host/URI 聚合。

3. `TestBuildC2SampleAnalysisSuppressesRawTCPPeriodicAsCS`
   - 构造普通 TCP 60 秒周期流。
   - 断言不会生成 CS `beacon-interval`。

## 5. 验证结果

已通过专项验证：

```text
cd backend && go test ./internal/engine -run C2
cd frontend && npm test -- C2Analysis
```

专项结果：

```text
backend/internal/engine C2 tests passed
C2Analysis.test.tsx: 9 tests passed
```

随后已补充完整验证：

```text
cd frontend && npx tsc --noEmit
cd frontend && npm test
cd frontend && npm run build
cd backend && go test ./...
```

完整结果：

- 前端类型检查：通过。
- 前端全量测试：10 个测试文件、41 项测试全部通过。
- 前端生产构建：通过。
- 后端 Go 全量测试：通过。

## 6. 当前状态

本轮后，CS HTTP 候选从“静态单点或重复单点提升”变为“多信号组合提升”：

```text
静态 profile-like 线索
  + 周期性
  + GET/POST 互补
  + 非浏览器上下文
  + 高频重复
  - 浏览器上下文惩罚
```

预期收益：

- 降低浏览器 polling 误报。
- 降低普通表单/API POST 误报。
- 降低原始 TCP 心跳误报到 CS 的概率。
- 保留对真实 CS HTTP/HTTPS Beacon 组合行为的发现能力。

## 7. 下一轮建议

1. 在前端 CS Host/URI 聚合详情中展示后端评分因子，例如 `stable-interval`、`get-post-tasking-shape`、`browser-context-penalty`。
2. 为 CS 聚合增加“误报抑制说明”或“为什么命中”展开区，便于用户理解评分。
3. 后端继续加入响应侧信号：状态码稳定性、响应体大小稳定性、GET/POST 请求-响应角色配对。
4. 候选表增加本地筛选：family、channel、confidence、tag、actorHints。
