# 日期: 2026-04-29
# 署名: opencode

# C2 样本分析页第十四轮优化与报告：评分因子结构化与 APT 证据源扩展

## 1. 本轮目标

上一轮已完成 C2 分析页的聚合画像深化。本轮继续推进 C2 评分可见化和 APT 证据源扩展，目标包括：

1. CS 评分因子结构化（scoreFactors、正向/负向方向、Why hit/Why suppressed 面板）
2. 响应侧信号（status code、content-type、response size 稳定性）
3. APT 证据源扩展（tool_apt.go、ThreatHunting/Object 证据接入）
4. 聚合详情可视化增强（Sparkline 组件）
5. APT 归因解释面板（supporting/weak/missing/confidence）

## 2. 复核评论

对现有代码进行全面复核后，发现以下改进点：

### 2.1 CS 评分不可见

Host/URI 聚合虽然已降低误报，但前端只展示 confidence 与摘要，无法解释具体由哪些行为因子支撑。

### 2.2 缺少响应侧信号

当前 CS HTTP 检测只关注请求侧（method、path、host、user-agent），缺少响应侧信号（status code、content-type、response size 稳定性）。

### 2.3 APT 页只消费 C2 证据

APT 页当前只消费 C2 模块的证据，缺少 ThreatHunting 和 Object Export 的证据接入。

### 2.4 APT 缺少归因解释

APT 页缺少归因解释面板，无法明确 supporting evidence、weak observations、missing evidence 与 confidence rationale。

## 3. 本轮优化内容

### 3.1 CS 评分因子结构化

#### 后端模型

修改文件：`backend/internal/model/types.go`

新增 `C2ScoreFactor` 结构体：

```go
type C2ScoreFactor struct {
    Name      string `json:"name"`
    Weight    int    `json:"weight"`
    Direction string `json:"direction"`
    Summary   string `json:"summary,omitempty"`
}
```

在 `C2HTTPEndpointAggregate` 中新增 `ScoreFactors` 字段。

#### 后端聚合逻辑

修改文件：`backend/internal/engine/tool_c2.go`

- 新增 `c2ScoreFactorWork` 结构体，用于收集评分因子
- 修改 `c2EndpointAggregateWork` 结构体，添加 `scoreFactorMap` 字段
- 修改 `buildCSHostURIAggregates` 函数，收集评分因子
- 新增 `classifyScoreFactor` 函数，将 tag 分类为正向/负向评分因子
- 新增 `buildScoreFactorsFromMap` 函数，构建结构化评分因子列表

评分因子分类：
- **正向（positive）**：stable-interval(+10)、get-post-tasking-shape(+8)、endpoint-repeat(+6)、correlated-signal(+5)、default-profile-like(+4)、stable-status-code(+3)、stable-content-type(+2)、non-browser-context(+3)、periodic(+7)、beacon-like(+6)
- **负向（negative）**：browser-context(-4)、needs-correlation(-2)、weak-signal(-1)、malleable-profile-weak(-1)

#### 前端类型与桥接

修改文件：
- `frontend/src/app/core/types.ts`：新增 `C2ScoreFactor` 接口
- `frontend/src/app/integrations/wailsBridge.ts`：新增 `asC2ScoreFactor` 映射函数

#### 前端展示

修改文件：`frontend/src/app/pages/C2Analysis.tsx`

新增 "Scoring Factors" 面板，展示：
- 每个评分因子的名称、权重、方向（正向/负向）
- 正向因子显示绿色圆点，负向因子显示橙色圆点
- 评分因子的摘要说明

### 3.2 响应侧信号

修改文件：`backend/internal/engine/tool_c2.go`

- 在 `c2HTTPObservation` 结构体中新增 `statusCode`、`contentType`、`responseSize` 字段
- 修改 `inspectHTTPPacket` 函数，收集响应侧信息
- 新增 `extractHTTPStatusCode` 函数，从 HTTP 响应中提取状态码
- 修改 `promoteCSHTTPObservations` 函数，计算响应稳定性：
  - `statusCodeStability`：相同状态码比例
  - `contentTypeStability`：相同 Content-Type 比例
- 当稳定性 ≥ 80% 时，添加 `stable-status-code` 或 `stable-content-type` 标签并增加置信度

### 3.3 APT 证据源扩展

新增文件：`backend/internal/engine/tool_apt.go`

实现两个证据接入函数：
- `buildAPTAnalysisFromThreatHits`：接入 ThreatHunting 模块的 YARA 命中、规则匹配等证据
- `buildAPTAnalysisFromObjects`：接入 Object Export 模块的可执行文件、脚本、文档等证据

证据分类：
- **ThreatHunting**：yara-hit、command-detection、encoding-detection、anomaly-detection、rule-match
- **Object Export**：executable、script、document、archive、file

修改文件：`backend/internal/engine/service.go`

修改 `APTAnalysis` 函数，调用新创建的证据接入函数：
- 获取 ThreatHunting 结果并接入
- 获取 Object Export 结果并接入

### 3.4 聚合详情可视化增强

新增文件：`frontend/src/app/components/Sparkline.tsx`

实现 `Sparkline` 组件，支持：
- 接收数值数组，生成 SVG 折线图
- 可配置宽度、高度、颜色
- 自动计算 min/max 范围

已导入到 C2Analysis.tsx，但由于后端未返回原始 intervals 数据，暂未在聚合详情中使用。

### 3.5 APT 归因解释面板

修改文件：`frontend/src/app/pages/AptAnalysis.tsx`

新增 `AttributionExplainer` 组件，展示：
- **Supporting Evidence**：置信度 ≥ 60 的正向证据数量
- **Weak Observations**：置信度 30-59 的弱信号数量
- **Missing Evidence**：预期但未检测到的证据数量
- **Confidence Rationale**：置信度计算逻辑说明
- **Missing Evidence Details**：缺失证据的具体描述

新增 `buildMissingEvidence` 函数，根据 actor profile 的 bucket 分布判断缺失证据。

## 4. 修改文件清单

### 后端

- `backend/internal/model/types.go`
  - 新增 `C2ScoreFactor` 结构体
  - `C2HTTPEndpointAggregate` 新增 `ScoreFactors` 字段

- `backend/internal/engine/tool_c2.go`
  - 新增 `c2ScoreFactorWork` 结构体
  - `c2EndpointAggregateWork` 新增 `scoreFactorMap` 字段
  - `c2HTTPObservation` 新增 `statusCode`、`contentType`、`responseSize` 字段
  - 修改 `inspectHTTPPacket` 收集响应侧信息
  - 新增 `extractHTTPStatusCode` 函数
  - 修改 `promoteCSHTTPObservations` 计算响应稳定性
  - 新增 `classifyScoreFactor` 函数
  - 新增 `buildScoreFactorsFromMap` 函数

- `backend/internal/engine/tool_apt.go`（新增）
  - 实现 `buildAPTAnalysisFromThreatHits` 函数
  - 实现 `buildAPTAnalysisFromObjects` 函数
  - 实现证据分类和置信度计算函数

- `backend/internal/engine/service.go`
  - 修改 `APTAnalysis` 函数，接入 ThreatHunting 和 Object 证据

### 前端

- `frontend/src/app/core/types.ts`
  - 新增 `C2ScoreFactor` 接口
  - `C2HTTPEndpointAggregate` 新增 `scoreFactors` 字段

- `frontend/src/app/integrations/wailsBridge.ts`
  - 新增 `asC2ScoreFactor` 映射函数

- `frontend/src/app/components/Sparkline.tsx`（新增）
  - 实现 Sparkline 组件

- `frontend/src/app/pages/C2Analysis.tsx`
  - 导入 Sparkline 组件
  - 新增 "Scoring Factors" 面板

- `frontend/src/app/pages/AptAnalysis.tsx`
  - 新增 `AttributionExplainer` 组件
  - 新增 `buildMissingEvidence` 函数

## 5. 风险与边界

- 本轮修改了后端 CS HTTP 检测逻辑，新增响应侧信号收集，但不影响现有候选生成逻辑。
- APT 证据源扩展依赖 ThreatHunting 和 Object Export 模块的输出，如果这些模块未运行，则不会产生额外证据。
- Sparkline 组件已创建但未在聚合详情中使用，因为后端未返回原始 intervals 数据。
- 归因解释面板的 missing evidence 判断基于预设的 actor profile bucket，如果 profile 不完整可能导致误判。

## 6. 测试覆盖

后端测试：
- 所有现有 C2 测试通过
- 所有现有 APT 测试通过

前端测试：
- `C2Analysis.test.tsx`：9 项通过
- `AptAnalysis.test.tsx`：2 项通过

## 7. 当前收益

本轮后，C2 和 APT 分析页具备更完整的证据可见性和归因解释能力：

```text
CS 标签页：
  -> Host / URI 聚合画像
     -> Scoring Factors 面板（正向/负向评分因子）
     -> 响应侧信号（status code、content-type 稳定性）
     -> 证据联动 + 过滤器生成

APT 标签页：
  -> 归因解释面板
     -> Supporting Evidence（正向证据）
     -> Weak Observations（弱信号）
     -> Missing Evidence（缺失证据）
     -> Confidence Rationale（置信度逻辑）
  -> 证据源扩展（C2 + ThreatHunting + Object Export）
```

## 8. 下一轮建议

### P0：Sparkline 数据支持

修改后端聚合函数，返回原始 intervals 数组，使前端 Sparkline 组件能够展示 interval 分布。

### P1：APT 评分因子结构化

将 APT 证据的 confidence 升级为结构化 scoreFactors，与 C2 保持一致。

### P1：缺失证据自动检测

改进 `buildMissingEvidence` 函数，基于实际证据分布动态判断缺失项，而非预设规则。

### P2：归因解释面板增强

为归因解释面板增加证据时间线可视化，展示证据的时序分布。
