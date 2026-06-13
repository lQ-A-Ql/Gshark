# 日期: 2026-04-29
# 署名: Codex

# C2 样本分析页第三轮复核、优化与报告

## 1. 本轮目标

上一轮已经将 C2 候选的端点、Host、URI、Method、Evidence 与 TTP / 基础设施标签直接显示到候选表中，解决了“不打开流也能初判”的问题。但继续复核后发现：如果后续 CS / VShell 规则继续增多，Evidence、标签和上下文会让每一行默认高度过大，影响批量浏览。

本轮目标：

```text
将候选表从“上下文默认展开”调整为“主行精简 + 可展开详情”
```

## 2. 复核评论

C2 候选表需要同时服务两个场景：

1. 快速浏览大量候选：需要行高低、主信息密度高。
2. 深入复核单条候选：需要完整上下文、完整标签和结构化记录。

上一轮的直接内嵌上下文更偏向第二个场景，但会牺牲第一个场景。本轮因此将信息分层：

- 主行：用于扫视。
- 展开详情：用于复核。

## 3. 本轮优化内容

### 3.1 主行精简

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.tsx`

主行现在保留：

- 包号
- Family
- Channel
- 类型
- 值
- 置信度
- 摘要
- 最多 5 个紧凑标签
- 证据联动按钮
- `展开详情 / 收起详情` 控制

超过 5 个标签时显示：

```text
+N more
```

### 3.2 可展开详情区

新增 `CandidateDetailPanel`，展开后显示：

- `Evidence Context`
  - 时间
  - Stream
  - 端点
  - Host
  - URI
  - Method
  - Evidence
- 完整标签集合
- `Typed Record Preview`
  - packetId
  - streamId
  - time
  - family
  - channel
  - source / destination
  - host / uri / method
  - indicatorType / indicatorValue
  - confidence
  - evidence
  - actorHints
  - sampleFamily
  - campaignStage
  - transportTraits
  - infrastructureHints
  - ttpTags

### 3.3 状态管理

候选表内部新增 `expandedRows` 状态：

- 使用 `Set<string>` 保存展开行。
- row key 由 `family / packetId / streamId / index` 组成。
- 支持多行同时展开，便于横向比较多个候选。

### 3.4 测试调整

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.test.tsx`

测试从：

```text
renders candidate context without opening a stream
```

调整为：

```text
expands candidate context without opening a stream
```

新增断言：

- 默认不显示端点详情。
- 点击 `展开 C2 候选详情 #42` 后显示完整上下文。
- 展开区显示 `Typed Record Preview`。

## 4. 修改文件

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.tsx`
  - 新增 `expandedRows` 状态。
  - 新增 `CandidateDetailPanel`。
  - 新增 `candidateTagValues`、`compactCandidateTags`、`uniqueValues`、`candidatePreviewRecord`。
  - 主行只显示摘要和紧凑标签。
  - 展开行显示完整上下文和 typed record preview。
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.test.tsx`
  - 更新候选上下文测试为展开式交互测试。
- `C:\Users\QAQ\Desktop\gshark\docs\c2-sample-analysis.md`
  - 追加第三轮复核优化记录。
- `C:\Users\QAQ\Desktop\gshark\docs\c2-sample-analysis-report-2026-04-29-round3.md`
  - 新增本轮报告。

## 5. 风险与边界

- 本轮没有修改后端检测逻辑，不影响 C2 候选结果。
- 当前 typed record preview 是只读展示，尚未提供复制按钮。
- 多行同时展开会增加页面高度，但这是用户主动操作；默认表格已经恢复精简。

## 6. 当前收益

本轮后，C2 候选表形成三层工作流：

```text
默认主行：快速扫视候选
展开详情：查看完整上下文和结构化字段
证据联动：定位包或打开关联流
```

这比前两轮更适合后续接入大量 CS / VShell / APT 兼容规则。

## 7. 下一轮建议

### P0：CS Host / URI 聚合视图

下一轮建议开始做 CS 聚合分区：

- Host
- URI
- GET 次数
- POST 次数
- 首次时间
- 最后时间
- 平均间隔
- jitter
- stream 列表
- packet 列表

### P1：VShell Stream-level 画像

将 VShell 候选按 stream 聚合：

- 架构标记
- 4 字节长度前缀
- 短包 / 长包交替
- 心跳间隔
- WebSocket 参数
- listener / management surface 线索

### P1：候选详情操作增强

给展开详情增加：

- 复制 typed record JSON
- 导出当前候选为证据片段
- 从详情区直接生成过滤器
