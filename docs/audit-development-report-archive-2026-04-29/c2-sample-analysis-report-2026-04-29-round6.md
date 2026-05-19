# 日期: 2026-04-29
# 署名: Codex

# C2 样本分析页第六轮复核、优化与报告

## 1. 本轮目标

上一轮已经完成 CS HTTP 误报抑制，并使 CS Host / URI 聚合画像更干净。本轮继续执行下一步：让 CS Host / URI 聚合行具备证据联动能力。

同时，根据用户要求，本轮将今日所有报告与既有审计开发报告统一存入一个新目录，方便后续审计、交付和归档。

## 2. 复核评论

当前 C2 页面已有三类证据入口：

```text
候选证据表
  -> 定位到包
  -> 打开关联流

候选展开详情
  -> Typed Record Preview

CS Host / URI 聚合画像
  -> Host / URI / GET / POST / interval / jitter / stream / packet
```

复核后发现：CS 聚合画像虽然已经展示 packets / streams，但缺少直接操作按钮。用户仍需要手动复制 packet ID 或回到候选表定位代表包。

聚合行已有 `packets` 字段，因此可以直接用首个 packet 作为代表证据入口，接入统一的 `EvidenceActions`。

## 3. 本轮优化内容

### 3.1 CS 聚合行接入 EvidenceActions

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.tsx`

在 `CSHostURIAggregates` 表的 `Streams / Packets / 摘要 / 证据` 列中新增：

```tsx
<EvidenceActions
  packetId={firstNumber(item.packets)}
  preferredProtocol="HTTP"
  className="pt-1"
/>
```

这样每条 CS Host / URI 聚合行都支持：

- `定位到包`
- `打开关联流`

### 3.2 代表 packet 策略

新增辅助函数：

```ts
function firstNumber(values?: number[]) {
  const value = values?.find((item) => Number.isFinite(item) && item > 0);
  return value ?? 0;
}
```

当前策略：

- 使用 `packets` 中第一个有效 packet 作为代表证据入口。
- preferred protocol 固定为 `HTTP`，因为该聚合只属于 CS HTTP/HTTPS Host / URI 画像。

### 3.3 测试更新

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.test.tsx`

更新点：

- 聚合画像测试会确认存在 `定位到包` 与 `打开关联流` 按钮。
- 候选证据联动测试改为使用 `getAllByRole(...).at(-1)`，避免聚合行和候选行同时存在同名按钮时出现多元素匹配错误。

## 4. 报告归档整合

新增目录：

```text
C:\Users\QAQ\Desktop\gshark\docs\audit-development-report-archive-2026-04-29
```

该目录用于统一存放：

- 今日所有 C2 轮次报告；
- C2 综合实现说明；
- 既有外部模块对比审计报告已从当前归档索引中移除；
- WinRM 解密补丁报告；
- 归档索引 README。

归档方式为复制，不删除原文件，避免破坏原有文档路径引用。

## 5. 当前收益

本轮后，CS Host / URI 聚合画像的工作流变为：

```text
Host / URI 聚合行
  -> 查看 GET / POST / interval / jitter
  -> 定位代表包
  -> 打开代表 HTTP 流
  -> 回到原始证据复核
```

这使聚合画像从“只读统计表”升级为“可回溯证据入口”。

## 6. 风险与边界

- 当前代表 packet 使用 `packets[0]`，不一定是置信度最高或最典型的 packet。
- 后续可以改成：优先 POST、优先首包、优先命中强静态线索、优先低 jitter 周期样本。
- 当前只支持打开代表流，还没有支持一键生成过滤器。

## 7. 下一轮建议

### P0：聚合行过滤器生成

为 CS Host / URI 聚合行增加：

- 复制 Host；
- 复制 URI；
- 生成显示过滤器；
- 生成 HTTP Host / URI 过滤表达式。

### P1：CS DNS Beacon 聚合

新增 DNS 聚合画像：

- qname；
- qtype；
- max label length；
- TXT / NULL / CNAME 分布；
- request / response ratio；
- packet 列表。

### P1：VShell Stream-level 画像

新增 VShell stream 聚合：

- streamId；
- arch marker；
- length-prefix count；
- heartbeat interval；
- short / long alternation；
- websocket params；
- listener / management hints。
