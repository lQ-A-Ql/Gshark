# 日期: 2026-04-29
# 署名: Codex

# C2 样本分析页第九轮复查评审、优化与开发报告

## 1. 本轮复查对象

- 上一轮报告：`c2-sample-analysis-report-2026-04-29-round8.md`
- 连续实现说明：`c2-sample-analysis.md`
- 重点实现文件：
  - `frontend/src/app/pages/C2Analysis.tsx`
  - `frontend/src/app/pages/C2Analysis.test.tsx`
  - `frontend/src/app/misc/FilterActions.tsx`

## 2. 对上一轮报告的评审评论

第八轮已经解决了 DNS 与 VShell 聚合行的过滤器语义问题，但复查后确认仍有两个产品化缺口：

1. **聚合行缺少详情展开**：DNS 和 VShell 聚合只能看摘要，无法直接查看时间范围、packet 序列、query type 分布、架构标记和 listener hints 等复核材料。
2. **候选证据表尚未接入协议化过滤器**：聚合行可以复制过滤器，但单条 candidate 仍只能定位包/流；分析人员从候选表出发时还需要手工拼接 host/uri/stream 条件。

因此本轮优先落地 round8 的 P0/P1：聚合行详情展开 + 候选表过滤器联动。

## 3. 本轮完成的开发优化

### 3.1 CS DNS 聚合行展开详情

新增 DNS 聚合详情面板，展开后展示：

- QName
- 时间范围
- 平均间隔
- Jitter
- 最大 label 长度
- 请求/响应比例
- Packet 时间序列
- Query Type 分布
- TXT / NULL / CNAME 形态
- confidence 与 review 标签

该面板用于快速复核 DNS Beacon 的周期性、TXT 偏向、qname 结构和 packet 证据链。

### 3.2 VShell Stream 聚合行展开详情

新增 VShell Stream 详情面板，展开后展示：

- Stream ID
- 协议
- 总包数
- 长度前缀计数
- 短包/长包比例
- transitions
- 心跳与 jitter
- Packet 时间序列
- 架构标记，例如 `l64` / `w64`
- Listener / 管理面提示

该面板用于复核 VShell 的 stream-level 行为，包括架构标记、长度前缀、短长包交替和心跳形态。

### 3.3 候选证据表接入协议化过滤器

候选证据表现在会按 candidate 的 channel / family / indicator 自动挂载 `FilterActions`：

- DNS candidate：生成 `dns.qry.name contains "..."`，必要时附加 TXT 类型过滤。
- TCP / SMB / DoT / VShell candidate：生成 `tcp.stream == N`。
- HTTP / HTTPS candidate：生成 `http.host == "..." && http.request.uri contains "..."`。
- 未识别但存在 streamId 的 candidate：回退到 TCP stream 过滤器。

这样 candidate 行具备完整证据联动：定位包、打开关联流、复制显示过滤器。

### 3.4 UI 细节

- 新增统一的聚合展开按钮，保持与现有 C2 候选展开按钮一致的圆角、过渡与图标风格。
- 详情面板保持白底卡片，避免回退到之前用户指出的“卡片套卡片压迫感”。
- 详情内容按 metric grid + tag 分区呈现，减少横向表格继续膨胀。

## 4. 测试补充

新增/更新前端测试：

- 展开 DNS 聚合详情，校验 `DNS Aggregate Detail`、`dns-beacon-review`、`Packet 时间序列` 与 packet 列表。
- 展开 VShell Stream 详情，校验 `VShell Stream Detail`、`stream-level-review`、packet 列表与 listener hint。
- 候选证据表复制 HTTP 显示过滤器，校验输出：

```text
http.host == "c2.example.test" && http.request.uri contains "/submit.php?id=42"
```

## 5. 验证结果

已通过专项验证：

```text
cd frontend && npx tsc --noEmit
cd frontend && npm test -- C2Analysis
```

专项结果：

```text
C2Analysis.test.tsx: 9 tests passed
```

随后已补充完整验证：

```text
cd frontend && npm test
cd frontend && npm run build
cd backend && go test ./...
```

完整结果：

- 前端全量测试：10 个测试文件、41 项测试全部通过。
- 前端生产构建：通过。
- 后端 Go 全量测试：通过。

## 6. 当前状态

本轮后，C2 页从“聚合摘要 + 过滤器”进一步推进为：

```text
聚合摘要
  -> 展开详情
  -> packet 时间序列
  -> 行为字段分布
  -> 证据联动
  -> 协议化过滤器

候选证据
  -> 定位包
  -> 打开关联流
  -> 协议化过滤器
  -> 详情展开
```

这使 C2 页更接近可用于真实流量复核的分析工作台，而不仅是规则命中列表。

## 7. 下一轮建议

1. 将 DNS / VShell 详情面板进一步接入小型时间线图或 interval sparkline，降低人工观察周期性的成本。
2. 对 CS 误报继续压降：在后端评分中加入组合门槛，例如周期性 + GET/POST 对称 + 低 URI 多样性 + 非浏览器上下文。
3. 候选表增加按 channel / confidence / actorHints 的本地筛选，避免大包下 candidate 列表过长。
4. 开始独立 APT 组织画像页骨架，首个 actor 建议继续沿用 Silver Fox / 银狐。
