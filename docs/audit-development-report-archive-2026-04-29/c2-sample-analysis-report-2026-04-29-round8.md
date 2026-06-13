# 日期: 2026-04-29
# 署名: Codex

# C2 样本分析页第八轮复查评审、优化与开发报告

## 1. 本轮复查对象

- 最新归档报告：`c2-sample-analysis-report-2026-04-29-round7.md`
- 当前连续说明：`c2-sample-analysis.md`
- 重点实现文件：
  - `frontend/src/app/pages/C2Analysis.tsx`
  - `frontend/src/app/misc/FilterActions.tsx`
  - `frontend/src/app/pages/C2Analysis.test.tsx`

## 2. 对上一轮报告的评审评论

上一轮报告中提出的 P0/P1 建议是合理的，尤其是：

1. **DNS 聚合行应生成 DNS 专用过滤器**：round7 已经生成 DNS 聚合画像，但前端复用 HTTP Host 过滤器会把 qname 错生成 `http.host == "..."`，不利于在 Wireshark/tshark 中直接复核 DNS Beacon 证据。
2. **VShell Stream 聚合行应生成 stream 过滤器**：VShell 画像的关键定位单位是 `tcp.stream`，仅能定位代表包还不够，分析人员需要一键复制 `tcp.stream == N` 来复核完整会话。
3. **过滤器生成需要走统一组件而不是新增零散按钮**：沿用 `FilterActions` 扩展协议感知能力，避免 C2 页继续堆叠一次性 UI 逻辑。

本轮确认 round7 的 Host/URI 聚合、DNS 聚合、VShell Stream 聚合与 LRU 缓存设计均可继续保留；主要问题集中在“证据联动到过滤器”的语义准确性。

## 3. 本轮完成的开发优化

### 3.1 FilterActions 协议化

`FilterActions` 从 HTTP 专用扩展为协议感知组件，新增：

- `protocol?: "http" | "dns" | "tcp"`
- `qname?: string`
- `dnsQueryType?: string`
- `streamId?: number`

同时保留原有 HTTP 行为：

- 复制 Host
- 复制 URI
- 生成 `http.host == "..." && http.request.uri contains "..."`

### 3.2 DNS 聚合行过滤器修正

CS DNS Beacon 聚合行现在生成 DNS 专用显示过滤器：

```text
dns.qry.name contains "abcdefg.example.com" && dns.qry.type == 16
```

其中：

- `dns.qry.name contains` 用于 qname 复核。
- 当聚合行存在 TXT 命中时附加 `dns.qry.type == 16`，优先帮助分析人员复核 DNS TXT Beacon。
- DNS 行按钮文案改为 `QName`，避免与 HTTP Host 混淆。

### 3.3 VShell Stream 聚合行过滤器

VShell Stream 聚合行新增 TCP stream 过滤器：

```text
tcp.stream == 9
```

该能力直接服务于 VShell 的 stream-level 画像复核，适用于：

- 架构标记 `l64` / `w64`
- 4 字节长度前缀
- 短包/长包交替
- 心跳间隔
- WebSocket / TCP listener 候选流

### 3.4 过滤器值安全转义

新增显示过滤器值转义逻辑：

- `\` 转义为 `\\`
- `"` 转义为 `\"`

避免 host、uri、qname 中出现特殊字符时生成不可用或语义错误的过滤器。

### 3.5 空 family 结构补齐

`EMPTY_FAMILY` 与测试构造中的 family 默认结构补齐：

- `dnsAggregates: []`
- `streamAggregates: []`

后续新增聚合分区时，空态结构更稳定。

## 4. 测试补充

本轮新增/更新前端测试：

- DNS 聚合行复制过滤器：校验输出 `dns.qry.name contains "abcdefg.example.com" && dns.qry.type == 16`
- VShell Stream 聚合行复制过滤器：校验输出 `tcp.stream == 9`
- mock `navigator.clipboard.writeText`，确保复制动作可回归。
- VShell mock 数据补充 stream aggregate 样本，覆盖 `l64`、长度前缀、心跳与 listener hint 展示链路。

## 5. 验证结果

已通过：

```text
cd frontend && npx tsc --noEmit
cd frontend && npm test -- C2Analysis
```

专项结果：

```text
C2Analysis.test.tsx: 7 tests passed
```

随后已补充完整验证：

```text
cd frontend && npm test
cd frontend && npm run build
cd backend && go test ./...
```

完整结果：

- 前端全量测试：10 个测试文件、39 项测试全部通过。
- 前端生产构建：通过。
- 后端 Go 全量测试：通过。

## 6. 当前状态

本轮后，C2 分析页证据联动链路更完整：

```text
CS / HTTP 聚合：Host、URI、HTTP 显示过滤器
CS / DNS 聚合：QName、DNS qname + TXT 类型显示过滤器
VShell / Stream 聚合：Stream 编号、tcp.stream 显示过滤器
```

这使页面输出的候选证据可以更快回到抓包工具中复核，降低误用 HTTP 过滤器分析 DNS 聚合的风险。

## 7. 下一轮建议

1. 为 DNS 和 VShell 聚合行增加“展开详情”，显示 packet 时间序列、间隔分布和样本 payload 摘要。
2. 将 C2 候选表也接入协议化 `FilterActions`，按 candidate 的 channel 自动生成 HTTP/DNS/TCP 过滤器。
3. 开始实现独立 APT 组织画像页的骨架，首个 actor 可使用 Silver Fox / 银狐，消费当前 C2 技术证据字段。
4. 对 CS 规则继续降低误报：增加多信号门槛，例如周期性 + GET/POST 对称 + 低 URI 多样性 + 非浏览器上下文组合评分。
