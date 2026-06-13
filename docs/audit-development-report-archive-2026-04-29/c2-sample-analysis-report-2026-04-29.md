# 日期: 2026-04-29
# 署名: Codex

# C2 样本分析页下一轮复核、优化与报告

## 1. 本轮复核结论

本轮复核对象为 `C2 样本分析` 专题页及其前后端链路。上一轮已经完成 CS / VShell 同级标签页、C2 候选规则、APT 兼容字段、前后端结构化模型与基础测试。本轮重点检查的是：这些候选结果是否能被分析人员快速回溯到原始证据。

复核结论：

- 页面骨架、规则候选和缓存链路基本达标。
- `C2IndicatorRecord` 中已经包含 `packetId`、`streamId`、`channel`、`method` 等证据定位字段。
- 但候选证据表此前只展示字段，不提供直接跳包 / 跳流入口，导致实战研判时需要人工在工作区重新定位。
- 项目内已有 `EvidenceActions` 组件，已经统一实现 `定位到包` 与 `打开关联流`，适合直接复用，避免 C2 页再写一套孤立按钮。

## 2. 本轮优化内容

### 2.1 候选证据表接入证据联动

已在 `C2Analysis.tsx` 的候选证据表中新增 `证据联动` 列，每条 C2 候选均可执行：

- `定位到包`
  - 使用 `locatePacketById(packetId)`。
  - 定位完成后跳回主工作区 `/`。
- `打开关联流`
  - 使用 `preparePacketStream(packetId, preferredProtocol)`。
  - 根据返回协议跳转到 `/http-stream`、`/tcp-stream` 或 `/udp-stream`。

这样 C2 页面不再只是统计面板，而是能形成：

```text
候选规则命中 -> 候选证据表 -> 原始包定位 -> 流追踪复核
```

### 2.2 协议偏好推断

新增 C2 候选到流追踪的协议偏好函数：

- `method` 存在、`http`、`websocket`、`doh`：优先 HTTP。
- `dns`、`kcp_udp`、`udp`：优先 UDP。
- `tcp`、`smb`、`dot`：优先 TCP。
- 其它场景返回 `undefined`，交由 Sentinel 上下文按包本身协议推断。

这里特别保留了对 `https` 的保守处理：如果没有 HTTP method，不强制打开 HTTP 流，避免 TLS 原始流与 HTTP 解码页语义混淆。

### 2.3 前端回归测试

`C2Analysis.test.tsx` 已补充：

- mock `useNavigate`。
- mock `locatePacketById` 与 `preparePacketStream`。
- 验证点击 `定位到包` 会调用 `locatePacketById(42)` 并跳转 `/`。
- 验证点击 `打开关联流` 会调用 `preparePacketStream(42, "HTTP")` 并跳转 `/http-stream`。

## 3. 修改文件

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.tsx`
  - 候选证据表新增 `EvidenceActions`。
  - 新增 C2 channel 到 preferred protocol 的推断逻辑。
  - 空态说明补充跳包 / 跳流能力。
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.test.tsx`
  - 新增导航与 Sentinel 证据动作 mock。
  - 新增 C2 候选证据联动测试。
- `C:\Users\QAQ\Desktop\gshark\docs\c2-sample-analysis.md`
  - 续写 2026-04-29 复核优化记录。
- `C:\Users\QAQ\Desktop\gshark\docs\c2-sample-analysis-report-2026-04-29.md`
  - 新增本轮复核、优化与回归报告。

## 4. 风险与边界

- 本轮没有改动后端 C2 检测规则，属于前端证据链增强。
- `https` 候选如果没有 HTTP method，将不强制指定 HTTP preferred protocol，避免错误跳转；实际路由由 `preparePacketStream` 依据 packet proto 推断。
- `EvidenceActions` 是 MISC 与 C2 共享组件，后续如果该组件按钮样式调整，会同时影响多个证据表，这是期望中的统一化行为。

## 5. 下一轮建议

1. **候选详情增强**：在候选表中进一步展示 `source`、`destination`、`host`、`uri`、`evidence` 摘要。
2. **CS 聚合详情**：实现同 Host / URI 的 GET 拉取、POST 回传配对视图。
3. **VShell Stream 画像**：将架构标记、长度前缀、心跳、短长包交替按 stream 聚合，而不是仅按单包候选展示。
4. **APT 独立页准备**：开始设计独立 `APT 组织画像` 页，首个 actor 可使用银狐 / Silver Fox，并消费当前 C2 技术证据。
5. **UI 微调**：如果候选列较多，可将表格行扩展为可展开详情，主行只展示核心字段和证据动作。

## 6. 验收项

本轮完成后应满足：

- C2 页面候选证据表出现 `证据联动` 列。
- 点击 `定位到包` 能回到主工作区并定位 packet。
- 点击 `打开关联流` 能进入对应 HTTP / TCP / UDP 流追踪页。
- tab 切换仍不重新请求 C2 分析接口。
- 前端类型检查、单元测试和构建通过。
