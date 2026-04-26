# 日期: 2026-04-26
# 署名: Codex

# CTF-NetA Module Audit & Development Report - Round 8

## 一、本轮目标

上一轮完成了 Shiro rememberMe 协议专项工具，并把 `cancellable` 从开发字段解释为更清晰的产品语义：**支持中断**。

本轮不继续堆新协议，而是复查上一轮报告中的“证据联动”建议，把已经产出的协议分析结果真正接回包表和流重组工作台。

本轮目标：

1. 复查 Shiro rememberMe 模块的结果呈现是否只是“静态报告”；
2. 抽出可复用的 MISC 证据动作入口；
3. 让 Shiro 候选支持一键定位原始包与打开关联流；
4. 补充测试和本轮报告，为后续 HTTP 登录 / SMTP / MySQL / NTLM 统一接入铺路。

---

## 二、复查结论

### 2.1 协议能力已经有证据字段，但页面未形成闭环

复查 `ShiroRememberMeAnalysisModule` 后确认，上一轮已经输出了足够的证据索引：

- `packetId`
- `streamId`
- `host`
- `path`
- `sourceHeader`
- `cookiePreview`
- `keyResults`

这些字段能告诉分析人员“风险在哪里”，但原页面只能查看详情和导出结果，不能直接跳到原始包或流上下文。对流量分析来说，这会造成一个明显断点：用户需要手动回主工作区搜索包号，再手动打开流。

### 2.2 主工作区已有成熟跳转能力，应复用而不是重写

复查 `CaptureMissionControl` 和 `SentinelContext` 后确认，现有应用已经具备稳定能力：

- `locatePacketById(packetId, filterOverride?)`
  - 定位到指定包；
  - 必要时切换分页和过滤上下文。
- `preparePacketStream(packetId, preferredProtocol?, filterOverride?)`
  - 根据包号定位包；
  - 判断 HTTP / TCP / UDP 流；
  - 预加载并设置 active stream。
- 路由目标：
  - `/http-stream`
  - `/tcp-stream`
  - `/udp-stream`

因此本轮不应该在 Shiro 模块里重新实现一套跳转逻辑，而应该把这套能力封装成 MISC 模块可复用的小组件。

### 2.3 `cancellable` 语义保持上一轮结论

本轮复查确认上一轮解释仍然成立：

- `cancellable` 表示模块请求支持中途取消或组件切换时自动中断；
- 它不表示协议动作可回滚；
- 它不表示风险处置可撤销；
- UI 中继续使用 `支持中断` 是合适的。

本轮没有再修改该字段，只在报告中确认语义已经收敛。

---

## 三、本轮优化实现

### 3.1 新增 MISC 证据动作组件

新增文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\EvidenceActions.tsx`

组件能力：

- 输入 `packetId`；
- 可选输入 `preferredProtocol`；
- 提供 `定位到包` 动作；
- 提供 `打开关联流` 动作；
- 调用 `useSentinel()` 中已有的 `locatePacketById` 与 `preparePacketStream`；
- 根据协议自动导航：
  - HTTP -> `/http-stream`
  - UDP -> `/udp-stream`
  - 其他默认 -> `/tcp-stream`
- 当包号无效或动作进行中时自动禁用按钮；
- 保留按钮级 pending 状态：
  - `定位中...`
  - `打开中...`

设计原则：

- 不把流跳转逻辑散落到每个协议模块；
- 不复制 `CaptureMissionControl` 的业务逻辑；
- 只做 MISC 协议结果到全局工作区的轻量连接层；
- 后续 HTTP 登录、SMTP、MySQL、NTLM 可直接复用。

### 3.2 Shiro rememberMe 详情接入证据动作

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\modules\ShiroRememberMeAnalysisModule.tsx`

接入位置：

- 候选详情卡片；
- 包号、流号、Host、Path、CBC/GCM 标签之后；
- Cookie Value 与 Key 结果之前。

新增交互：

- `定位到包`
  - 跳回主工作区；
  - 定位 Shiro rememberMe 候选对应的原始包。
- `打开关联流`
  - 优先按 HTTP 语义准备流；
  - 成功时跳转到 HTTP 流工作台；
  - 如果无法解析协议或流号，则回到主工作区保留包级上下文。

这让 Shiro 分析从“发现线索”前进到“追溯证据”。

### 3.3 测试桩补齐路由与 Sentinel 行为

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\MiscTools.test.tsx`

补充内容：

- mock `react-router` 的 `useNavigate`；
- mock `useSentinel()` 返回的：
  - `locatePacketById`
  - `preparePacketStream`
  - `setActiveStream`
- 新增测试：
  - 展开 Shiro rememberMe 模块；
  - 点击 `定位到包`；
  - 断言调用 `locatePacketById(401)`；
  - 点击 `打开关联流`；
  - 断言调用 `preparePacketStream(401, "HTTP")`；
  - 断言导航到 `/http-stream` 并携带 `streamId: 44`。

---

## 四、验证结果

### 4.1 前端类型检查

执行命令：

```powershell
npx tsc --noEmit
```

执行目录：

```text
C:\Users\QAQ\Desktop\gshark\frontend
```

结果：

- 通过

### 4.2 MISC 页面专项测试

执行命令：

```powershell
npm test -- MiscTools.test.tsx
```

执行目录：

```text
C:\Users\QAQ\Desktop\gshark\frontend
```

结果：

- 1 个测试文件通过；
- 9 个测试通过；
- 新增 Shiro 证据联动测试通过。

### 4.3 前端全量测试

执行命令：

```powershell
npm test
```

执行目录：

```text
C:\Users\QAQ\Desktop\gshark\frontend
```

结果：

- 9 个测试文件通过；
- 29 个测试通过。

### 4.4 前端生产构建

执行命令：

```powershell
npm run build
```

执行目录：

```text
C:\Users\QAQ\Desktop\gshark\frontend
```

结果：

- 通过；
- Vite 成功生成 `dist` 产物。

---

## 五、本轮关键改动文件

前端：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\EvidenceActions.tsx`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\modules\ShiroRememberMeAnalysisModule.tsx`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\MiscTools.test.tsx`

文档：

- `C:\Users\QAQ\Desktop\gshark\docs\ctf-neta-module-audit-and-development-report-2026-04-26-round8.md`

---

## 六、本轮评价

本轮没有新增大型协议解析器，但解决了协议分析工具链里很关键的一步：**从结构化结论回到原始证据**。

对安全分析场景来说，这个提升很实际：

- 发现 Shiro rememberMe 命中后，可以立刻跳到证据包；
- 可以直接查看关联 HTTP/TCP/UDP 流上下文；
- 分析人员不需要在包表、过滤器和流页面之间手动切换；
- MISC 模块逐步从“工具集合”变成“证据驱动的工作台”。

这类优化虽然小，但会显著降低复盘成本。协议功能不是只有解析器本身，能否快速追溯证据同样决定工具好不好用。

---

## 七、下一轮建议

下一轮建议继续沿用本轮抽象，把证据动作扩展到已经完成的协议模块：

1. HTTP 登录行为分析
   - 登录尝试 -> 定位请求包；
   - 登录尝试 -> 打开 HTTP 流；
   - 暴力猜测端点 -> 聚合跳转。

2. SMTP 会话重建
   - AUTH 命令 -> 定位包；
   - 邮件消息 -> 打开 TCP 流；
   - 附件线索 -> 回到 MIME 片段所在包。

3. MySQL 会话重建
   - 登录包 -> 定位；
   - SQL 查询 -> 定位；
   - ERR / RESULTSET 响应 -> 定位响应包；
   - 会话 -> 打开 TCP 流。

4. NTLM 会话材料中心
   - frameNumber -> 包号定位；
   - HTTP/SMB3 认证材料 -> 关联流跳转；
   - WinRM 解密结果 -> 回链到 NTLM 材料来源。

5. 交互体验补强
   - 当无法找到流时给出轻量提示；
   - 支持从证据动作传入过滤器；
   - 在 MISC 模块内统一呈现“证据链”区域。

---

## 八、结论

Round 8 完成了 Shiro rememberMe 的证据联动闭环：

- 新增可复用的 MISC 证据动作组件；
- Shiro 候选详情支持一键定位原始包；
- Shiro 候选详情支持一键打开关联流；
- 新增测试覆盖路由跳转与 Sentinel 调用；
- `cancellable` 语义保持为“支持中断”，未再混入协议含义。

至此，Shiro rememberMe 模块已经不只是能“识别风险”，还可以把风险结果直接带回包级与流级证据上下文。下一轮应把同一套联动扩展到 HTTP 登录、SMTP、MySQL 与 NTLM，让 MISC 页真正形成统一证据操作层。
