# 日期: 2026-04-30
# 署名: Codex

# 协议专项与 MISC 工具箱合并摘要

## 一、合并范围

本文件按“协议专项分析与 MISC 工具箱”方向合并近期协议能力、内建 MISC 模块、Payload / WebShell 解码迁移、WinRM/SMB3 工具和 cancellable 语义说明。原始模块接口文档与补丁报告继续保留。

## 二、能力定位

- 协议专项分析面向抓包中的具体协议行为，目标是把流量还原为可审计的结构化结论。
- MISC 工具箱承载轻量工具、实验性解码、密钥/凭据辅助分析和不适合塞进主流追踪页的专项能力。
- `cancellable=true` 表示模块请求支持取消：前端切换模块、刷新、重新输入或离开页面时可以中止请求，后端或桥接层应避免过期结果覆盖当前 UI。

## 三、已完成能力

### 1. 协议专项能力

- HTTP 登录行为分析已落地，覆盖认证尝试明细、账号/来源/路径聚合和异常登录线索。
- SMTP 分析已落地，支持邮件会话、认证、发件行为与附件/对象线索。
- MySQL 分析已落地，支持连接、认证、查询和异常行为基础审计。
- Shiro rememberMe 专项工具已纳入计划并完成结构化接入方向，聚焦 rememberMe cookie 分析和 key 测试。

### 2. MISC 内建模块

- WinRM 解密工具保留为内建复杂模块。
- SMB3 session key 相关工具保留为内建复杂模块。
- Payload / WebShell 解码工作台迁移到 MISC，避免流追踪页面继续承担实验性解码工作台。
- 内建模块通过 manifest 暴露 `kind=builtin`、`requires_capture`、`supports_export`、`cancellable`、`api_prefix` 等能力描述。

### 3. Payload / WebShell 解码

- 工作台支持手动粘贴 HTTP 报文、HTTP body、form-urlencoded、multipart、Base64、Hex 和纯参数值。
- 候选识别覆盖 query、form、multipart、JSON 字段、URL 多轮解码、base64url 和 Hex 包裹文本。
- Base64 作为稳定解码路径保留并增强错误表达。
- Behinder、AntSword、Godzilla 作为实验性路径，需要展示置信度、失败阶段和人工复核提示。
- Auto 模式只应在置信度达标时返回成功，低置信结果显示“候选可疑 / 需要人工确认”。

### 4. 产品表达

- HTTP/TCP/UDP 流追踪页不再展示完整解码工作台，只保留当前片段预览。
- MISC 解码模块提供输入区、候选区、解码配置区、结果区、复制和导出。
- 非 Base64 解码失败需要说明具体阶段，例如未提取到密文、密钥/IV 长度非法、AES 分组长度非法、Base64 候选不足。

## 四、当前缺陷

1. WebShell 解码真实样本覆盖不足，Behinder、AntSword、Godzilla 仍需要更多样例验证。
2. `/api/streams/inspect` 与 `/api/streams/decode` 已可复用，但前端桥接和结果字段仍需持续向后兼容。
3. MISC 模块 manifest 的 UI 表达还可增强，例如显示是否需要抓包、是否可取消、是否支持导出。
4. 自定义 zip 模块与内建模块的能力边界已经明确，但脚手架和错误诊断仍可进一步产品化。
5. 协议专项模块增多后，需要统一“分析中、可取消、失败、低置信、导出”状态体验。

## 五、下一步建议

1. 为 Payload / WebShell 解码补充更多后端单测，覆盖 HTTP 报文提取、候选识别、多轮 URL 解码和失败阶段。
2. 为 MISC 模块列表增加能力徽标：无需抓包、支持导出、可取消、实验性。
3. 将 HTTP 登录、SMTP、MySQL、Shiro 的报告输出格式统一为摘要、证据、明细、建议四段。
4. 为 cancellable 模块建立统一 AbortController 管理模式，防止过期结果覆盖。
5. 将高风险协议行为映射到 EvidenceActions / FilterActions，方便从协议分析跳回证据定位。
