# CTF-NetA Module 对比审计与 GShark 开发报告

- 时间: 2026-04-25 22:55:54 +08:00
- 署名: opencode
- 范围:
  - 对 `C:\Users\QAQ\Desktop\gshark` 当前实现进行代码审计
  - 对照既定开发计划核查完成度
  - 继续推进一批高优先级落地项

## 一、报告摘要

本次审计结论如下:

1. P0 路线已经有较强落地基础，尤其是 WebShell 解码工作台、NTLM 会话材料中心、工控规则检测基础版。
2. P1 路线整体仍未展开，HTTP 登录分析、MySQL/SMTP、Shiro/Cobalt Strike、通信核心网字段工作台在当前仓库中仍未发现实现。
3. P2 路线部分完成，结构化模型、缓存、MISC 注册表、抓包关闭清理能力已经存在，但分析页存在会话隔离不足的问题。
4. 本轮开发已继续修复分析页会话回流风险、补强工控规则、补充 P0 相关测试，并增强 MISC 元数据展示。

## 二、基线审计结论

### 1. P0 完成度

#### 1.1 WebShell 工作流升级

状态: 高完成度，约 80%-85%

已落地能力:

- 候选 payload 自动提取
- 家族指纹识别与推荐解码器
- Base64 / Behinder / AntSword / Godzilla / Auto 解码
- Godzilla XOR 支持
- 批量区间解码
- `仅预览 / 衍生视图 / 覆盖原文` 三态工作流
- 流级持久化覆盖与 override 计数

关键证据:

- `backend/internal/engine/stream_payload_inspector.go`
- `backend/internal/engine/stream_decoder.go`
- `backend/internal/engine/stream_decoder_extended.go`
- `frontend/src/app/components/StreamDecoderWorkbench.tsx`
- `frontend/src/app/pages/HttpStream.tsx`
- `frontend/src/app/pages/TcpStream.tsx`
- `frontend/src/app/pages/UdpStream.tsx`

仍有缺口:

- 还没有明确的请求/响应配对工作流模型
- 候选提取与指纹识别原先缺少测试，本轮已补基础测试

#### 1.2 NTLM / WinRM / SMB 材料统一

状态: 高完成度，约 85%-90%

已落地能力:

- NTLM 统一材料模型
- HTTP / WinRM / SMB3 材料统一提取
- MISC 内建 `NTLM 会话材料中心`
- 统一导出与详情查看

关键证据:

- `backend/internal/engine/tool_ntlm.go`
- `backend/internal/model/types.go`
- `backend/internal/transport/http_server.go`
- `backend/internal/transport/misc_modules.go`
- `frontend/src/app/misc/modules/NTLMSessionMaterialsModule.tsx`

仍有缺口:

- 取消能力尚未接入
- 离线分析材料导出仍偏前端导出，没有更强的后端工件模型

#### 1.3 工控规则异常分析

状态: 部分完成，约 65%-75%

已落地规则:

- 主从角色推断
- 多主站竞争
- 未知功能码
- 异常响应
- 非法数量字段
- 数量越界
- 长度不一致
- 高频写入
- 功能码突变（本轮新增）

关键证据:

- `backend/internal/tshark/industrial_rules.go`
- `backend/internal/tshark/industrial_analysis.go`
- `frontend/src/app/pages/IndustrialAnalysis.tsx`

仍有缺口:

- 更强的异常值规则
- 规则冲突模型
- 更细粒度的时间窗口与突变上下文

### 2. P1 完成度

状态: 基本未启动

本次代码审计未发现以下实现:

- HTTP 登录行为分析
- MySQL 流量专用重建
- SMTP 流量专用重建
- Apache Shiro 专项工具
- Cobalt Strike 专项工具
- Diameter / GTP / S1AP / NGAP / NAS / PFCP 字段工作台

### 3. P2 完成度

状态: 部分完成

已完成基础:

- MISC 模块 manifest 扩展
- 结构化模型输出
- 流覆盖持久化
- 抓包关闭时清缓存/清任务/清流状态
- 分析页缓存机制

原有风险:

- 多个分析页存在旧请求结果回流 UI 的风险
- MISC 元数据虽然在模型中存在，但通用 UI 展示不足

## 三、本轮继续开发的落地项

### 1. 修复分析页会话回流风险

本轮已为以下页面补充请求中止与最新请求判定逻辑:

- `frontend/src/app/pages/IndustrialAnalysis.tsx`
- `frontend/src/app/pages/VehicleAnalysis.tsx`
- `frontend/src/app/pages/UsbAnalysis.tsx`
- `frontend/src/app/pages/TrafficGraph.tsx`
- `frontend/src/app/pages/MediaAnalysis.tsx`
- `frontend/src/app/components/CaptureMissionControl.tsx`

处理方式:

- 接口层增加 `AbortSignal` 支持
- 页面层维护 `AbortController`
- 引入请求序号，只有最新请求可以回写状态
- 页面卸载时主动 abort
- 缓存 key 统一引入 `captureRevision`

效果:

- 旧抓包分析结果不再容易回写到新会话
- 手动刷新与自动刷新都遵循同一套生命周期约束

### 2. 增强 MISC 元数据展示

已补充通用模块卡片展示以下信息:

- 是否需要抓包
- 协议域
- 是否支持导出
- 是否可取消
- 依赖项

关键文件:

- `frontend/src/app/misc/modules/GenericMiscModule.tsx`
- `frontend/src/app/pages/MiscTools.test.tsx`

### 3. 增加工控规则深度

新增规则:

- `功能码突变`

目标:

- 识别同一源到同一目标的 Modbus 请求在短序列内从一种功能码切换到另一种功能码的行为
- 更贴近计划中的“同功能码突变/规则异常分析”方向

关键文件:

- `backend/internal/tshark/industrial_rules.go`
- `backend/internal/tshark/industrial_analysis_test.go`

### 4. 补充 P0 相关测试

本轮新增测试覆盖:

- `backend/internal/engine/stream_payload_inspector_test.go`
  - HTTP form 中 AntSword 候选识别
  - AES-like 密文判型
  - multipart 候选提取
- `backend/internal/engine/tool_ntlm_test.go`
  - WinRM 协议归类与方向识别
  - SMB3 完整度识别
  - 服务端 challenge 方向识别
- `frontend/src/app/pages/analysisCacheKeys.test.ts`
  - 分析页缓存 key 含 `captureRevision`

## 四、当前完成度更新

相对于审计前，本轮推进后的状态:

1. P0 WebShell 工作流: 保持高完成度，测试覆盖更完整。
2. P0 NTLM 材料中心: 保持高完成度，补了后端识别测试。
3. P0 工控规则分析: 从基础版继续前进，新增 `功能码突变` 规则。
4. P2 生命周期一致性: 从“存在明显高风险”提升为“主要分析页已完成会话隔离修复”。
5. P2 MISC 元数据产品化: 从“模型层完成”推进到“通用 UI 已消费核心元数据”。

## 五、验证结果

### 前端测试

执行:

```powershell
pnpm run test -- src/app/pages/analysisCacheKeys.test.ts src/app/pages/MiscTools.test.tsx src/app/pages/UsbAnalysis.test.tsx src/app/pages/VehicleAnalysis.test.ts src/app/pages/TrafficGraph.test.ts
```

结果:

- 5 个文件通过
- 21 个测试通过

### 前端构建

执行:

```powershell
pnpm run build
```

结果:

- 构建通过

### 后端测试

执行:

```powershell
go test ./internal/engine/... ./internal/tshark/...
```

结果:

- `engine` 通过
- `tshark` 通过

## 六、当前仍未完成的方案项

优先级建议如下。

### P0.5

1. 工控规则继续深化
2. 为 `IndustrialAnalysis` 增加更强的异常值与规则冲突检测
3. 为流工作台补“请求/响应成组配对”的操作语义

### P1

1. HTTP 登录行为分析
2. MySQL 流量重建
3. SMTP 会话重建
4. Shiro rememberMe 专项工具
5. Cobalt Strike 材料提取与解码

### P2

1. 给 NTLM 材料中心、WinRM、SMB3 等能力补统一取消接口
2. 给分析页补更直接的“session mismatch”测试
3. 继续统一更多分析页/总览页的请求治理模式

## 七、建议的下一轮开发顺序

建议按以下顺序继续推进:

1. 做 HTTP 登录行为分析
原因: 与当前产品定位高度一致，能直接复用现有分页、对象、流、过滤、定位能力。

2. 做 SMTP / MySQL 会话重建
原因: 都属于高价值内容型协议，能直接进入 MISC 或 ObjectExport 邻近体系。

3. 继续补工控异常规则
原因: 当前工控页已经具备规则显示框架，继续加规则的收益最高。

4. 最后补 Shiro / Cobalt Strike 等攻防题型专项工具
原因: 价值高，但更偏专题工具，优先级应低于通用实战流量研判能力。

## 八、结论

当前项目对既定方案的实现状态已经从“有方向但不够完整”推进到“P0 已可用、P2 关键风险已明显下降”的阶段。

本轮开发不是只写审计报告，而是已经继续把方案中的高优先级内容落成代码:

- 修复分析页 session/capture 回流风险
- 补强 MISC 元数据产品化展示
- 增加工控 `功能码突变` 规则
- 补 WebShell 与 NTLM 的测试

如果继续沿当前方向推进，下一阶段最值得优先落地的是:

- HTTP 登录行为分析
- SMTP / MySQL 会话重建
- 工控规则深化

署名: opencode

## 九、2026-04-26 复核评论

复核人: Codex

对上一轮报告的评论如下:

1. **总体判断基本准确。**
   - 对 P0 WebShell 工作流、NTLM 材料中心、工控规则基础版的完成度评估与当前代码状态基本一致。
   - 对 P1 “尚未真正展开”的结论也是准确的，尤其是 HTTP 登录行为分析在上一轮报告形成时确实仍未落地。

2. **风险判断是有价值的。**
   - 报告把“分析页旧请求结果回流 UI”列为重点风险，这一点对后续开发方向有直接指导意义。
   - 报告把 MISC 元数据展示、测试覆盖和会话治理纳入同一轮推进，也符合当前项目产品化节奏。

3. **仍有两点需要补充。**
   - 上一轮报告虽然提到“请求/响应配对工作流模型”尚未完善，但没有把它上升为 WebShell 与 HTTP 登录分析的共同基础能力，这一点在后续实现中应继续强调。
   - 对 P1 的优先级排序合理，但建议把 HTTP 登录行为分析明确视为“下一轮首要落地点”，因为它最容易复用当前 HTTP 流、包索引、过滤、定位与 MISC 框架。

4. **结论。**
   - 上一轮报告是可信的，并且成功把后续开发顺序收敛到了正确方向。
   - 基于该报告，下一轮最合适的执行动作就是优先实现 `HTTP 登录行为分析`，再向 SMTP / MySQL 与更深工控规则推进。
