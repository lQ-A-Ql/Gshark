# 日期: 2026-04-26
# 署名: Codex

# CTF-NetA Module 对比开发报告（第 4 轮）

## 一、本轮目标

本轮承接上一份报告：

- `C:\Users\QAQ\Desktop\gshark\docs\ctf-neta-module-audit-and-development-report-2026-04-26-round2.md`

在对其进行复盘审计后，继续执行下一轮优化。根据上一轮建议，本轮选择的主要落地方向是：

- **MySQL 会话重建**

这样做的原因有三点：

1. 它与上一轮已完成的 SMTP 会话重建形成自然衔接；
2. 它可以补齐数据库查询、默认库、登录用户、错误响应这类“凭据型 / 查询型协议”能力；
3. 它能继续验证当前项目专题模块的统一实现范式是否足够稳固。

---

## 二、对上一轮报告的复盘审计结论

对上一轮 SMTP 报告复盘后，结论如下：

### 1. 优先级判断准确

上一轮把 MySQL 放在紧随 SMTP 的位置是合理的。

- SMTP 已经证明当前项目可以很好地承载“会话级协议重建”；
- MySQL 则是在此基础上继续扩展到数据库协议，并且能复用大量工程模式；
- 因此这不是一次跳跃式扩展，而是顺着既有产品化方向继续前进。

### 2. 当前架构已经开始形成“专题分析模板”

从已经完成的几轮实现来看，多个能力已经逐步出现统一模式：

- 后端输出 typed model；
- HTTP 接口绑定 capture 生命周期；
- 通过 MISC 注册表统一进入前端；
- 前端按卡片、表格、详情、导出方式呈现；
- 用测试和构建做回归保障。

这说明当前项目的演进方向已经从“补工具”逐渐走向“补专题分析框架”。

### 3. 当前最值得继续补强的缺口仍是证据联动

虽然 MySQL、SMTP、HTTP 登录、NTLM 等模块都已有结构化结果，但它们与主工作区/流追踪页之间还没有完全统一的跳转联动。

后续建议优先补：

- 结果条目跳转到包号
- 结果条目跳转到流号
- 主页面与专题模块之间的双向往返

---

## 三、本轮已完成优化：MySQL 会话重建

### 1. 后端新增 MySQL 专项分析服务

新增文件：

- `C:\Users\QAQ\Desktop\gshark\backend\internal\engine\tool_mysql.go`
- `C:\Users\QAQ\Desktop\gshark\backend\internal\engine\tool_mysql_test.go`

本轮新增能力包括：

- 按 `stream_id` 聚合 MySQL 会话；
- 基于 MySQL 数据包头解析单个 TCP 载荷中的 MySQL frame；
- 识别并提取：
  - 服务器握手版本
  - connection id
  - 登录用户名
  - 默认数据库
  - auth plugin
  - COM_QUERY
  - COM_INIT_DB
  - COM_STMT_PREPARE
  - OK / ERR / RESULTSET 响应
- 关联查询与对应响应，形成结构化查询轨迹；
- 输出会话级摘要、服务端事件摘要与分析说明。

### 2. 新增结构化模型

后端模型文件：

- `C:\Users\QAQ\Desktop\gshark\backend\internal\model\types.go`

新增结构化类型：

- `MySQLQueryRecord`
- `MySQLServerEvent`
- `MySQLSession`
- `MySQLAnalysis`

这些类型使 MySQL 能力不再以临时文本方式输出，而是正式进入项目的结构化数据模型体系。

### 3. 新增 API 并接入 capture 生命周期

修改文件：

- `C:\Users\QAQ\Desktop\gshark\backend\internal\transport\http_server.go`

新增接口：

- `GET /api/tools/mysql-analysis`

特点：

- 使用 `r.Context()` 传递取消信号；
- 前端 abort 时可中断；
- 关闭抓包时不会继续让旧 capture 的 MySQL 分析落回当前 UI。

### 4. MySQL 已纳入内建 MISC 模块体系

修改文件：

- `C:\Users\QAQ\Desktop\gshark\backend\internal\transport\misc_modules.go`

新增内建模块：

- `mysql-session-analysis`

模块元数据：

- `requiresCapture: true`
- `protocolDomain: MySQL / Database`
- `supportsExport: true`
- `cancellable: true`
- `dependsOn: [capture, mysql]`

这说明 MySQL 模块已与现有专题工具体系保持一致，而不是额外开辟一套孤立入口。

---

## 四、前端闭环实现情况

### 1. 前端类型与 bridge 已补齐

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\core\types.ts`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\integrations\wailsBridge.ts`

新增前端类型：

- `MySQLQueryRecord`
- `MySQLServerEvent`
- `MySQLSession`
- `MySQLAnalysis`

新增 bridge 接口：

- `bridge.getMySQLAnalysis(signal?)`

### 2. 新增 MySQL 专项界面模块

新增文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\modules\MySQLSessionAnalysisModule.tsx`

并注册到：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\registry.tsx`

当前 MySQL 模块已支持：

- 全部 / 登录 / 错误 三类筛选
- 关键词检索
- 会话列表
- 会话详情
- 查询轨迹表格
- 服务端事件摘要
- 导出 JSON
- 导出 TXT

### 3. 前端测试回归已接入

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\MiscTools.test.tsx`

已新增 MySQL 模块的 mock 与渲染回归路径，使其进入统一的 MISC 页面测试范围。

---

## 五、测试与验证

### 1. 后端测试

执行目录：

- `C:\Users\QAQ\Desktop\gshark\backend`

执行命令：

```powershell
go test ./...
```

结果：

- 全部通过

新增的 MySQL 单元测试覆盖了：

- 握手与登录信息解析
- 默认数据库提取
- COM_QUERY 与响应关联
- OK / ERR / RESULTSET 识别

### 2. 前端类型检查

执行目录：

- `C:\Users\QAQ\Desktop\gshark\frontend`

执行命令：

```powershell
npx tsc --noEmit
```

结果：

- 通过

### 3. 前端测试

执行目录：

- `C:\Users\QAQ\Desktop\gshark\frontend`

执行命令：

```powershell
npm test
```

结果：

- 9 个测试文件通过
- 28 个测试通过

### 4. 前端构建

执行目录：

- `C:\Users\QAQ\Desktop\gshark\frontend`

执行命令：

```powershell
npm run build
```

结果：

- 构建通过

---

## 六、本轮关键改动文件

### 新增文件

- `C:\Users\QAQ\Desktop\gshark\backend\internal\engine\tool_mysql.go`
- `C:\Users\QAQ\Desktop\gshark\backend\internal\engine\tool_mysql_test.go`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\modules\MySQLSessionAnalysisModule.tsx`

### 修改文件

- `C:\Users\QAQ\Desktop\gshark\backend\internal\model\types.go`
- `C:\Users\QAQ\Desktop\gshark\backend\internal\transport\http_server.go`
- `C:\Users\QAQ\Desktop\gshark\backend\internal\transport\misc_modules.go`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\core\types.ts`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\integrations\wailsBridge.ts`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\registry.tsx`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\MiscTools.test.tsx`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\modules\SMTPSessionAnalysisModule.tsx`

---

## 七、本轮评价

本轮 MySQL 会话重建的价值主要体现在三点：

1. **补齐了数据库协议分析这一块高价值空白**
   - 现在项目对专题协议的覆盖，已经从 HTTP / SMTP 扩展到 MySQL。

2. **进一步验证了专题模块的工程模板是成立的**
   - 这轮实现没有引入新的架构分叉，反而再次复用了已有的 typed model + cancellable + MISC UI 方案。

3. **为后续“专题能力之间的统一联动”打下更明确的需求基础**
   - 现在问题不再是“能不能做出专题模块”，而是“怎样让这些模块更像同一个产品体系中的协作单元”。

---

## 八、下一轮建议

基于当前状态，下一轮建议优先顺序如下：

1. **证据联动增强**
   - 让 MySQL / SMTP / HTTP 登录 / NTLM / 工控命中结果统一支持跳包、跳流。

2. **公共会话摘要能力抽象**
   - 将会话标题、命令轨迹、结果摘要、导出文本模板进一步抽为可复用基础层。

3. **工控规则继续深化**
   - 在已有工业分析与规则命中基础上，继续补时间窗口突变、角色异常切换、冲突写入等规则。

4. **再考虑扩展更复杂或更低频的协议专题**
   - 如通信核心网协议、Shiro、Cobalt Strike 等。

---

## 九、结论

本轮没有偏离既定路线，而是严格围绕上一轮建议继续推进，并实际落地了：

- **MySQL 会话重建**

至此，当前项目在吸收 `CTF-NetA/module` 中专题能力方面，已经从：

- WebShell / NTLM / 工控 / HTTP 登录 / SMTP

继续推进到了：

- **MySQL 数据库协议重建**

整体趋势已经越来越清晰：

- 工作区负责通用抓包与全局操作；
- 流追踪页负责载荷级查看与解码；
- 分析页负责异常规则与统计画像；
- MISC 页负责专题协议/算法模块；
- 所有能力统一纳入可取消、可缓存、可导出的工程体系。

这条路线比继续堆脚本式功能更稳，也更适合持续扩展。

## 十、2026-04-26 界面轮复核评论

对上一轮《MySQL 会话重建》报告进行复盘后，可以确认其判断总体正确，但本轮也暴露出一个重要现实：**当前项目在专题能力层面的积累速度，已经开始反过来要求页面层进行重组与视觉秩序重建**。

1. **上一轮关于“证据联动应优先于继续横向扩协议”的判断依然成立**
   - 这一点没有变化。
   - 但从本轮 UI 改版来看，还需要再补一句：在证据联动之前，MISC 页本身也要先具备更稳定的模块分层、展开逻辑与视觉识别能力，否则模块越多越难用。

2. **上一轮已经把技术能力铺到了足够深的位置，本轮开始转向产品编排是合理的**
   - 从 HTTP 登录、SMTP、MySQL、NTLM、SMB3、WinRM 等能力堆叠到现在，继续只做协议实现会让入口变重。
   - 因此本轮优先重做 MISC 页，而不是继续盲目加协议模块，是必要的节奏调整。

3. **专题能力框架现在需要“前台壳层”**
   - 过去几轮的重点是后端模型、分析链路和模块接入。
   - 本轮说明：这些能力已经需要一个更成熟的壳层来承载，包括标题头区、模块列表、展开工作台、导入入口与筛选提示。

4. **后续建议应明确区分“能力层推进”和“承载层推进”**
   - 能力层：协议分析、规则引擎、专题工具。
   - 承载层：页面布局、模块交互、证据联动、统一导航与跳转。
   - 这两条线后续应并行推进，而不是只盯着能力层继续横向扩展。

总体评价：上一轮报告在技术路径上判断准确；而本轮对 MISC 页布局与标题头区的重做，说明项目已经进入“能力成熟后需要产品化重排”的阶段。
