# 日期: 2026-04-26
# 署名: Codex

# CTF-NetA Module 对比审计与 GShark 开发续进报告

## 一、报告摘要

本轮工作围绕上一轮报告的结论继续推进，重点做了三件事:

1. 对 `C:\Users\QAQ\Desktop\gshark\docs\ctf-neta-module-audit-and-development-report-2026-04-25.md` 进行了复核评论，并已把评论追加到原报告末尾。
2. 对当前仓库实现状态再次审计，确认上一轮报告对 **P0 已具备高可用基础、P1 尚未展开** 的判断基本准确。
3. 继续执行优化方案，优先落地了 **HTTP 登录行为分析**，将其接入后端结构化模型、API、MISC 模块体系和前端专用界面。

本轮的核心结论是：

- **P1 已正式开始落地**，其中 `HTTP 登录行为分析` 已进入可运行状态。
- 该能力与现有 HTTP 流追踪、抓包缓存、本地 SQLite 包库、MISC 模块体系兼容良好。
- 下一轮可继续围绕 **SMTP / MySQL 会话重建** 与 **更深工控异常规则** 展开。

## 二、对上一轮报告的审计结论

### 1. 报告准确项

上一轮报告以下判断是准确的：

- P0 WebShell 工作流已经具备较高完成度
- NTLM / WinRM / SMB 材料统一已经进入高完成度阶段
- 工控规则分析虽然已经有框架，但仍处于持续增强阶段
- P1 基本未启动，其中 HTTP 登录行为分析在上一轮报告形成时确实尚未落地
- P2 中“分析页结果回流风险”和“MISC 元数据展示不足”是当时最值得修复的产品化问题

### 2. 报告值得补充项

复核时认为上一轮报告还可补充两点：

1. 应更强调 **请求/响应配对能力** 是 WebShell 工作台与登录行为分析的共同基础能力。
2. 应更明确把 **HTTP 登录行为分析** 作为下一轮第一优先级，而不是仅作为 P1 列表中的一个条目。

这两点已经在本轮实现方向中吸收。

## 三、本轮继续执行的优化方案

## 1. 新增 HTTP 登录行为分析后端能力

已新增：

- `C:\Users\QAQ\Desktop\gshark\backend\internal\engine\tool_http_login.go`
- `C:\Users\QAQ\Desktop\gshark\backend\internal\engine\tool_http_login_test.go`

后端能力说明：

- 新增结构化模型：
  - `HTTPLoginAnalysis`
  - `HTTPLoginEndpoint`
  - `HTTPLoginAttempt`
- 新增服务方法：
  - `(*Service).HTTPLoginAnalysis(ctx)`
- 对当前抓包中的 HTTP 包做顺序审计，自动识别登录候选请求
- 以 **stream id + 顺序队列** 的方式，把认证请求与后续 HTTP 响应进行配对

当前识别规则覆盖：

- 登录路径关键词：
  - `login`
  - `signin`
  - `auth`
  - `session`
  - `token`
  - `password`
  - `sso`
  - `otp`
  - `mfa`
- 认证参数识别：
  - `username / user / login / email / account`
  - `password / passwd / pwd / pass`
  - `token / access_token / refresh_token / otp / code`
  - `captcha / verify / verification_code`
- 请求体解析：
  - query string
  - `application/x-www-form-urlencoded`
  - `application/json`

响应侧当前可自动判断：

- 成功
  - 2xx + Set-Cookie
  - 2xx + token 返回
  - 3xx 跳转到非登录页面
  - 正文命中成功关键字
- 失败
  - 401 / 403
  - 429 限速
  - 正文命中失败关键字
  - 仍跳回登录页
- 待确认
  - 验证码 / OTP / MFA 中间态
  - 只有 2xx 但缺少明确成功/失败信号
  - 请求没有在抓包中找到明确响应

此外还补了端点聚合分析：

- 每个认证端点统计：
  - 尝试次数
  - 成功 / 失败 / 待确认次数
  - 用户名变体数
  - 密码尝试次数
  - Set-Cookie / token hint 次数
  - 状态码分布
  - 请求键集合
  - 响应信号集合
- 会标记 **疑似爆破 / 批量验证**：
  - 同一端点尝试次数 >= 3
  - 失败次数 >= 2
  - 且用户名变化或口令尝试明显

## 2. 新增 HTTP 登录行为分析 API

已接入：

- `C:\Users\QAQ\Desktop\gshark\backend\internal\transport\http_server.go`

新增接口：

```text
GET /api/tools/http-login-analysis
```

接口特点：

- 绑定 `r.Context()`
- 支持前端 abort/cancel
- 返回结构化结果，而非脚本文本输出

## 3. 将 HTTP 登录行为分析接入 MISC 工具体系

已接入：

- `C:\Users\QAQ\Desktop\gshark\backend\internal\transport\misc_modules.go`

新增内建模块：

- `http-login-analysis`

模块元信息：

- 协议域：`HTTP / Auth`
- 需要抓包：是
- 支持导出：是
- 可取消：是
- 依赖：`capture`, `http`

这使得该能力没有脱离当前产品架构，而是进入了现有的 **MISC 模块注册表**。

## 4. 新增前端专用模块界面

已新增：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\modules\HTTPLoginAnalysisModule.tsx`

已修改：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\registry.tsx`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\integrations\wailsBridge.ts`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\core\types.ts`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\MiscTools.test.tsx`

前端界面能力：

- 自动加载当前抓包中的 HTTP 登录分析
- 结果筛选：
  - 全部
  - 成功
  - 失败
  - 待确认
- 关键词检索
- 左侧认证端点列表
- 右侧端点聚合详情
- 底部认证尝试明细表
- 客户端导出：
  - JSON
  - TXT

并且前端模块已经接入取消能力：

- `bridge.getHTTPLoginAnalysis(signal?)`
- 页面卸载 / 切换抓包时可中断旧请求

## 四、本轮对整体方案推进度的更新判断

### 1. P0

P0 仍维持高完成度，尤其是：

- WebShell 工作台
- NTLM 材料中心
- 工控规则检测基础版

### 2. P1

P1 不再是“完全未启动”，因为：

- **HTTP 登录行为分析已经落地**

当前 P1 状态建议改判为：

- **已启动，但仅完成第一个高优先级切面**

仍未落地项包括：

- MySQL 会话重建
- SMTP 会话重建
- Shiro rememberMe 专项工具
- Cobalt Strike 材料提取与解码
- 通信核心网协议字段工作台

### 3. P2

P2 本轮没有大规模新增页面治理改造，但 HTTP 登录分析模块已经遵循了当前项目的产品化方向：

- 结构化模型
- 可取消请求
- MISC 注册表接入
- 前端统一卡片风格
- 可导出

因此它是一次“按新规范新增能力”的正确样板。

## 五、验证结果

### 后端测试

执行：

```powershell
go test ./...
```

目录：

- `C:\Users\QAQ\Desktop\gshark\backend`

结果：

- 全部通过

### 前端测试

执行：

```powershell
npm test
```

目录：

- `C:\Users\QAQ\Desktop\gshark\frontend`

结果：

- 9 个测试文件通过
- 28 个测试通过

### 前端构建

执行：

```powershell
npm run build
```

目录：

- `C:\Users\QAQ\Desktop\gshark\frontend`

结果：

- 构建通过

## 六、本轮关键改动文件

### 新增文件

- `C:\Users\QAQ\Desktop\gshark\backend\internal\engine\tool_http_login.go`
- `C:\Users\QAQ\Desktop\gshark\backend\internal\engine\tool_http_login_test.go`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\modules\HTTPLoginAnalysisModule.tsx`

### 修改文件

- `C:\Users\QAQ\Desktop\gshark\backend\internal\model\types.go`
- `C:\Users\QAQ\Desktop\gshark\backend\internal\transport\http_server.go`
- `C:\Users\QAQ\Desktop\gshark\backend\internal\transport\misc_modules.go`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\core\types.ts`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\integrations\wailsBridge.ts`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\registry.tsx`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\MiscTools.test.tsx`

## 七、下一轮建议

建议下一轮优先按如下顺序推进：

1. **SMTP 会话重建**
   - 与登录行为分析同属内容型协议分析
   - 可继续复用当前 MISC 模块落地方向

2. **MySQL 会话重建**
   - 适合补凭据型 / 查询型协议能力
   - 与 HTTP 登录分析一起构成“认证 / 内容 / 凭据”基础面

3. **工控规则深化**
   - 继续增加异常值、规则冲突、时间窗口突变、设备角色异常切换等规则

4. **请求/响应配对能力继续抽象**
   - 不仅服务于 HTTP 登录行为分析
   - 也能反哺 WebShell 解码工作台与后续 SMTP / MySQL 重建

## 八、结论

本轮并没有发散式地去堆积专题工具，而是遵照上一轮报告建议，优先落地了 **最符合当前产品定位、最容易复用现有架构的 P1 第一项：HTTP 登录行为分析**。

这使当前项目从：

- “P0 高完成度、P1 未启动”

推进到了：

- “P0 高完成度、P1 已启动并落地第一个高优先级能力”

如果继续保持这种推进方式，下一轮最值得继续实施的是：

- SMTP / MySQL
- 更深工控规则
- 更通用的请求/响应配对抽象

## 九、2026-04-26 晚间复核评论

对本报告进行复盘后，结论如下：

1. **优先级判断基本准确**
   - 将 HTTP 登录行为分析作为上一轮首个 P1 能力落地是合理的，因为它同时验证了：结构化模型、MISC 模块渲染、前端导出、以及 capture 生命周期下的可取消接口。
   - 该能力没有破坏现有工作区与流追踪主线，而是延续了“专题能力进入统一分析工作流”的方向，这一点判断正确。

2. **报告对“共同基础能力”的强调还可以更进一步**
   - 上一轮已经指出“请求/响应配对能力继续抽象”是后续重点，这个判断是对的。
   - 但从本轮 SMTP 落地来看，还应进一步补充：**协议重建类能力最好先抽象统一的会话归并 / 明细命令轨迹 / 内容正文预览 / 导出文本层**，否则每新增一种协议都会重复编写类似逻辑。

3. **下一轮建议中的 SMTP 优先级是正确的**
   - SMTP 既能覆盖认证材料，也能覆盖内容重建与附件线索，和 HTTP 登录行为分析的互补性很强。
   - 相较于直接进入 MySQL 或更复杂的通信核心网协议，SMTP 更适合用来继续验证 typed model + cancellable + exportable 的产品化路径。

4. **后续还需关注两类风险**
   - 一类是“模块越来越多后 MISC 工具页信息密度过高”，需要继续优化筛选、分域与模块说明。
   - 另一类是“协议专项能力之间缺少统一的证据跳转”，后续最好补充从模块结果跳到包号/流号的统一联动。

总体评价：本报告的判断方向是可靠的，且已成功指导出一条连续的产品化实施路径；本轮 SMTP 会话重建继续印证了该路线具备可执行性。
