# 日期: 2026-04-26
# 署名: Codex

# CTF-NetA Module Audit & Development Report — Round 7

## 一、本轮目标

本轮从前几轮的 MISC 页面壳层优化，重新转回协议功能实现本身。

本轮目标有三项：

1. 复查上一轮 MISC 模块体系与报告评论，确认下一步不再继续做纯 UI 收口；
2. 补齐一个计划中尚未落地、且能快速融入现有 MISC 工作台体系的协议专项工具；
3. 正式解释并落地 `cancellable` 的产品语义，避免页面上继续出现含义不明的 `Cancelable` 标签。

最终本轮选择落地：

- **Shiro rememberMe 分析工具**

该方向适合 CTF、授权渗透测试和威胁流量复盘：它基于 HTTP 流量中的 `rememberMe` Cookie，辅助判断 Apache Shiro 相关历史风险、默认密钥命中、`deleteMe` 回收痕迹与 Java 序列化载荷线索。

---

## 二、复查审计结论

### 2.1 已完成能力不应重复建设

复查当前代码和报告后可以确认，前几轮已经落地：

- HTTP 登录行为分析；
- SMTP 会话重建；
- MySQL 会话重建；
- NTLM 会话材料中心；
- SMB3 Random Session Key；
- WinRM 解密辅助；
- MISC 嵌入式工作台渲染模式。

因此，本轮如果继续做 HTTP 登录 / SMTP / MySQL，收益会明显下降。更合适的方向是补一个新的协议专项能力。

### 2.2 Shiro rememberMe 只存在模型声明，尚未形成真实链路

复查发现：

- `backend/internal/model/types.go` 中已经出现了 `ShiroRememberMeAnalysis`、`ShiroRememberMeCandidate`、`ShiroRememberMeKeyResult` 等模型；
- 但缺少后端分析实现；
- 缺少 HTTP 路由；
- 缺少 MISC 模块注册；
- 缺少前端 bridge 类型映射；
- 缺少专属前端工作台；
- 缺少测试与报告说明。

也就是说，中断前的状态更像“模型先占位”，而不是“功能已落地”。

### 2.3 `cancellable` 的含义需要产品化解释

本轮明确：`cancellable` / `cancelable` 不是协议属性。

它的真实含义是：

- **当前模块的分析请求支持中途取消，或在切换页面、关闭组件、重新刷新时通过 AbortController / request context 中断执行。**

它不表示：

- 协议本身可取消；
- 操作可回滚；
- 分析结果可以撤销；
- 风险动作可以自动阻断。

因此页面中裸露英文 `Cancelable` 容易误导用户，本轮已改为更明确的中文能力说明：

- `支持中断`

对不具备该能力位的模块，通用渲染器显示为：

- `同步执行`

---

## 三、本轮协议能力实现

### 3.1 后端新增 Shiro rememberMe 分析器

新增文件：

- `C:\Users\QAQ\Desktop\gshark\backend\internal\engine\tool_shiro.go`

核心能力：

- 遍历当前抓包本地索引中的 HTTP-like 包；
- 解析 `Cookie` 与 `Set-Cookie` 头；
- 提取名称为 `rememberMe` / `remember-me` 的 Cookie；
- 识别 `rememberMe=deleteMe` 回收痕迹；
- 对 Cookie 值做 URL 解码与 Base64 解码；
- 判断密文长度、AES 块对齐、CBC/GCM 可能性；
- 内置测试历史 Shiro 默认 key：
  - `kPH+bIxk5D2deZiIxcaaaA==`
- 支持用户提交自定义候选 key；
- 尝试 AES-CBC 与 AES-GCM 解密；
- 校验 Java 序列化魔数 `AC ED 00 05`；
- 提取疑似 Java 类名和明文预览；
- 输出包号、流号、Host、Path、Cookie 来源、命中结果和备注。

### 3.2 后端模型与请求结构补齐

修改文件：

- `C:\Users\QAQ\Desktop\gshark\backend\internal\model\types.go`

本轮补齐：

- `SourceHeader`
  - 用于区分来源是请求 `Cookie` 还是响应 `Set-Cookie`
- `ShiroRememberMeRequest`
  - 用于承载前端提交的自定义候选 key

### 3.3 HTTP 路由接入

修改文件：

- `C:\Users\QAQ\Desktop\gshark\backend\internal\transport\http_server.go`

新增接口：

```text
GET  /api/tools/shiro-rememberme
POST /api/tools/shiro-rememberme
```

说明：

- `GET` 可用默认 key 做快速扫描；
- `POST` 可提交 `candidate_keys`，每行可使用 `base64Key` 或 `label::base64Key`。

### 3.4 MISC 模块注册接入

修改文件：

- `C:\Users\QAQ\Desktop\gshark\backend\internal\transport\misc_modules.go`

新增内建模块：

- ID: `shiro-rememberme-analysis`
- 标题: `Shiro rememberMe 分析`
- API: `/api/tools/shiro-rememberme`
- 协议域: `HTTP / Shiro`
- 支持导出: `true`
- 支持中断: `true`
- 依赖: `capture`, `http`

---

## 四、前端工作台实现

### 4.1 类型与 bridge 映射

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\core\types.ts`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\integrations\wailsBridge.ts`

新增前端类型：

- `ShiroRememberMeAnalysis`
- `ShiroRememberMeCandidate`
- `ShiroRememberMeKeyResult`

新增 bridge 方法：

- `getShiroRememberMeAnalysis(candidateKeys?: string[], signal?: AbortSignal)`

### 4.2 新增 Shiro rememberMe 专属模块

新增文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\modules\ShiroRememberMeAnalysisModule.tsx`

前端能力：

- 自动扫描当前抓包中的 rememberMe Cookie；
- 支持 `全部 / 命中 / deleteMe` 筛选；
- 支持输入自定义 AES key；
- 支持刷新并重新测试 key；
- 展示候选包号、流号、Host、Path、Cookie 预览；
- 展示 CBC/GCM 可能性、密文长度、Key 命中状态；
- 展示疑似 Java 序列化类名与载荷预览；
- 支持 JSON / TXT 导出。

### 4.3 MISC 注册表接入

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\registry.tsx`

新增映射：

- `shiro-rememberme-analysis` → `ShiroRememberMeAnalysisModule`

### 4.4 `cancellable` 展示语义优化

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\MiscTools.tsx`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\modules\GenericMiscModule.tsx`

调整内容：

- 顶部标签从 `可取消分析` 改为 `支持中断`；
- 模块摘要标签从 `Cancelable` 改为 `支持中断`；
- 通用模块元信息从 `可取消 / 不可取消` 改为 `支持中断 / 同步执行`；
- 增加 title 说明：
  - `该模块的分析请求支持中途取消或切换时自动中断`

这样用户看到的就不再是开发字段，而是能理解的产品能力。

---

## 五、测试与验证

### 5.1 后端测试

新增文件：

- `C:\Users\QAQ\Desktop\gshark\backend\internal\engine\tool_shiro_test.go`

覆盖点：

- 能从 HTTP Cookie 中识别 `rememberMe`；
- 能用 Shiro 默认 key 解密 AES-CBC 样本；
- 能识别 Java 序列化魔数；
- 能提取 `org.apache.shiro.subject.SimplePrincipalCollection` 类名；
- 能识别 `rememberMe=deleteMe` 回收痕迹。

执行命令：

```powershell
go test ./backend/internal/engine ./backend/internal/transport
```

结果：

- 通过

### 5.2 前端类型检查

执行命令：

```powershell
npx tsc --noEmit
```

结果：

- 通过

### 5.3 MISC 页面测试

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\MiscTools.test.tsx`

新增覆盖：

- `Shiro rememberMe 分析` 模块进入 MISC 列表；
- bridge 自动请求 Shiro 分析；
- 展开模块后能看到命中的 Java 类名；
- 未加载抓包时不会触发 Shiro 分析请求；
- `cancellable` 文案更新为 `支持中断`。

执行命令：

```powershell
npm test -- MiscTools.test.tsx
```

结果：

- 8 个测试通过

---

## 六、本轮关键改动文件

后端：

- `C:\Users\QAQ\Desktop\gshark\backend\internal\engine\tool_shiro.go`
- `C:\Users\QAQ\Desktop\gshark\backend\internal\engine\tool_shiro_test.go`
- `C:\Users\QAQ\Desktop\gshark\backend\internal\model\types.go`
- `C:\Users\QAQ\Desktop\gshark\backend\internal\transport\http_server.go`
- `C:\Users\QAQ\Desktop\gshark\backend\internal\transport\misc_modules.go`

前端：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\core\types.ts`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\integrations\wailsBridge.ts`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\registry.tsx`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\modules\ShiroRememberMeAnalysisModule.tsx`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\modules\GenericMiscModule.tsx`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\MiscTools.tsx`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\MiscTools.test.tsx`

文档：

- `C:\Users\QAQ\Desktop\gshark\docs\misc-module-interface.md`
- `C:\Users\QAQ\Desktop\gshark\docs\ctf-neta-module-audit-and-development-report-2026-04-26-round7.md`

---

## 七、本轮评价

这一轮的价值在于把 MISC 模块体系重新拉回到了“协议专项能力”：

- 前几轮解决了模块如何被展示；
- 本轮补了一个真实可用的协议工具；
- 同时把 `cancellable` 这类开发字段转译成用户能理解的运行能力。

Shiro rememberMe 这个模块的落地方式也比较适合当前阶段：

- 后端提供结构化分析；
- 前端提供轻量工作台；
- MISC 注册表承载入口；
- 测试覆盖核心解密与识别逻辑；
- 后续可以自然接入包号/流号定位与更多 key 字典。

---

## 八、下一轮建议

下一轮建议继续做两条线：

1. **证据联动**
   - Shiro 候选 → 包号定位；
   - Shiro 候选 → HTTP/TCP stream 跳转；
   - HTTP 登录 / SMTP / MySQL 结果统一支持跳包与跳流。

2. **协议能力继续横向扩展**
   - Cobalt Strike Beacon HTTP/DNS 初筛；
   - Spring / Fastjson / Java 反序列化流量线索；
   - 更深的工控规则包级证据联动。

---

## 九、结论

本轮完成了一个明确的协议能力闭环：

- `Shiro rememberMe` 从模型占位变成了真实可用的 MISC 内建模块；
- 后端能扫描 Cookie、测试 key、识别 Java 序列化和 `deleteMe`；
- 前端能展示、筛选、刷新、提交自定义 key、导出结果；
- `cancellable` 的含义也被改成了清楚的产品语义：**支持中断**。

这意味着 MISC 页不再只是“更好看的模块容器”，而是在继续增长真实协议分析能力。
