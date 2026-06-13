# 日期: 2026-04-30
# 署名: Codex

# 前端真实浏览器复核与启动门降级修复报告（round34）

## 一、对上一轮（round33）的复盘评论

round33 的结论总体成立：共享 `viewportPosition`、`useViewportSafePosition`、`FloatingSurface`、Tooltip collision、下载/复制统一入口和复杂表格扫描，已经把“前端第一优先级闭环”中的代码层基座补齐。

本轮首先纠正轮次基准：最新报告确认为 `frontend-design-audit-report-2026-04-30-round33.md`，因此本轮编号为 **round34**。

对 round33 的复盘意见如下：

1. **最主要遗留是“真实浏览器截图级走查未执行”**  
   round33 已经给出视觉回归清单，但未完成真实浏览器执行。本轮已通过 `@browser-use` / in-app browser 打开本地 Vite 页面，并用本地 API 后端加载 `http.pcap` 做交互复核。

2. **共享浮层方案方向正确**  
   数据包表格右键菜单在真实浏览器中右下区域触发后，菜单被限制在视口内，没有继续出现前端越界。该项从“单测保障”升级为“真实页面可见行为已复核”。

3. **浏览器复核暴露出 round33 未覆盖的新启动链路问题**  
   在后端仍处理上一轮长耗时 HTTP stream / threat-like 分析时，前端刷新或直达 `/misc` 会停在启动页：后端健康检查已连接，但运行时组件检测请求被长任务拖住，导致 `tshark：检测中` 一直阻塞进入主界面。  
   这个问题不是视觉样式问题，而是启动门与长耗时后台任务耦合的问题；如果不修复，会直接影响用户在大包分析、威胁分析或流追踪后台仍忙时切换页面。

4. **MISC 页面当前视觉方向基本符合上一轮要求**  
   `/misc` 真实浏览器截图中，页面为浅色主背景、Hero 与模块工作台分层清晰，未再出现早期“深色页 / 玻璃暗卡 / 卡片里套重卡片”的主问题。仍可继续优化的是模块内局部统计条、详情区和表格密度，但不再属于阻断级缺陷。

## 二、本轮审计目标

本轮目标从 round33 遗留清单展开：

- 使用真实浏览器执行可落地的视觉回归片段；
- 复核数据包右键菜单视口边界；
- 复核 MISC 页面实机显示；
- 捕捉并修复真实运行中出现的新前端阻塞问题；
- 续写 round34 报告并更新归档索引。

## 三、本轮真实浏览器复核记录

### 1. 本地运行环境

启动方式：

```powershell
cd C:\Users\QAQ\Desktop\gshark
$env:GSHARK_BACKEND_TOKEN='dev'; go run ./backend/cmd/sentinel serve 127.0.0.1:17891

cd C:\Users\QAQ\Desktop\gshark\frontend
$env:VITE_BACKEND_TOKEN='dev'; npm run dev -- --host 127.0.0.1 --port 5173
```

浏览器目标：

```text
http://127.0.0.1:5173/
```

使用样例：

```text
C:\Users\QAQ\Desktop\gshark\http.pcap
```

### 2. 工作区加载复核

结果：

- 后端连接成功；
- `http.pcap` 成功加载；
- 数据包表格渲染出 6,144 packets；
- 主工作区保持白底、浅色工具栏、浅色协议树与 HEX 面板；
- 底部状态栏能显示当前抓包、显示数量、缓存数量、后端总计和 TLS / engine 状态。

### 3. 数据包右键菜单复核

操作：

- 在数据包表格靠近右下区域执行右键；
- 观察菜单是否被挤出视口或遮挡。

结果：

- 右键菜单正常显示；
- 菜单内容包括 TCP / UDP / HTTP 追踪动作；
- 菜单被限制在视口内，没有向右或向下越界；
- 说明 round33 的 `useViewportSafePosition` + `FloatingSurface` 集成在真实页面中有效。

### 4. MISC 页面复核

操作：

```text
http://127.0.0.1:5173/misc
```

结果：

- 页面最终能进入 `MISC 工具箱`；
- Hero、能力标签、导入按钮、模块工作台统一为浅色风格；
- HTTP 登录行为分析工作台默认展开，按钮数量、徽标、筛选、导出按钮和详情空态可读；
- 未复现早期“卡片套深卡片 / 暗色玻璃层 / 标题区风格突兀”的主问题。

### 5. 真实复核中发现的新问题

在后端仍处理上一轮长耗时流分析时，刷新或直达 `/misc` 会出现：

```text
后端服务：已连接
tshark：检测中
后端已连接，等待打开文件
```

同时，手动请求运行时配置接口会超时：

```powershell
Invoke-RestMethod http://127.0.0.1:17891/api/tools/runtime-config ... -TimeoutSec 5
# TaskCanceledException: timeout
```

判断：

- 这说明启动门不应无限等待“运行时组件检测”；
- 后端健康已连接时，前端应该允许降级进入主界面，并提示用户稍后在设置侧栏刷新；
- 否则任何后台长任务都可能让用户误以为前端或后端启动失败。

## 四、本轮代码优化

### 1. 新增通用异步超时工具

新增文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\utils\asyncControl.ts`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\utils\asyncControl.test.ts`

新增能力：

- `OperationTimeoutError`：结构化超时错误；
- `isOperationTimeoutError(error)`：类型守卫；
- `withTimeout(operation, timeoutMs, message)`：为启动检测、轻量初始化请求等提供统一超时保护。

该工具先服务启动链路，后续可继续迁移 cancellable / stale-result 保护相关逻辑，作为统一请求生命周期治理的基础。

### 2. 启动运行时检测增加有限等待

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\state\SentinelContext.tsx`

新增常量：

```ts
const STARTUP_TOOL_RUNTIME_TIMEOUT_MS = 3500;
const STARTUP_TLS_CONFIG_TIMEOUT_MS = 2500;
```

优化点：

- `bridge.updateToolRuntimeConfig(savedConfig)` 启动阶段最多等待 3.5 秒；
- `bridge.getTLSConfig()` 启动阶段最多等待 2.5 秒；
- 如果运行时组件检测超时或失败，设置 `toolRuntimeCheckDegraded=true`；
- 状态文案改为：

```text
运行时组件检测超时，已先进入主界面；可在设置侧栏刷新状态
```

- 成功刷新 runtime snapshot、保存 runtime config 或手动设置 tshark path 后，会自动清除 degraded 状态。

### 3. StartupGate 支持降级进入主界面

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\App.tsx`

优化点：

- 启动门进入条件从“必须 `tsharkStatus.available`”调整为：

```ts
backendConnected && !isTSharkChecking && (tsharkStatus.available || toolRuntimeCheckDegraded)
```

- 检测超时时，启动页显示：

```text
tshark：稍后重试
运行时组件检测超时，已先进入主界面；可在设置侧栏刷新状态
```

- 不再显示强制配置 tshark 的错误卡片，避免把“检测暂时被长任务阻塞”误判为“tshark 不可用”；
- 进度条在降级状态下走满，随后自动进入主界面。

## 五、验证结果

### 1. TypeScript 类型检查

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npx tsc --noEmit
```

结果：

- 通过。

### 2. 目标单测

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npm test -- asyncControl viewportPosition PacketVirtualTable
```

结果：

- 通过，3 个测试文件、13 个测试通过。

### 3. 全量前端单测

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npm test
```

结果：

- 通过，14 个测试文件、59 个测试通过。

### 4. 生产构建

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npm run build
```

结果：

- 通过，Vite production build 成功。
- 构建体积遗留仍存在：`MiscTools`、`UpdateCenter`、主入口 `index` 依旧是后续性能治理重点。

### 5. 真实浏览器验证

已执行：

- 打开 `http://127.0.0.1:5173/`；
- 本地 UI 加载 `C:\Users\QAQ\Desktop\gshark\http.pcap`；
- 在数据包表格右下区域触发右键菜单；
- 打开 `http://127.0.0.1:5173/misc`；
- 模拟后端长任务占用时刷新页面，观察启动门超时降级。

结果：

- 数据包右键菜单未越界；
- MISC 页面可进入且保持浅色准线；
- 启动运行时检测超时后不再永久卡在启动页，约 3.5 秒后以降级状态进入主界面；
- 底部状态栏保留“运行时组件检测超时，可在设置侧栏刷新状态”的提示。

## 六、当前收益

- round33 的“真实浏览器视觉回归未执行”遗留，本轮已完成首批真实浏览器复核。
- 右键菜单边界从单测验证升级为真实页面交互验证。
- 修复了浏览器复核暴露的启动门阻塞问题：后端忙于长任务时，前端不再无限等待 runtime check。
- 增加了可复用的 `asyncControl` 工具，为后续统一 cancellable 请求 hook、超时保护、stale-result 管理提供基础。
- MISC 页面在真实浏览器下符合当前浅色单主题准线，可继续作为页面视觉标准。
- 全量前端测试和生产构建均通过，新增逻辑没有破坏 C2/APT、MISC、USB、TrafficGraph 等现有测试。

## 七、遗留问题与下一轮建议

### 遗留问题

1. 本轮完成真实浏览器基础复核，但还没有覆盖低高度窗口、窄宽窗口、长表格展开后的全部滚动边界。
2. 本轮使用启动阶段 `withTimeout` 解决“无限等待”问题，但底层请求仍未真正通过 `AbortSignal` 取消；后续应继续推进统一 cancellable 请求 hook。
3. 后端长任务期间 `/api/tools/runtime-config` 被拖慢，前端已降级规避，但后端侧并发/锁粒度仍值得后续审计。
4. `MiscTools`、`UpdateCenter`、主入口 chunk 仍偏大，性能治理尚未开始。
5. 降级状态目前是“允许进入 + 设置侧栏刷新”，后续可增加显式 toast 或状态栏操作按钮，提升可发现性。

### 下一轮建议

1. 继续执行真实浏览器视觉回归：低高度窗口、窄屏、长表格展开、HEX 横向滚动、MISC 下拉/折叠动画。
2. 推进统一 cancellable 请求 hook，优先覆盖 MISC 专项模块、C2/APT 页面和启动 runtime 请求。
3. 审计后端运行时配置接口与长耗时分析之间的锁竞争，避免轻量状态接口被流追踪批量任务拖慢。
4. 若继续做前端治理，优先拆分 `MiscTools` 内建模块为 lazy chunks，降低首次进入 MISC 的成本。
5. 保持浅色单主题和功能性高对比白名单，不新增 `dark:` 分支。
