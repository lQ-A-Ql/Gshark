# 日期: 2026-04-30
# 署名: Codex

# 前端统一 cancellable 请求 hook 与浏览器路由复核报告（round35）

## 一、本轮复查评论

上一轮 round34 的重点是把真实浏览器视觉复核落到本地运行环境，并修复启动阶段 runtime 检测在后端长任务期间阻塞入口的问题。复盘后结论如下：

- round34 已经把“只靠单测 / 构建验证”的风险往真实浏览器推进了一步，尤其是数据包右键菜单边界、MISC 页面实机显示和启动门 degraded 进入机制。
- round34 仍遗留一个更基础的前端工程问题：页面和 MISC 模块里存在多处手写 `AbortController`、`AbortError` 判断和过期结果保护逻辑；这些逻辑虽然局部可用，但分散实现会继续带来状态串台风险。
- round34 新增的 `asyncControl.withTimeout` 适合解决“有限等待”问题，但不直接替代“同一视图内只允许一个当前请求生效”的请求生命周期治理。
- 因此本轮不继续堆新页面，而是优先抽象并迁移统一 cancellable 请求 hook，同时用浏览器路由冒烟验证页面切换不会把旧请求结果回落到当前 UI。

## 二、本轮审计范围

本轮重点审计以下前端请求链路：

- C2 样本分析页；
- APT 组织画像页；
- 工控分析页；
- 流量图页；
- USB 分析页；
- 车机分析页；
- 媒体分析页；
- MISC 内建模块：HTTP 登录、MySQL、SMTP、Shiro rememberMe。

审计目标是找出重复请求取消模式，并把可证明等价的实现迁移到同一个基础 hook：

- 新请求开始时取消上一请求；
- 组件卸载时取消当前请求；
- 忽略 abort-like error；
- 旧请求晚返回时不能覆盖新状态；
- `onSettled` 只对当前请求触发，避免旧请求把 loading 提前置回 false。

## 三、本轮开发变更

### 1. 新增统一请求生命周期 hook

新增文件：

- `frontend/src/app/hooks/useAbortableRequest.ts`
- `frontend/src/app/hooks/useAbortableRequest.test.tsx`

该 hook 提供：

- `run({ request, onSuccess, onError, onSettled })`：启动一个可取消请求；
- `cancel()`：取消当前请求并递增序号，阻断旧响应；
- `isAbortLikeError(error, signal?)`：统一识别 `AbortError`、signal aborted 和常见 aborted message。

核心行为：

- 每次 `run` 前会主动 abort 上一个 controller；
- 内部使用 sequence guard，保证旧请求即使晚返回也不会进入 `onSuccess` / `onError`；
- hook unmount 时自动执行 `cancel`；
- `onSettled` 只在当前请求仍然是最新 controller 时触发。

### 2. 页面级迁移

以下页面已从本地 `AbortController` 模式迁移到统一 hook：

- `frontend/src/app/pages/C2Analysis.tsx`
- `frontend/src/app/pages/AptAnalysis.tsx`
- `frontend/src/app/pages/IndustrialAnalysis.tsx`
- `frontend/src/app/pages/TrafficGraph.tsx`
- `frontend/src/app/pages/UsbAnalysis.tsx`
- `frontend/src/app/pages/VehicleAnalysis.tsx`
- `frontend/src/app/pages/MediaAnalysis.tsx`

迁移后收益：

- 页面刷新、路由切换、抓包切换导致的旧请求回落风险降低；
- `AbortError` 文案处理不再散落在每个页面；
- loading 状态不会被旧请求的 finally 抢先关闭；
- 后续新增专题页可以直接复用同一 hook。

### 3. MISC 模块迁移

以下内建模块已迁移：

- `frontend/src/app/misc/modules/HTTPLoginAnalysisModule.tsx`
- `frontend/src/app/misc/modules/MySQLSessionAnalysisModule.tsx`
- `frontend/src/app/misc/modules/SMTPSessionAnalysisModule.tsx`
- `frontend/src/app/misc/modules/ShiroRememberMeAnalysisModule.tsx`

兼容细节：

- HTTP / MySQL / SMTP 的刷新动作继续保留当前选择上下文，避免刷新后丢失已选 endpoint / session。
- Shiro rememberMe 的 effect 不再随自定义 key 文本逐字触发全量分析；手动分析按钮仍可把当前 key 列表传给后端。
- MISC 模块在切换、刷新或卸载时统一取消旧请求，符合 manifest 中 `cancellable=true` 的产品语义。

### 4. 浏览器实机发现并修复 MainLayout key 警告

本轮通过浏览器路由冒烟发现 React duplicate key warning：`MainLayout` 中背景 fade 层和 route 容器都使用同一 pathname 作为 sibling key，在路由切换时会出现重复 key。

修复文件：

- `frontend/src/app/layouts/MainLayout.tsx`

修复方式：

- 背景 fade 层改为 `key={`fade-${backgroundFade.key}`}`；
- route 容器改为 `key={`route-${location.pathname}`}`。

复核结论：

- 浏览器日志中保留了修复前的旧 warning 时间戳；
- 修复并 reload 后继续进行路由切换冒烟，未观察到新的 duplicate-key 时间戳。

## 四、浏览器复核结果

本轮启动本地后端与前端：

- 后端：`go run ./backend/cmd/sentinel serve 127.0.0.1:17891`
- 前端：`npm run dev -- --host 127.0.0.1 --port 5173`

使用浏览器执行：

- 打开 `/misc`，确认 MISC 页面能进入并显示 HTTP 登录模块，无启动门长时间卡死；
- 快速切换 `/c2-analysis`、`/apt-analysis`、`/traffic-graph`、`/media-analysis`、`/usb-analysis`、`/misc`；
- 最终落点保持在 `/misc`，页面没有因为旧请求晚返回跳回其它页面状态；
- 在路由冒烟过程中发现并修复了 `MainLayout` duplicate key warning。

限制说明：

- 本轮浏览器工具主要用于真实路由与控制台复核；低高度 / 窄宽窗口、HEX 横向滚动和长表格展开仍需后续继续覆盖。

## 五、验证结果

已执行前端验证：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npx tsc --noEmit
npm test -- useAbortableRequest asyncControl C2Analysis AptAnalysis TrafficGraph VehicleAnalysis UsbAnalysis MiscTools
npm test
npm run build
```

验证结论：

- `npx tsc --noEmit`：通过；
- targeted tests：8 个测试文件，36 个测试通过；
- full tests：15 个测试文件，62 个测试通过；
- `npm run build`：通过。

构建观察：

- 新增 `useAbortableRequest` chunk 体积很小，约 0.94 kB；
- `MiscTools`、`UpdateCenter` 和主入口 chunk 仍偏大，后续仍应作为性能治理目标。

## 六、对当前前端状态的影响

本轮完成后，前端请求生命周期从“页面局部手写取消”推进为“共享 hook 可复用基座”：

- 页面级专题分析请求更一致；
- MISC cancellable 语义更可信；
- 旧请求回落和 loading 串台风险下降；
- 后续继续迁移 `SentinelContext` 或抓包生命周期请求时，有了可复用参考实现。

这与前几轮已落地的共享浮层定位、共享表格、共享下载 / 复制工具一起，构成当前前端稳定性治理的四个基础方向：

1. 视口安全浮层；
2. 统一业务表格；
3. 统一浏览器文件 / 剪贴板动作；
4. 统一 cancellable 请求生命周期。

## 七、遗留问题

本轮没有迁移以下内容：

- `SentinelContext` 内的抓包加载、数据包列表、威胁分析、流追踪等生命周期请求。这些请求与 capture revision、关闭抓包、线程清理和缓存失效强耦合，不能简单套用页面级 hook，下一轮应单独设计 capture-scoped request helper。
- 后端长任务与 runtime config lock 的竞争关系仍未系统审计。round34 已做前端 degraded 兜底，但后端锁粒度仍需要继续复查。
- 低高度 / 窄宽窗口真实视觉回归仍未完全闭环。
- chunk 拆分仍未开始，`MiscTools`、`UpdateCenter` 和入口包仍是主要体积热点。

## 八、下一轮建议

下一轮建议继续围绕“请求生命周期 + 真实浏览器复核 + 性能入口”推进：

1. 为 `SentinelContext` 设计 capture-scoped 请求控制器，保证关闭抓包后旧 capture 的数据包、威胁分析、流结果绝不回落 UI。
2. 继续执行浏览器低高度 / 窄宽场景，覆盖长表格、MISC select、HEX 横向滚动、C2 / USB 展开行。
3. 开始拆分 `MiscTools` 内建模块加载路径，优先把低频重模块延迟加载。
4. 审计后端 runtime config / TLS config / 长任务分析的锁竞争，避免再出现启动检测被分析任务拖慢的问题。
5. 将新增 hook 写入前端工程约定：新页面请求默认使用 `useAbortableRequest`，只有 capture 生命周期强耦合请求才允许使用专门控制器。
