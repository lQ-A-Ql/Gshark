# 日期: 2026-04-30
# 署名: Codex

# 前端 capture-scoped 请求生命周期治理与关闭抓包即时脱离报告（round36）

## 一、本轮复查评论

上一轮 round35 已经把页面级专题请求和部分 MISC 模块统一到 `useAbortableRequest`，解决了“同一页面内旧请求晚返回覆盖新状态”的通用问题。复查后确认：

- `useAbortableRequest` 适合 C2、APT、工控、媒体、USB、MISC 模块等页面级请求。
- `SentinelContext` 的抓包生命周期请求不适合直接套页面级 hook，因为它同时涉及 capture revision、关闭抓包、预加载轮询、威胁分析、流切换、packet detail、stream cache 和事件订阅。
- round35 仍遗留一个更核心的问题：关闭抓包时 UI 状态清理位于 `bridge.closeCapture()` 之后，如果后端正在清理威胁分析或长任务，用户会感觉“关闭仍在等待威胁分析”。
- 因此本轮重点不是继续扩展页面，而是给 `SentinelContext` 建立 capture-scoped 请求控制器，并把关闭抓包改成“前端立即脱离当前 capture，后端清理异步等待但不阻塞 UI 清空”。

## 二、本轮审计目标

本轮审计覆盖 `frontend/src/app/state/SentinelContext.tsx` 中与当前抓包强绑定的请求链路：

- 数据包分页加载；
- 过滤器加载与轮询；
- 预加载 probe；
- start capture 请求；
- stream index 刷新；
- HTTP / TCP / UDP stream 切换；
- stream prefetch cache；
- 威胁分析 / 对象导出结果刷新；
- packet detail / raw hex / layers；
- backend status / progress / error 事件回落。

本轮目标：

1. 关闭抓包后前端立即清空当前 capture UI，不再等后端威胁分析完成；
2. 关闭 / 切换抓包时 abort 所有前端可取消请求；
3. 即使请求无法真正取消，旧 scope 的结果也不能再写回当前 UI；
4. stream prefetch 不能把旧包缓存写进新包 stream cache；
5. 无 active capture 时忽略旧解析 / 威胁分析 / 媒体分析事件。

## 三、本轮开发变更

### 1. 新增 capture-scoped 任务控制器

新增文件：

- `frontend/src/app/utils/captureTaskScope.ts`
- `frontend/src/app/utils/captureTaskScope.test.ts`

核心能力：

- `createCaptureTaskScope()` 创建一个 capture 范围内的任务注册器；
- `beginTask(key)` 为某类任务创建 `AbortController` 与 scope guard；
- 同 key 新任务会自动 abort 旧任务；
- `invalidate()` 会递增 scope id，并 abort 当前所有注册任务；
- 每个 task 都有 `isCurrent()`，用于判断“当前结果是否还属于当前 capture scope”；
- `finish()` 清理当前任务注册，避免 controller 泄漏。

测试覆盖：

- 同 key 旧任务会被新任务 abort；
- scope invalidate 会 abort 所有 in-flight tasks；
- 不同 key 任务可以并行，并在 scope 失效时统一失效。

### 2. asyncControl 补充 abort-like error 识别

修改：

- `frontend/src/app/utils/asyncControl.ts`
- `frontend/src/app/hooks/useAbortableRequest.ts`

变更：

- 将 `isAbortLikeError(error, signal?)` 下沉到 `asyncControl`；
- `useAbortableRequest` 继续 re-export 该函数，保持现有页面导入兼容；
- `SentinelContext` 可直接复用同一 abort 判断，避免 `DOMException AbortError` 判断继续散落。

### 3. wailsBridge 增加 signal 透传

修改：

- `frontend/src/app/integrations/wailsBridge.ts`

新增可选 `AbortSignal` 的 bridge 方法：

- `startStreamingPackets(filePath, filter, signal?)`
- `locatePacketPage(packetId, limit, filter?, signal?)`
- `getPacket(packetId, signal?)`
- `listStreamIds(protocol, signal?)`
- `getPacketRawHex(packetId, signal?)`
- `getPacketLayers(packetId, signal?)`

这些方法现在可以被 capture-scoped task 直接取消。

### 4. SentinelContext 接入 captureTaskScope

修改：

- `frontend/src/app/state/SentinelContext.tsx`

已迁移到 capture scope 的任务包括：

- `packet-page`
- `packet-locate`
- `preload-page`
- `capture-start`
- `threat-analysis`
- `stream-index`
- `http-stream`
- `tcp-stream`
- `udp-stream`
- `prefetch-http-*`
- `prefetch-tcp-*`
- `prefetch-udp-*`
- `packet-detail`
- `packet-raw-hex`
- `packet-layers`

同时移除 / 替代了多处本地 `AbortController` ref：

- packet page abort ref；
- preload page abort ref；
- threat analysis abort ref；
- HTTP / TCP / UDP stream request abort ref。

### 5. 关闭抓包改为 UI 立即脱离

本轮重构 `stopCapture()`：

旧行为：

- 先 `cancelAllFrontendCaptureTasks()`；
- 然后等待 `bridge.cancelMediaBatchTranscription()` 与 `bridge.closeCapture()`；
- 等后端返回后才清空 packets、streams、threat hits、objects、file meta。

新行为：

- 立即递增 capture sequence / filter sequence；
- 立即 invalidate capture task scope；
- 立即清空 packets、streams、threat hits、objects、selected packet、hex、layers、stream cache、prefetch state、file meta；
- 立即将 `activeCapturePathRef.current` 置空并 bump `captureRevision`；
- UI 状态先显示“当前抓包已从界面移除，正在请求后端清理线程”；
- 后端 `closeCapture()` 完成后只更新最终状态文案，不再阻塞 UI 脱离。

这直接解决“关闭抓包时仍在等待威胁分析”的前端体验问题：即使后端还在执行清理，当前抓包也已经从前端 session 中失效。

### 6. 旧事件回落抑制

事件订阅中新增 active capture guard：

- 无 active capture 时，忽略旧 `__progress__`；
- 无 active capture 时，忽略旧解析、预加载、威胁分析、媒体流相关 status；
- 无 active capture 时，忽略旧解析、预加载、威胁分析、媒体流相关 error。

这样可以避免关闭抓包后，后端迟到的“威胁分析完成 / 解析完成 / 媒体流分析完成”状态重新污染 UI 状态栏。

## 四、验证结果

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npx tsc --noEmit
npm test -- captureTaskScope asyncControl useAbortableRequest
npm test -- captureTaskScope asyncControl useAbortableRequest MiscTools C2Analysis AptAnalysis TrafficGraph VehicleAnalysis UsbAnalysis
npm test
npm run build
```

验证结论：

- `npx tsc --noEmit`：通过；
- 基础请求生命周期测试：3 个测试文件，9 个测试通过；
- targeted tests：9 个测试文件，39 个测试通过；
- full tests：16 个测试文件，65 个测试通过；
- `npm run build`：通过。

构建观察：

- 本轮新增 `captureTaskScope` 属于小型纯工具，不引入第三方依赖；
- Vite build 仍显示 `MiscTools`、`UpdateCenter` 与主入口 chunk 偏大；
- 本轮未处理 chunk 拆分，该问题继续留到性能治理阶段。

## 五、风险与兼容性说明

- 本轮主要处理前端 session 失效与旧请求回落；如果后端自身 `closeCapture()` 仍有长耗时清理，前端现在不会再等它清完才清 UI，但后端锁粒度仍需要后续继续审计。
- `activeCapturePathRef.current` 现在是旧 capture 状态回落的核心屏障；后续新增 capture-scoped 请求必须检查 active capture 或接入 `captureTaskScope`。
- stream prefetch 现在虽然默认 `STREAM_PREFETCH_LIMIT = 0`，但相关代码已接入 scope guard，未来打开预取时不会把旧包 stream 写入新包 cache。
- `useAbortableRequest` 仍用于页面级请求；`captureTaskScope` 用于 `SentinelContext` 这类 capture 生命周期请求，二者职责不同。

## 六、遗留问题

本轮仍未处理：

- 后端 `closeCapture()` / 威胁分析 / runtime config / TLS config 的锁竞争与取消传播；
- 真实浏览器低高度 / 窄宽窗口视觉复核；
- `MiscTools`、`UpdateCenter` 和主入口 chunk 拆分；
- WinRM、SMB3、Payload / WebShell 等剩余复杂 MISC 模块是否需要进一步迁移到 `useAbortableRequest`。

## 七、下一轮建议

下一轮建议进入两个方向之一：

1. **后端关闭抓包链路审计**：检查 `/api/capture/close`、威胁分析、对象导出、媒体分析、runtime config 是否共享锁或等待长任务，确保后端真正快速取消；
2. **继续前端性能治理**：从 `MiscTools` 开始做内建模块懒加载，把低频重模块从首屏 chunk 中拆出去。

优先建议先做后端关闭链路审计，因为本轮已解决前端即时脱离，但如果后端清理持续占锁，仍可能影响下一次打开抓包或 runtime 检测。
