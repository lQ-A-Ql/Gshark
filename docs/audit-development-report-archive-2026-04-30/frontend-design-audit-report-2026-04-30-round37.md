# 日期: 2026-05-01
# 署名: Codex

# 前端测试闭环、MISC 懒挂载与下一阶段计划落地报告（round37）

## 一、本轮复查评论

round36 已经把 `SentinelContext` 的抓包生命周期请求纳入 `captureTaskScope`，关闭抓包也改成前端 UI 立即脱离旧 capture。本轮按照“先执行 test，再依据现有状态落地新 plan”的要求，先从测试结果回看当前前端稳定性。

复查后确认：

- 之前的主风险不再是单一页面样式不一致，而是前端异步请求边界是否真的与 UI 可见状态一致。
- MISC 页面虽然已成为工具箱入口，但折叠模块仍可能在不可见状态下挂载，导致 HTTP / MySQL / SMTP / Shiro / NTLM / SMB3 等模块在首屏同时发起请求。
- USB 页面默认页签选择仍需要兼容后端不同形态的数据：有些样本可能只填充嵌套结构，顶层 packet count 不一定完整。
- Payload / WebShell 解码模块存在一个轻微但真实的交互竞态：点击“示例”后立即点击“识别候选”时，可能读到旧的 React state。
- 测试基础设施在 Windows + jsdom + 全套 UI 测试并发下存在等待窗口偏短的问题，容易把真实慢渲染误判为失败。

因此本轮将新计划落地为三件事：稳定测试、修复真实异步/挂载边界、把下一阶段计划从“继续泛化优化”收束为“前端懒加载与真实浏览器回归”。

## 二、本轮审计目标

本轮覆盖范围：

- `frontend/src/app/pages/MiscTools.tsx`
- `frontend/src/app/pages/MiscTools.test.tsx`
- `frontend/src/app/pages/UsbAnalysis.tsx`
- `frontend/src/app/misc/modules/PayloadWebShellDecoderModule.tsx`
- `frontend/src/test/setup.ts`

目标：

1. 先跑测试，定位当前失败是业务逻辑缺陷、测试契约过期，还是异步边界不稳；
2. 修复 MISC 折叠模块不可见但仍后台请求的问题；
3. 修复 Payload 示例输入后立即识别的旧 state 竞态；
4. 修复 USB 默认页签对嵌套数据的兼容问题；
5. 将测试契约更新为“默认只挂载首个 MISC 模块，其余模块展开后才请求”；
6. 依据测试结果续写报告，并把下一阶段计划写入合并摘要。

## 三、本轮开发变更

### 1. MISC 模块从“折叠但已挂载”改为“展开后懒挂载”

修改：

- `frontend/src/app/pages/MiscTools.tsx`

新增 `mountedModules` 状态，用于区分“模块是否曾经挂载过”和“模块当前是否展开”。

新行为：

- 初次加载模块列表后，仅默认首个模块会自动挂载；
- 用户展开某个模块时，该模块才会挂载并发起自身请求；
- 用户收起后，已挂载模块保留内部状态，避免反复展开时丢失输入；
- 刷新模块列表时，只保留仍存在且曾挂载过的模块状态；
- 删除或导入模块导致列表变化时，已消失模块不会继续残留在 `mountedModules` 中。

修复价值：

- 避免 MISC 首屏同时请求 HTTP 登录、MySQL、SMTP、Shiro、NTLM、SMB3 等全部工具；
- 降低页面初次进入时的无意义后端压力；
- 让 UI 可见状态与网络请求生命周期更一致；
- 为后续 `MiscTools` chunk 拆分和模块级动态加载打基础。

### 2. MISC 测试契约改为按需请求

修改：

- `frontend/src/app/pages/MiscTools.test.tsx`

测试现在明确断言：

- 首屏只会请求模块清单和默认首个模块；
- MySQL、SMTP、Shiro、NTLM、SMB3 不应在未展开时请求；
- 展开 `ntlm-session-materials` 后才请求 NTLM 材料；
- 展开 `mysql-session-analysis` 后才请求 MySQL；
- 展开 `smtp-session-analysis` 后才请求 SMTP；
- 展开 `shiro-rememberme-analysis` 后才请求 Shiro；
- 展开 `smb3-session-key` 后才请求 SMB3 Session 候选；
- SMB3 自动填充测试也改为先展开模块，再等待候选加载。

这不是单纯“改测试适配实现”，而是把产品边界写成可回归的测试契约：隐藏模块不应悄悄工作。

### 3. Payload 示例输入识别竞态修复

修改：

- `frontend/src/app/misc/modules/PayloadWebShellDecoderModule.tsx`

新增 `draftRef` 保存 textarea 当前值，并在以下动作中同步更新：

- 手动输入；
- 清空；
- 使用示例；
- 点击识别候选。

修复后，用户点击“示例”后立即点击“识别候选”时，`inspectStreamPayload` 会收到最新示例内容，而不是空字符串或旧输入。

### 4. USB 默认页签兼容嵌套数据

修改：

- `frontend/src/app/pages/UsbAnalysis.tsx`

`domainHasData()` 不再只依赖顶层计数字段，同时检查嵌套业务数据：

- HID：`keyboardEvents`、`mouseEvents`、`hid.keyboardEvents`、`hid.mouseEvents`、`hid.devices`；
- Mass Storage：`massStorage.readOperations`、`writeOperations`、`devices`、`commands`；
- Other USB：`otherRecords`、`other.records`、`controlRecords`、`setupRequests`。

修复价值：

- 后端字段演进或不同样本只填充结构化明细时，前端仍能默认切到有数据的页签；
- 避免页面看起来“无数据”，但切到子页后其实有 HID / Storage / Other 明细的错觉。

### 5. 测试异步等待窗口稳定化

修改：

- `frontend/src/test/setup.ts`

通过 Testing Library `configure({ asyncUtilTimeout: 3000 })` 将默认异步等待窗口从 1s 提升到 3s。

原因：

- 当前全量测试包含 C2、MISC、USB、TLS Dialog 等较重 UI；
- Windows + jsdom 环境下全套并发时，部分测试不是逻辑失败，而是等待窗口过短；
- 该调整不放宽断言，只减少慢渲染导致的误报。

## 四、验证结果

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npm test -- MiscTools UsbAnalysis
npm test
npx tsc --noEmit
npx tsc --noEmit --noUnusedLocals --noUnusedParameters
npm run build

cd C:\Users\QAQ\Desktop\gshark
go test ./backend/internal/transport ./backend/internal/engine
```

验证结论：

- `npm test -- MiscTools UsbAnalysis`：通过，2 个测试文件，16 个测试通过；
- `npm test`：通过，16 个测试文件，65 个测试通过；
- `npx tsc --noEmit`：通过；
- `npx tsc --noEmit --noUnusedLocals --noUnusedParameters`：通过；
- `go test ./backend/internal/transport ./backend/internal/engine`：通过；
- `npm run build`：通过。

构建观察：

- `MiscTools` chunk 约 140.90 kB，仍是后续拆分重点；
- `UpdateCenter` chunk 约 168.10 kB，Markdown / 更新中心相关依赖仍偏重；
- 主入口 `index` chunk 约 497.42 kB，后续应继续检查首屏依赖；
- `logo` 资源约 2.58 MB，仍是资源体积审计候选。

## 五、风险与兼容性说明

- 本轮 MISC 懒挂载会改变部分模块的请求时机：隐藏模块不会再提前预热数据。这符合产品预期，但如果后续某模块依赖“后台提前加载”，需要明确改成独立预取策略，而不是靠折叠内容挂载副作用。
- 已挂载模块在收起后保留状态，方便用户恢复输入；如果后续某模块处理超大结果，需要评估收起时是否释放内存。
- 测试异步等待窗口提升到 3s 是测试稳定性调整，不代表业务请求可以无限等待；业务请求仍应继续走 `useAbortableRequest`、`withTimeout` 或 `captureTaskScope`。
- 浏览器插件验收在本轮命令行测试后曾尝试启动，但交互被中断；本轮最终以自动化测试、类型检查、构建和后端目标测试作为闭环依据。

## 六、依据当前状态落地的新 plan

### 第一层：MISC 模块懒加载产品化

- 将当前“懒挂载”继续推进为“模块级动态 import”，优先拆 `MiscTools` 大 chunk。
- 对 Payload / WinRM / SMB3 / NTLM 等低频重模块建立独立加载边界。
- 模块展开时显示轻量加载骨架，避免用户误以为点击无响应。

### 第二层：隐藏面板后台请求审计

- 复查所有 `CollapsibleContent`、Tabs、Dialog、Popover 中被隐藏但仍挂载的重组件。
- 重点检查 C2 展开详情、USB 子页、UpdateCenter、对象导出、媒体预览。
- 对“隐藏仍需保持状态”和“隐藏应释放/不请求”建立明确约定。

### 第三层：前端异步边界一致化

- 页面级专题请求继续默认使用 `useAbortableRequest`；
- 抓包生命周期请求继续默认使用 `captureTaskScope`；
- 长耗时初始化继续使用 `withTimeout` 或 degraded 进入；
- 新增 MISC 模块必须说明 `cancellable`、请求取消策略和过期结果处理策略。

### 第四层：真实浏览器回归补齐

- 继续用 in-app browser 或本地浏览器覆盖低高度、窄宽、MISC 模块展开/收起、HEX 横向滚动、右键菜单边界和 Select 下拉。
- 浏览器回归优先关注视觉和交互，不替代单测。
- 若浏览器插件中断，应记录为未完成项，不把命令行测试结果伪装成视觉验收。

### 第五层：构建体积治理

- 优先拆 `MiscTools`、`UpdateCenter`、主入口 chunk；
- 检查大 logo 资源是否能压缩、延迟加载或替换；
- 建立 chunk 观察清单，避免后续协议模块继续把低频工具塞进首屏。

## 七、下一轮建议

下一轮建议从 `MiscTools` chunk 拆分开始，而不是继续广泛改样式：

1. 先把 MISC 内建模块 renderer 做动态 import；
2. 保留当前懒挂载状态，展开模块时再加载对应 renderer；
3. 给 Payload / WebShell、WinRM、SMB3、NTLM 这类重模块单独建立加载骨架；
4. 跑 `npm test`、`npm run build`，对比 chunk 输出；
5. 再用浏览器做 `/misc` 展开/收起和模块切换冒烟。

如果要继续处理后端，则建议并行审计 `closeCapture`、威胁分析和 runtime config 锁竞争；但从本轮测试结果看，前端下一步最直接的收益是 MISC 模块级懒加载与首屏体积治理。
