# 日期: 2026-04-26
# 署名: Codex

# CTF-NetA Module Audit & Development Report - Round 9

## 一、本轮目标

上一轮完成了 Shiro rememberMe 的证据联动。本轮开始按“逐层清理”的方式处理冗余代码，并继续把清理过程记录到 `docs` 报告中。

本轮不做大范围重构，先处理两类确定性较高、回归风险较低的冗余：

1. TypeScript 编译器明确指出的未用符号；
2. MISC 协议模块中重复出现的 JSON / TXT 导出下载逻辑。

---

## 二、清理前复查结论

本轮先执行了综合冗余统计，确认当前主要冗余热点包括：

- 前端存在 6 个 `--noUnusedLocals --noUnusedParameters` 明确报出的未用符号；
- MISC 协议模块中多处重复实现：
  - 构造导出文件名；
  - `JSON.stringify(..., null, 2)`；
  - 文本格式渲染分支；
  - `Blob` 创建；
  - `URL.createObjectURL`；
  - 临时 `<a>` 下载触发；
  - `URL.revokeObjectURL`。
- `HTTPLoginAnalysisModule`、`MySQLSessionAnalysisModule`、`SMTPSessionAnalysisModule`、`ShiroRememberMeAnalysisModule`、`NTLMSessionMaterialsModule` 均存在同类导出逻辑。

这些点比 TCP/UDP 流页面合并、MISC 全局壳层抽象更安全，适合作为第一轮清理入口。

---

## 三、本轮清理实现

### 3.1 清理 TypeScript 高置信未用符号

清理内容：

- 移除 `captureOverview.ts` 中未使用的 `buildQuickFilters` 参数；
- 移除 `MainLayout.tsx` 中未使用的 `Hexagon` 图标导入；
- 移除 `MySQLSessionAnalysisModule.tsx` 中未使用的 `ShieldCheck` 图标导入；
- 移除 `MediaAnalysis.tsx` 中未使用的 `SpeechBatchTaskItem` 类型导入；
- 移除 `UsbAnalysis.tsx` 中未使用的 `MousePointer2` 图标导入；
- 移除 `UpdateCenter.tsx` 中未使用的 `tone` 计算和仅服务于该变量的 `statusTone` helper，同时移除 `useMemo` 导入。

这部分清理不改变运行行为，只删除编译器已确认未被读取的符号。

### 3.2 抽取 MISC 结构化结果导出 helper

新增文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\exportResult.ts`

新增能力：

- `MiscExportFormat`
  - 统一表示 `"json" | "txt"`；
- `exportStructuredResult`
  - 输入文件名前缀、导出格式、结构化 payload、文本渲染函数；
  - JSON 分支统一使用 `JSON.stringify(payload, null, 2)`；
  - TXT 分支复用各模块已有的文本渲染函数；
  - 统一负责 `Blob`、`URL.createObjectURL`、临时下载链接和 `URL.revokeObjectURL`。

### 3.3 替换重复导出实现

已替换的模块：

- `HTTPLoginAnalysisModule`
- `MySQLSessionAnalysisModule`
- `SMTPSessionAnalysisModule`
- `ShiroRememberMeAnalysisModule`
- `NTLMSessionMaterialsModule`

保持不变的行为：

- 导出按钮文案不变；
- 导出文件名不变；
- JSON 格式不变；
- TXT 内容渲染不变；
- 空结果禁用逻辑不变。

对 NTLM 会话材料模块，新增 `renderMaterialsText(rows)` 仅用于保留原先多条材料之间的分隔符拼接规则。

---

## 四、本轮收益

### 4.1 确定性冗余归零

清理前：

```text
npx tsc --noEmit --noUnusedLocals --noUnusedParameters
```

会报出 6 个未用符号。

清理后：

- 该检查通过；
- 未用局部变量和未用参数的确定性冗余归零。

### 4.2 MISC 导出逻辑集中化

清理前：

- 多个 MISC 模块重复维护 Blob 下载逻辑；
- 后续新增协议模块时容易继续复制；
- 如果要调整导出 MIME、释放 URL、下载触发方式，需要多处修改。

清理后：

- `Blob` 和 `URL.createObjectURL` 只保留在 `exportResult.ts`；
- 各协议模块只保留自己的文件名前缀和 TXT 渲染函数；
- 后续协议模块可以直接复用同一 helper。

---

## 五、验证记录

### 5.1 未用符号检查

执行命令：

```powershell
npx tsc --noEmit --noUnusedLocals --noUnusedParameters
```

执行目录：

```text
C:\Users\QAQ\Desktop\gshark\frontend
```

结果：

- 通过。

### 5.2 MISC 导出逻辑复查

复查结果：

- MISC 模块内 `Blob` / `URL.createObjectURL` 逻辑已集中到 `exportResult.ts`；
- 各模块仍保留轻量 `exportAnalysis` / `exportMaterials` wrapper，用于传入本模块的 payload 和文本渲染函数。

### 5.3 MISC 专项测试

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
- 9 个测试通过。

### 5.4 前端全量测试

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

### 5.5 前端生产构建

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
- Vite 成功生成 `dist` 产物；
- `MiscTools` chunk 从上一轮约 `115.91 kB` 下降到约 `115.22 kB`，属于轻微但可见的收敛。

---

## 六、下一层清理建议

下一轮建议继续按低风险到高风险推进：

1. **MISC 加载状态抽象**
   - 抽 `AbortController` 分析请求模式；
   - 统一 `hasCapture`、`loading`、`error`、空结果重置逻辑。

2. **MISC Notes / 导出按钮 UI 抽象**
   - 抽通用 notes 渲染；
   - 抽 JSON / TXT 双按钮组件；
   - 减少每个协议模块重复 JSX。

3. **TCP / UDP Stream 页面合并**
   - 两个页面相似度最高，但涉及流切换体验，建议单独一轮做；
   - 优先抽共享 `RawStreamPage`，再保留协议差异参数。

4. **超大文件拆分**
   - `wailsBridge.ts` 可按协议域拆 mapper；
   - `SentinelContext.tsx` 可拆 packet state、stream state、analysis cache；
   - `http_server.go` 可按 tools / stream / capture / update 分组。

---

## 七、结论

Round 9 完成了第一层冗余清理：

- 删除 TypeScript 编译器明确指出的未用符号；
- 抽取 MISC 结构化导出 helper；
- 将 5 个 MISC 模块的 Blob 下载逻辑收敛到单一实现；
- 保持用户可见行为不变。

这轮清理的目标不是一次性“扫干净”，而是先把确定性最高、最容易复制蔓延的冗余收掉。下一轮可以继续向 MISC 加载状态和 TCP/UDP 页面骨架推进。
