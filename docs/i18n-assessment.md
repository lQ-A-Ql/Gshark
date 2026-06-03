# meow~traffic 前端国际化（i18n）评估报告

> 生成日期：2026-06-02
> 范围：`frontend/src/**/*.{ts,tsx}`

---

## 1. 现状分析

### 1.1 规模概览

| 指标 | 数值 |
|------|------|
| 含中文字符串的文件数 | **397** |
| 中文字符串出现总次数 | **~2,768** |
| 技术栈 | React 18.3.1 / TypeScript 5.9.2 / Vite 6.3 / pnpm |
| 现有 i18n 库 | **无** |

### 1.2 中文字符串分布（Top 20 文件）

| 文件 | 出现次数 | 类型 |
|------|---------|------|
| `features/apt/actorRegistry.ts` | 52 | APT 组织名称与描述 |
| `features/update/UpdateCenterPanels.tsx` | 43 | 更新中心 UI |
| `features/vehicle/VehicleUdsTransactionsPanel.tsx` | 41 | 车机 UDS 事务面板 |
| `layouts/MainHeader.tsx` | 40 | 全局顶栏 |
| `features/industrial/IndustrialAuxiliaryPanels.tsx` | 35 | 工控辅助面板 |
| `pages/C2Analysis.tsx` | 35 | C2 分析页面 |
| `features/c2/c2EvidenceModel.ts` | 32 | C2 证据模型 |
| `features/usb/UsbMousePanel.tsx` | 32 | USB 鼠标面板 |
| `pages/AptAnalysis.tsx` | 30 | APT 分析页面 |
| `App.tsx` | 30 | 根组件/路由 |
| `features/c2/C2DecryptFormControls.tsx` | 18 | C2 解密表单 |
| `components/CaptureWelcomePanel.tsx` | 19 | 抓包欢迎面板 |
| `features/usb/UsbTables.tsx` | 19 | USB 表格组件 |

### 1.3 字符串类别

按用途可将中文字符串分为以下几类：

| 类别 | 示例 | 估算占比 |
|------|------|---------|
| **页面/面板标题** | `"APT 组织画像"`、`"流量图"`、`"MISC 工具箱"` | ~15% |
| **按钮/操作标签** | `"开始检测"`、`"重试"`、`"复制输出"` | ~10% |
| **表格列头** | `"源→目标"`、`"端口数"`、`"置信度"` | ~10% |
| **错误/状态消息** | `"请先导入抓包文件"`、`"后端未连接"`、`"加载失败"` | ~25% |
| **描述/说明文本** | `"独立承载组织/活动簇画像..."` | ~10% |
| **占位符/提示** | `"在此输入待计算哈希的文本..."` | ~5% |
| **导航/菜单项** | `"主工作区"`、`"C2 样本分析"`、`"证据链总览"` | ~10% |
| **领域术语/数据** | APT 组织名、协议名等（部分不宜翻译） | ~15% |

---

## 2. 方案对比

### 2.1 候选方案

| 维度 | `react-i18next` | `react-intl` (FormatJS) | `@lingui/core` |
|------|-----------------|--------------------------|----------------|
| **npm 周下载量** | ~3M | ~5M | ~200K |
| **包体积 (min+gz)** | ~15KB | ~22KB | ~8KB |
| **React 18 支持** | 完善 | 完善 | 完善 |
| **TypeScript 支持** | 良好（类型推断需插件） | 优秀（内置类型） | 优秀（CLI 生成类型） |
| **复数/性别** | i18next 内置 | ICU MessageFormat | ICU MessageFormat |
| **懒加载** | 原生支持 namespaces | 需手动实现 | 原生支持 |
| **ICU 标准** | 否（自有语法） | 是 | 是 |
| **CLI 提取工具** | i18next-parser | formatjs extract | lingui extract |
| **学习曲线** | 低 | 中 | 中 |
| **生态成熟度** | 高 | 高 | 中 |

### 2.2 推荐方案：`react-i18next`

**推荐理由：**

1. **生态最成熟**：React 生态中使用最广泛的 i18n 方案，文档完善，社区活跃，遇到问题容易找到解决方案。
2. **与 React 18 完全兼容**：支持 Suspense、并发模式，不影响项目已有的 React 18 特性。
3. **懒加载原生支持**：通过 `namespaces` 可按功能模块懒加载语言文件，与项目的 feature-based 架构天然契合。
4. **体积可控**：核心 ~15KB (min+gz)，对桌面应用影响可忽略。
5. **渐进式迁移友好**：可以逐文件迁移，不需要一次性改动全部代码，支持混合使用硬编码和 i18n 调用。
6. **i18next 生态完整**：后端日志、日期格式化、语言检测等都有对应插件。

**不选 `react-intl` 的原因**：包体积较大，API 风格偏声明式（`<FormattedMessage>`），在大量内联字符串场景下代码侵入性较高。

**不选 `@lingui/core` 的原因**：社区规模较小，CLI 工具链配置复杂度较高，对项目当前的 pnpm + Vite 工具链适配需要额外验证。

---

## 3. 关键设计决策

### 3.1 Key 命名规范

采用 **分层点分命名**，格式为 `{feature}.{component}.{purpose}`：

```
navigation.workspace        // 导航 → 主工作区
c2.decrypt.form.placeholder // C2 解密 → 表单 → 占位符
common.button.retry          // 通用 → 按钮 → 重试
error.backend.disconnected   // 错误 → 后端 → 未连接
```

**规则：**

- 第一层：功能域（`navigation`、`c2`、`apt`、`traffic`、`common`、`error`）
- 第二层：组件或上下文（`decrypt`、`panel`、`form`）
- 第三层：用途（`label`、`placeholder`、`title`、`message`、`tooltip`）
- 通用/跨功能字符串统一放 `common.*`
- 错误消息统一放 `error.*`

### 3.2 文件结构

采用 **按语言分文件 + 按功能拆子文件** 的混合方案：

```
frontend/src/i18n/
├── index.ts                  # i18next 初始化配置
├── zh-CN/
│   ├── index.ts              # 合并导出
│   ├── common.json           # 通用字符串
│   ├── navigation.json       # 导航/菜单
│   ├── error.json            # 通用错误消息
│   ├── c2.json               # C2 分析模块
│   ├── apt.json              # APT 画像模块
│   ├── traffic.json          # 流量图模块
│   ├── industrial.json       # 工控分析模块
│   ├── vehicle.json          # 车机分析模块
│   ├── media.json            # 媒体流还原模块
│   ├── usb.json              # USB 分析模块
│   ├── hunting.json          # 威胁狩猎模块
│   ├── object.json           # 附件提取模块
│   ├── misc.json             # MISC 工具箱模块
│   └── update.json           # 更新中心模块
└── en-US/
    ├── index.ts
    ├── common.json
    └── ... (同 zh-CN 结构)
```

**理由：**
- 与项目的 feature-based 目录结构对齐
- 按功能拆文件便于并行开发和 code review
- 每个 namespace 对应一个 JSON 文件，支持 i18next 的懒加载

### 3.3 语言设置

| 配置项 | 值 | 说明 |
|--------|-----|------|
| 默认语言 | `zh-CN` | 当前项目语言，迁移期保持不变 |
| 回退语言 | `zh-CN` | 缺少翻译时回退到中文 |
| 目标语言（Phase 3） | `en-US` | 英文为首要扩展语言 |
| 语言检测顺序 | `localStorage` → `navigator` → 默认 | 桌面应用场景下无需 URL 检测 |
| 存储 key | `meow-traffic-locale` | localStorage 中的键名 |

### 3.4 不翻译的内容

以下内容 **不纳入 i18n**：

- APT 组织名称（如 `Silver Fox`、`APT28`）—— 国际通用名称
- 协议名称（如 `HTTP`、`DNS`、`SMB`）—— 技术术语
- 后端返回的动态错误消息（后端 API 层独立处理）
- 日志/调试信息（面向开发者，非用户）
- 测试文件中的断言字符串（可保持中文或使用 mock）

---

## 4. 迁移策略

### Phase 1：基础设施 + 试点（1-2 周）

**目标：** 搭建 i18n 基础设施，完成 1-2 个组件的完整迁移作为范例。

**步骤：**

1. 安装依赖：
   ```bash
   pnpm add i18next react-i18next i18next-browser-languagedetector
   ```

2. 创建 `frontend/src/i18n/` 目录结构和初始化配置

3. 提取 `MainHeader.tsx`（40 处）和 `CaptureWelcomePanel.tsx`（19 处）的中文字符串
   - 这两个组件覆盖面广（导航、状态、按钮），可作为迁移模板

4. 创建 ESLint 自定义规则或 `no-restricted-syntax` 规则，标记新增硬编码中文为 warning

5. 更新 CI pipeline，确保 i18n 相关的类型检查通过

**交付物：**
- i18n 基础设施代码
- 2 个完整迁移的组件作为参考
- 迁移指南文档（供后续开发者参考）

### Phase 2：全量提取（3-4 周）

**目标：** 将所有组件中的中文字符串提取到语言文件。

**按模块分批执行：**

| 批次 | 模块 | 文件数（估） | 优先级 |
|------|------|-------------|--------|
| 2a | 通用组件 + 布局 | ~30 | 高 |
| 2b | 流量图 + C2 分析 | ~50 | 高 |
| 2c | APT + 威胁狩猎 + 证据链 | ~40 | 高 |
| 2d | 工控 + 车机 + USB | ~60 | 中 |
| 2e | 媒体流 + MISC 工具箱 + 更新中心 | ~50 | 中 |
| 2f | 状态管理 + 集成层 + 测试文件 | ~170 | 低 |

**每个批次的工作流：**
1. `i18next-parser` 扫描目标文件，生成初始 key 列表
2. 人工审查 key 命名，调整为规范格式
3. 替换硬编码字符串为 `t('key')` 调用
4. 运行测试确保无回归
5. 提交 PR review

### Phase 3：添加英文支持（1-2 周）

**目标：** 完成 `en-US` 语言文件，实现语言切换。

**步骤：**

1. 从 `zh-CN/*.json` 复制结构到 `en-US/*.json`
2. 翻译 `common.json` 和 `navigation.json`（优先级最高）
3. 逐模块翻译其余文件，可使用 AI 辅助初译 + 人工校对
4. 在 Runtime Settings 中添加语言切换 UI
5. 验证语言切换功能和布局适应性（中文 vs 英文的文本长度差异）

---

## 5. 工作量估算

| 阶段 | 工作内容 | 估算工时 | 时间跨度 |
|------|---------|---------|---------|
| Phase 1 | 基础设施 + 试点迁移 | **3-5 人天** | 1-2 周 |
| Phase 2 | 全量字符串提取 | **10-15 人天** | 3-4 周 |
| Phase 3 | 英文翻译 + 语言切换 | **5-8 人天** | 1-2 周 |
| **合计** | | **18-28 人天** | **5-8 周** |

**说明：**
- Phase 2 占总工作量最大，可安排多人并行（每人负责不同模块）
- 测试文件（~170 个含中文的 `.test.ts(x)` 文件）优先级最低，可在后续迭代中逐步处理
- 如使用 AI 辅助翻译，Phase 3 可压缩至 1 周

### 5.1 风险与注意事项

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| 动态拼接的字符串难以提取 | 中 | 重构为带插值的模板 key：`t('error.timeout', { endpoint, ms })` |
| CSS 布局对英文文本长度不适应 | 低 | 使用 `min-width` / `truncate` / `whitespace-nowrap` |
| 后端 API 返回的中文错误消息 | 低 | 后端独立处理，前端仅做展示层 i18n |
| 新增代码仍写硬编码中文 | 中 | ESLint 规则 + CI 卡点 |
| i18n JSON 文件体积增长 | 低 | 桌面应用无网络传输瓶颈，按 namespace 懒加载即可 |

---

## 6. 附录：快速验证命令

```bash
# 统计当前中文字符串数量
cd frontend/src && rg -c "[\u4e00-\u9fff]" -g "*.tsx" -g "*.ts" | wc -l

# 安装 i18n 依赖
cd frontend && pnpm add i18next react-i18next i18next-browser-languagedetector

# 提取中文字符串（Phase 2 中使用）
npx i18next-parser 'src/**/*.{tsx,ts}' --config i18next-parser.config.js
```
