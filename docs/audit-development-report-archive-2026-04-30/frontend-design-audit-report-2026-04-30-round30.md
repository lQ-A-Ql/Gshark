# 日期: 2026-04-30
# 署名: Codex

# 前端全站设计缺陷复核与优化报告（round30）

## 一、本轮目标

本轮继续执行“前端复核、低风险优化、验证、报告”的迭代节奏，重点放在上一轮遗留的共享组件收敛：

- 继续删除可证明等价的前端冗余 UI helper。
- 以 MISC 页面为浅色单主题准线，收敛任务控制台与威胁狩猎页的指标卡风格。
- 复查深色模式残留，确认不引入 `dark` / `dark:` 分支。
- 续写 docs 下的前端开发报告，并更新当天归档索引和分类摘要。

本轮不改动后端协议逻辑，不调整 MISC 模块算法，不引入深色模式。

## 二、本轮复核评论

复查 round29 后的前端代码，重复 helper 已明显减少，但仍有两个低风险收敛点：

1. `CaptureMissionControl.tsx` 仍保留局部 `StatCard`，职责与共享 `MetricCard` 重叠。
2. `ThreatHunting.tsx` 仍保留局部 `GlassStatCard`，同样是三段指标概览卡片，且渐变玻璃感与 MISC 准线略有偏离。
3. `dark` / `dark:` 分支扫描无命中，当前未发现显式深色模式代码残留。
4. `bg-black`、`bg-slate-950`、`text-white` 等暗色类名仍存在于代码/Hex/JSON 预览或局部高对比按钮中，不能直接等同于深色模式，需要后续继续人工分类。

因此本轮选择迁移两处指标卡，不触碰复杂表格、路由、协议功能和代码预览块。

## 三、本轮开发内容

### 1. 任务控制台指标卡迁移到共享组件

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\CaptureMissionControl.tsx
```

完成：

- 引入共享 `MetricCard`。
- 将“总包数 / 可疑命中 / 流数量 / 提取对象”四个任务控制台指标卡改为 `MetricCard`。
- 为四个指标补充对应 tone：`emerald`、`rose`、`blue`、`amber`。
- 删除局部 `StatCard` helper。

当前收益：

- 首页任务控制台的指标卡与 C2、APT、MISC 等页面的共享卡片体系一致。
- 删除最后一个通用 `StatCard` 重复实现。
- 保留原有统计值、说明文案、图标和布局网格，不改变业务行为。

### 2. 威胁狩猎指标卡迁移到共享组件

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\ThreatHunting.tsx
```

完成：

- 引入共享 `MetricCard`。
- 将“总命中 / 高风险 / CTF / 异常”三张顶部指标卡改为 `MetricCard`。
- 删除局部 `GlassStatCard` helper。
- 指标值统一使用 `toLocaleString()`。
- 为指标补充简短 hint，说明各指标口径。

当前收益：

- 威胁狩猎页的顶部数据区从自定义玻璃渐变卡片收敛到 MISC 准线下的浅色指标卡。
- 减少页面级视觉孤岛，页面之间的信息层级更一致。
- 保留原有狩猎执行、规则参数、命中列表、详情定位和关联流跳转逻辑。

### 3. 冗余与深色分支复查

已复查：

```powershell
Get-ChildItem -Path frontend/src/app -Recurse -Include *.tsx,*.ts |
  Select-String -Pattern '^function StatCard|^function GlassStatCard|^function BucketList|^function ConversationList|^function MiniMetric'
```

结果：

- 未发现残留命中。

已复查：

```powershell
Get-ChildItem -Path frontend/src -Recurse -Include *.tsx,*.ts,*.css |
  Select-String -Pattern '\bdark\b|dark:'
```

结果：

- 未发现 `dark` / `dark:` 显式深色模式分支。

## 四、验证结果

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npx tsc --noEmit --noUnusedLocals --noUnusedParameters
```

结果：

- 通过。

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npm test
```

结果：

- 通过，12 个测试文件、47 个测试全部通过。

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npm run build
```

结果：

- 通过，Vite production build 成功。

已执行：

```powershell
git diff --check -- frontend/src/app/components/CaptureMissionControl.tsx frontend/src/app/pages/ThreatHunting.tsx
```

结果：

- 通过。

说明：

- 本轮未修改后端协议逻辑，因此未额外运行后端 `go test`。
- `npm run build` 输出显示 `MiscTools`、`UpdateCenter` 等 chunk 仍偏大，但本轮范围是共享组件收敛，暂不做拆包调整。

## 五、当前收益

- `StatCard` / `GlassStatCard` 这类通用指标卡重复实现已清零。
- 任务控制台、威胁狩猎、C2、APT 等页面的指标卡继续统一到 `MetricCard`。
- 页面风格进一步贴近 MISC 的浅色单主题准线。
- 本轮没有引入深色模式分支。
- 前端验证链路保持通过，改动集中且低风险。

## 六、遗留与下一轮建议

### 遗留问题

1. 复杂表格仍是主要冗余来源，例如 C2 聚合详情、APT 证据表、工控事务表和威胁狩猎命中表。
2. `AnalysisDataTable` 仍缺少列宽、cell class、展开行、actions slot 等能力，暂不适合承接所有复杂表格。
3. `RecommendationCard`、`CategoryCard`、`GuideCard` 等仍是页面级业务卡片，需要继续区分“业务语义封装”和“通用 UI 重复”。
4. 暗色类名仍需要人工分类，尤其是代码/Hex/JSON 预览块，不能为了单主题目标牺牲可读性。
5. `MiscTools` 和 `UpdateCenter` 构建 chunk 偏大，后续可考虑模块级懒加载或工具面板拆分。

### 下一轮建议

1. 增强 `AnalysisDataTable`，先支持列宽、单元格 className、空状态和行级 actions。
2. 选择一个复杂但低耦合的表格作为试点，例如威胁狩猎命中表或工控事务表。
3. 继续按“共享组件能力先补齐，再迁移页面”的顺序推进，避免大面积重写。
4. 对暗色类名做白名单化记录，把代码预览高对比块与主题残留明确分开。
5. 若继续优化构建体积，优先检查 `MiscTools` 内建模块是否可以进一步延迟加载。
