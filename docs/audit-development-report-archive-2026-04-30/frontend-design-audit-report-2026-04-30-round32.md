# 日期: 2026-04-30
# 署名: Codex

# 前端显示缺陷审计与修复报告（round32）

## 一、本轮目标

本轮继续执行“审计、修复、报告”的前端收口迭代，重点从页面风格统一转向真实显示缺陷修复：

- 以数据包表格右键菜单位置异常为切入点，审计同类浮层、菜单和下拉面板的越界风险。
- 修复数据包表格右键菜单在视口底部或右侧出现位置异常、溢出或触发原生菜单的问题。
- 优化工作区十六进制 / ASCII 区域显示，解决字号偏小、列距过窄、字节按钮过于紧凑的问题。
- 对顶部导航菜单、侧栏 tooltip 和 MISC 通用 select 下拉做低风险显示保护。
- 不引入深色模式，不改变协议分析能力，不修改后端逻辑。

## 二、本轮复核评论

复查前端浮层实现后，本轮发现的高置信显示问题如下：

1. `PacketVirtualTable` 的右键菜单直接使用 `event.clientX` / `event.clientY` 作为 fixed 坐标，没有菜单尺寸估算和视口边界夹取。用户在表格底部或右侧右键时，菜单会贴底、溢出或显示在异常区域。
2. 数据包表格根节点只在部分状态下阻止原生右键菜单，菜单已存在时再次右键可能出现浏览器默认上下文菜单，与自定义菜单状态冲突。
3. 工作区 HEX 区域使用 `text-xs`、`text-[11px]`、`px-[1px]` 和窄列布局，长时间阅读流量字节时过于紧凑，选中字节与范围高亮的可视面积也偏小。
4. 顶部菜单和 MISC 通用 select 均为 `top-full` 浮层，原实现缺少明确的视口高度约束，虽然不是截图中的主问题，但属于同一类“浮层相信自己一定有空间”的显示风险。
5. 侧栏 tooltip 使用深色气泡且没有垂直居中，和 MISC 浅色准线不一致，也容易在窄区域中显得突兀。

本轮优先修复可直接定位且低风险的问题；复杂的第三方 Radix tooltip / sheet / dialog 结构保持不动，避免为了统一而引入交互回归。

## 三、本轮开发内容

### 1. 数据包表格右键菜单视口安全定位

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\PacketVirtualTable.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\PacketVirtualTable.test.tsx
```

完成：

- 新增 `getContextMenuPosition()`，按菜单估算宽高、视口宽高和安全边距计算最终位置。
- 在右侧或底部空间不足时，自动将菜单坐标夹取到视口内，避免菜单被窗口裁掉。
- 行级 `onContextMenu` 增加 `stopPropagation()`，避免右键事件继续冒泡到外层容器。
- 表格根节点统一阻止原生右键菜单，并在空白处右键时关闭已有菜单。
- 菜单自身拦截右键与点击冒泡，防止点击菜单项前被外层 `onClick` 提前关闭。
- 菜单视觉从旧的普通 `rounded-md bg-card shadow-lg` 升级为浅色半透明卡片、柔和阴影和 cyan hover，贴近 MISC 页面准线。
- 增加 helper 单测，覆盖正常坐标、右下角夹取、负坐标和极小视口。

当前收益：

- 截图所示“右键菜单跑到异常位置”的根因已经收敛。
- 同一个定位 helper 后续可复用到其他自定义上下文菜单。
- 右键菜单行为不再依赖浏览器原生菜单状态，交互更稳定。

### 2. 工作区 HEX / ASCII 区域可读性优化

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\workspace\HexAsciiPanel.tsx
```

完成：

- HEX 面板标题栏改为浅色渐变、稍大字号和更明确的 Packet 标签。
- 主内容从 `text-xs` 提升到 `text-[13px]`，行高从紧凑模式提升到 `leading-6`。
- HEX 行布局从 `44px_1fr_136px` 调整为 `64px_minmax(34rem,1fr)_12rem`，offset、hex 和 ASCII 三块间距更清晰。
- 内容容器增加 `min-w-[760px]`，避免面板过窄时强行压缩字节列；必要时使用横向滚动，保持 hex 阅读结构稳定。
- HEX 字节按钮改为 `inline-flex`，增加最小宽度、横向间距、字距和 hover 状态。
- ASCII 区域增加左侧分割线和独立间距，减少 hex 与 ASCII 粘连感。
- 当前字节和选中范围的高亮面积扩大，范围选择增加 ring，定位更容易。
- 空状态从普通文本升级为浅色虚线卡片，保持面板结构完整。

当前收益：

- HEX 区域不再像压缩日志，而更接近可读的流量取证工作区。
- 字节点击目标更大，减少误点。
- ASCII 列与 hex 列分隔更明确，适合长时间分析 payload。

### 3. 同类浮层显示保护

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\layouts\MainLayout.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\modules\GenericMiscModule.tsx
```

完成：

- 顶部导航菜单增加 `max-h-[calc(100vh-5rem)]` 与 `overflow-auto`，避免菜单内容过长时溢出视口。
- 顶部菜单视觉调整为浅色圆角浮层、柔和阴影、cyan hover，减少与 MISC 风格割裂。
- 顶部菜单项增加更稳定的点击高度和字体权重。
- 侧栏 tooltip 改为浅色浮层、垂直居中和 `pointer-events-none`，避免 hover 过程中 tooltip 自身影响鼠标命中。
- MISC 通用 select 的选项列表从固定 `max-h-64` 改为 `max-h-[min(16rem,calc(100vh-12rem))]`，在低高度窗口中不再盲目向下撑开。

当前收益：

- 自定义菜单、tooltip、select 下拉这三类高频浮层都获得基础边界保护。
- 浮层风格继续向 MISC 的浅色安全工具箱准线靠拢。
- 未改动复杂路由、数据加载和业务状态，回归风险较低。

## 四、验证结果

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npm test -- PacketVirtualTable
```

结果：

- 通过，`PacketVirtualTable` 3 个测试全部通过。

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npx tsc --noEmit --noUnusedLocals --noUnusedParameters
```

结果：

- 通过。

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark
git diff --check -- frontend/src/app/components/PacketVirtualTable.tsx frontend/src/app/components/PacketVirtualTable.test.tsx frontend/src/app/components/workspace/HexAsciiPanel.tsx frontend/src/app/layouts/MainLayout.tsx frontend/src/app/misc/modules/GenericMiscModule.tsx
```

结果：

- 通过。

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npm test
```

结果：

- 通过，12 个测试文件、49 个测试全部通过。

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npm run build
```

结果：

- 通过，Vite production build 成功。

已执行：

```powershell
Get-ChildItem -Path frontend/src -Recurse -Include *.tsx,*.ts,*.css |
  Select-String -Pattern '\bdark\b|dark:'
```

结果：

- 无命中。

说明：

- 本轮未修改后端协议逻辑，因此未运行后端 `go test`。
- 本地 `rg.exe` 在当前 Codex Desktop 环境中被系统拒绝启动，本轮使用 PowerShell `Select-String` 完成浮层和深色模式扫描。
- `npm run build` 仍显示 `MiscTools`、`UpdateCenter`、`index` 等 chunk 较大，这是既有构建体积治理事项，不影响本轮显示缺陷修复结论。

## 五、当前收益

- 数据包表格右键菜单已经具备视口安全定位，不再直接裸用鼠标坐标。
- 表格右键事件链更稳定，自定义菜单与浏览器原生菜单不再互相打架。
- 工作区 HEX / ASCII 面板可读性显著提升，字号、列距、字节间距和选择态更适合流量分析。
- 顶部菜单、侧栏 tooltip、MISC select 下拉完成一轮低风险浮层显示保护。
- 本轮继续保持浅色单主题，没有新增 `dark` / `dark:` 深色模式残留。
- 前端类型检查、全量单测和生产构建均通过。

## 六、遗留与下一轮建议

### 遗留问题

1. 本轮未做浏览器真实视觉截图回归，建议下一轮启动页面后针对右键菜单、低高度窗口 select、顶部菜单和 HEX 区域做一次人工视觉走查。
2. Radix Tooltip / Dialog / Sheet 等第三方封装浮层目前未发现高置信越界问题，本轮未改动；后续如果出现截图证据，再单独治理。
3. 顶部菜单仍是 CSS hover 菜单，不具备完整键盘导航与焦点管理；如果要继续打磨桌面端体验，建议后续迁移到可控状态或 Radix Menu。
4. HEX 面板为了保证 16 字节结构稳定，在窄面板下会出现横向滚动；这是当前更偏取证阅读的选择，后续可考虑增加“紧凑 / 舒适”密度切换。
5. 构建体积偏大的遗留仍存在，尤其是 `MiscTools`、`UpdateCenter` 和主入口 chunk。

### 下一轮建议

1. 启动前端页面做一次浏览器视觉巡检，优先覆盖主工作区右键菜单、HEX 面板、MISC select 和顶部菜单。
2. 若继续修显示 bug，下一轮重点关注表格列设置面板、长文本弹窗、协议详情预览和低分辨率窗口布局。
3. 若继续做架构收口，优先抽出可复用的 `viewportSafePosition` / `FloatingSurface`，避免后续每个页面各写一套浮层边界逻辑。
4. 构建体积治理可以单开一轮，避免和显示缺陷修复混在一起增加回归面。
