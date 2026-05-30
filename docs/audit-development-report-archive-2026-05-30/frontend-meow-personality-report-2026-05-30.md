# 前端 UI meow 人格化改造报告 2026-05-30

## 概述

为 meow~traffic 前端注入"猫咪人格"，在保持专业取证工具定位的前提下，通过色温调暖、字体圆润化、像素猫咪状态精灵和空状态插画，提升品牌辨识度和长时间使用的视觉舒适度。

## P0 — 视觉舒适度

### 色温调暖

- 新增 `cream` 页面主题：暖白底 `252 251 248` + 紫罗兰强调色 `139 92 246`
- 设为主工作区（`/`）和更新页（`/updates`）的默认主题
- fallback 主题从 `blue` 改为 `cream`
- 玻璃壳背景色从纯白微调为暖奶白（`rgba(255,255,252,0.74)`）

### 圆角柔化

- 所有 `meow-` 表面类的 `border-radius` 从 `0.125rem`（2px）统一提升到 `0.25rem`（4px）
- 保持建筑感但更贴合"猫咪"的柔软气质

## P1 — 品牌字体 + 猫咪状态精灵

### 字体替换

- 引入 `@fontsource-variable/nunito` 作为 UI 字体
- 圆润字形天然贴合 "meow~" 品牌气质
- 高 x-height，11-12px 信息密集场景下可读性优于系统字体
- 通过 `@theme inline` 的 `--font-sans` 覆盖全局生效

### Footer 猫咪状态精灵

纯 CSS `clip-path` 实现的像素猫咪，4 种状态自动切换：

| 状态 | 猫咪姿态 | 触发条件 |
|------|----------|----------|
| idle | 趴着打盹（呼吸动画 3s 循环） | 后端已连接，无 capture |
| active | 竖耳左右看（2s 循环） | 后端已连接，有 capture |
| alert | 弓背炸毛（0.6s 抖动） | 预留：发现威胁时 |
| confused | 歪头（2.4s 摇摆） | 后端断连 |

## P2 — 猫咪细节元素

### 侧边栏猫爪 Active 指示器

- 激活的导航项底部显示猫爪印
- 纯 CSS `radial-gradient` 实现（主垫 + 4 个趾垫）
- 半透明（`opacity: 0.48`），不抢夺注意力

### 空状态像素猫咪插画

创建 `MeowEmptyState` 可复用组件，4 种场景变体：

| 变体 | 视觉 | 适用场景 |
|------|------|----------|
| `box` | 猫咪蜷在纸箱里 | 无数据通用 / 欢迎面板 |
| `window` | 猫咪看窗外 | 一切平静 / 无威胁 |
| `keyboard` | 猫咪趴键盘 | 无 C2 / 分析数据 |
| `headphones` | 猫咪戴耳机 | 无媒体会话 |

### 已接入的页面

| 页面 | 触发条件 | 猫咪变体 |
|------|----------|----------|
| 欢迎面板 | 最近文件列表为空 | box |
| 威胁狩猎 | 无命中结果 | window |
| 媒体分析 | 无媒体会话 | headphones |
| C2 分析 | 无家族命中 | keyboard |
| APT 分析 | 无样本家族 | window |
| USB HID | 无键盘事件 | box |
| 流量图 | 无数据 | window |

## 修改文件

| 文件 | 变更 |
|------|------|
| `frontend/src/styles/theme.css` | 色温调暖、圆角 2px→4px |
| `frontend/src/styles/fonts.css` | 引入 Nunito Variable |
| `frontend/src/styles/meow-sprites.css` | 新增：猫咪精灵 + 猫爪 + 空状态 CSS |
| `frontend/src/styles/index.css` | 引入 meow-sprites.css |
| `frontend/src/app/layouts/mainLayoutConfig.ts` | 新增 cream 主题、更新默认 |
| `frontend/src/app/layouts/MainFooter.tsx` | 替换 Box 图标为猫咪精灵 |
| `frontend/src/app/layouts/MainSidebarNav.tsx` | 添加猫爪 active 指示器 |
| `frontend/src/app/components/MeowEmptyState.tsx` | 新增：可复用空状态组件 |
| `frontend/src/app/components/CaptureWelcomePanel.tsx` | 接入 box 猫咪 |
| `frontend/src/app/components/analysis/AnalysisCards.tsx` | AnalysisEmptyState 新增 cat prop |
| `frontend/src/app/features/hunting/ThreatHuntingResultPanels.tsx` | 接入 window 猫咪 |
| `frontend/src/app/features/media/MediaSessionTable.tsx` | 接入 headphones 猫咪 |
| `frontend/src/app/features/traffic/TrafficSimpleBarChart.tsx` | 接入 window 猫咪 |
| `frontend/src/app/features/usb/UsbHidTables.tsx` | 接入 box 猫咪 |
| `frontend/src/app/pages/C2Analysis.tsx` | 接入 keyboard 猫咪 |
| `frontend/src/app/pages/AptAnalysis.tsx` | 接入 window 猫咪 |
| `frontend/package.json` | 新增 @fontsource-variable/nunito 依赖 |

## 测试验证

- 757 测试全部通过
- TypeScript 类型检查通过
- ESLint 零警告
- 前端架构边界检查通过
- 构建成功

## 设计原则

- **猫咪是人格，不是主题** — 出现在边缘、空隙、等待的时刻，不抢占数据展示
- **不替代专业指示器** — 威胁等级、连接状态等仍用标准图标和颜色
- **纯 CSS 实现** — 无外部图片依赖，零运行时开销
- **渐进增强** — `prefers-reduced-motion` 下动画自动禁用
