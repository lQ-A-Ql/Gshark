# 前端纯白背景设计语言收口报告

## 本轮目标

根据用户要求，将前端设计语言中的彩色渐变背景统一收口为纯白背景，保持 `meow~traffic` 作为安全流量分析工作台的密集、克制、可扫描界面。

## 实际改动

1. 全局主题层
   - 在 `frontend/src/styles/theme.css` 追加纯白背景覆盖规则。
   - 覆盖页面背景、玻璃壳层、tile、表单面板、工具条、导航栏、菜单、控制条、输入面、工作台面板等共享 surface。
   - 禁用这些 surface 的 radial / linear 渐变背景和装饰性 scan/halo 覆盖层。
   - 将纯白覆盖规则放在 `@layer utilities` 末尾，避免后续同等选择器重新覆盖回渐变背景。

2. 组件级显式渐变
   - `AnalysisHero` 顶部彩色渐变线改为中性分割线，并移除不再使用的渐变配置字段。
   - `MiscToolsHero` 顶部彩色渐变线改为中性分割线。
   - `HttpStream` / `RawStreamPage` 页面级紫色渐变背景改为纯白。
   - `RuntimeSettingsSidebar` 内容区渐变背景改为纯白。
   - `MediaPlaybackDialog` 音频播放容器渐变背景改为纯白。
   - 启动页后端连接进度条从蓝色渐变改为纯白进度。

3. 保留范围
   - 保留数据包表格的 Wireshark 风格 packet coloring，因为它是协议/状态可视编码，不属于装饰性背景。
   - 保留严重等级、状态、图表等功能性颜色，不把所有语义色降为白色。

## 验证结果

```powershell
cd frontend; pnpm run typecheck
cd frontend; pnpm run lint
cd frontend; pnpm run format:check
cd frontend; pnpm run test:run
git diff --check
```

结果：

- `pnpm run typecheck`：通过。
- `pnpm run lint`：通过。
- `pnpm run format:check`：通过。
- `pnpm run test:run`：通过，225 个测试文件 / 700 个测试。
- `git diff --check`：通过。

## 结论

本轮将彩色渐变背景从产品设计语言中移除，统一为纯白 surface；功能性颜色仍保留在状态、风险等级、协议着色和图表语义中。

署名：Codex
时间：2026-05-24 20:44:56 +08:00
