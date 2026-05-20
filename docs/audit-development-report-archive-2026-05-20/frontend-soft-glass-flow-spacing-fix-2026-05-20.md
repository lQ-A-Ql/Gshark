# 前端柔和玻璃填充、全页无缝分区与纵向比例修正报告

署名：Codex

时间：2026-05-20 20:55:34 +08:00（Asia/Shanghai）

## 目标

- 删除主体分析页内部残留的硬白填充，改为柔和半透明毛玻璃填充。
- 将非 USB 页面仍存在的分区 gutter 收敛为连续矩形分区。
- 修正 APT 等长页面在 tiled 布局下的纵向压缩风险。
- 继续保持 HTTP/TCP/UDP 流追踪页面不做结构迁移。

## 文档评审

- 已阅读 rontend-usb-glass-spacing-refinement-2026-05-20.md。
- 本轮在上一轮 USB 去间距、去内框、毛玻璃深化基础上，将规则提升到公共 tiled 页面流与跨页面残留清理。

## 修改摘要

- 公共布局
  - PageShell tiled inner 改为自然 block 文档流，保留 gshark-tile-page min-h-full w-full p-0，避免长页面 flex 子项被压缩。
  - 	heme.css 增加 .gshark-tile-page 顶层分区 margin reset。
  - 新增 .gshark-soft-fill，统一低透明度白青/白蓝渐变、弱边框、轻模糊填充。

- 跨页面分区收敛
  - TrafficGraph 概览和图表区域改为无 gutter tiled 分区。
  - Media 批量转写、分析进度、转写汇总、转写单元格和导出动作块改为 gshark-soft-fill 或无边框空态。
  - 结合既有改动，APT、C2、Vehicle、Industrial、Media、Object、Evidence、ThreatHunting、Update 等页面主体分区不再保留明显 gap-4/mt-4 外部缝隙。

- 白色填充处理
  - 主体分析内容中的 g-background/bg-card/bg-white 残留继续替换为 gshark-soft-fill 或透明分隔。
  - 代码块、终端块、媒体播放 dialog 与流追踪页面保留其语义面板，不纳入主体去卡片化范围。

## 流追踪排除确认

本轮未对以下结构做迁移：

- /http-stream
- /tcp-stream
- /udp-stream
- RawStream*
- rontend/src/app/components/stream/**
- rontend/src/app/features/raw-stream/**

## 验证记录

`powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec vitest run src/app/pages/UsbAnalysis.test.tsx src/app/pages/UsbAnalysis.hidPanel.test.tsx src/app/pages/AptAnalysis.test.tsx src/app/pages/VehicleAnalysis.test.tsx src/app/pages/IndustrialAnalysis.test.tsx src/app/pages/MediaAnalysis.test.tsx src/app/pages/C2Analysis.test.tsx src/app/pages/C2Analysis.vshell.test.tsx src/app/pages/C2Analysis.candidates.test.tsx src/app/pages/C2Analysis.decrypt.test.tsx src/app/pages/EvidencePanel.test.tsx src/app/pages/MiscTools.test.tsx src/app/pages/MiscTools.customModules.test.tsx src/app/pages/MiscTools.sessions.test.tsx src/app/pages/MiscTools.smb3.test.tsx src/app/pages/MiscTools.payloadHints.test.tsx
pnpm run typecheck
pnpm run lint
pnpm run format:check
pnpm run size:check
pnpm run boundary:check
pnpm run ci

cd C:\Users\QAQ\Desktop\gshark
git diff --check
`

结果：

- 目标页面回归测试通过：14 个测试文件、44 个测试。
- 	ypecheck 通过。
- lint 通过。
- ormat:check 通过。
- size:check 通过。
- oundary:check 通过。
- 完整前端 pnpm run ci 通过：225 个测试文件、692 个测试，Vite build 通过。
- git diff --check 通过。

## Playwright / Chrome 验收

- 临时启动本地 backend 与 Vite 后，使用 Playwright CLI + Chrome 截图抽查：
  - /usb-analysis
  - /vehicle-analysis
  - /industrial-analysis
  - /media-analysis
  - /c2-analysis
  - /evidence
  - /misc
  - /apt-analysis
  - /http-stream

验收结果：

- /usb-analysis 主体为连续分区，空态不再出现内部硬白框中框。
- /media-analysis、/vehicle-analysis、/industrial-analysis、/c2-analysis、/evidence、/misc 已呈现贴合分区与柔和玻璃填充。
- /apt-analysis 在未加载抓包时仍显示欢迎面板；长页压缩风险已通过 PageShell tiled 自然文档流修正。
- /http-stream 保持流追踪工作台结构。
- Playwright 临时截图产物已清理。

## 注意事项

- 本报告为本地开发报告，不纳入 commit。
- 未提交 rontend/dist/、uild/、样本或 Playwright 产物。
