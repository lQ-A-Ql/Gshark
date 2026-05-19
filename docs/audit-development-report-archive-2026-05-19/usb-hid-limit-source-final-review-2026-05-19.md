# USB HID 事件上限与数据源切换最终复审报告

署名：Codex

时间：2026-05-19 22:29:30 +08:00（Asia/Shanghai）

## 本轮目标

- 分工修复 USB HID source 切换不生效、鼠标轨迹只还原部分样本、数据源选择器样式不统一的问题。
- 为 HID 行为事件增加可配置 limit，达到 limit 时提示，并允许用户提高上限。
- 最终由主线程复审后统一验证。

## 文档评审

- 已阅读本日 USB 鼠标 HID 轨迹优化、CTF 兼容优化、多协议数据源选择优化报告。
- 当前改动延续既有分层：后端负责 source/limit/截断元数据，前端负责选择器、limit 控件、缓存键与提示。
- 本报告和本地样本仍按用户要求不纳入 commit。

## 修改摘要

- 后端
  - `USBAnalysisOptions` 增加 `HIDEventLimit`。
  - `USBAnalysis` 增加 `hid_event_limit`、`hid_events_truncated`、`hid_mouse_events_total`、`hid_keyboard_events_total`。
  - HID keyboard/mouse 行为数组默认上限提高到 `20000`，支持 `500~100000` clamp。
  - `usbRecordLimit=2000` 继续只用于通用 USB records、Mass Storage、Other USB 等非 HID 行为列表。
  - `USBAnalysisWithOptions` 缓存键纳入 source 与 limit，manual source 不再复用 auto 缓存。
  - HTTP `/api/analysis/usb` 支持 `hid_source` 与 `hid_event_limit`。

- 前端
  - USB 分析请求、mapper、类型、缓存键接入 `hid_event_limit` 与截断元数据。
  - 鼠标面板 source selector 改为项目共享 `SelectField`。
  - 鼠标面板新增 HID 事件上限输入，支持 blur/Enter 提交、非法输入恢复、数值 clamp。
  - 截断时显示当前上限、鼠标/键盘总事件数，并在轨迹区提示“轨迹已按事件上限截断”。
  - HID 交互测试拆为独立测试文件，保持前端 size budget 通过。

## 验证记录

```powershell
cd C:\Users\QAQ\Desktop\gshark\backend
go test ./internal/tshark -run "TestUSB|TestDetectUSB|TestBuildUSBMouse" -count=1
go test ./internal/transport -run "Test.*USB" -count=1
go test ./internal/engine -run "Test.*USB" -count=1
go test ./...
$env:GSHARK_USB_MOUSE_SAMPLE='C:\Users\QAQ\Downloads\鼠标流量\鼠标流量.pcapng'; go test ./internal/tshark -run TestUSBMouseTrafficSampleRegression -count=1 -v

cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec vitest run src/app/pages/UsbAnalysis.test.tsx src/app/pages/UsbAnalysis.hidPanel.test.tsx src/app/pages/analysisCacheKeys.test.ts src/app/integrations/clients/analysisClient.test.ts src/app/integrations/mappers/usbMapper.test.ts
pnpm run ci

git diff --check
```

结果：全部通过。前端完整 CI 覆盖 222 个测试文件、684 个测试；Vite build 通过。样本回归通过，TShark 仅提示 `usbms.scsi.opcode` 可选字段缺失，不影响 HID 验证。

## 复审结论

- 样本只还原一部分轨迹的主因已由默认 HID limit 提高与可调上限修复。
- 协议切换不改变轨迹的主因已由 source+limit 缓存键修复。
- 协议选择器已使用项目共享 Select 组件。
- 截断状态已进入后端元数据和前端提示链路。

## 提交说明

- 本报告仅本地保留，不纳入 commit。
- 未提交本地鼠标样本、`frontend/dist/` 或构建产物。
