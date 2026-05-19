# USB 鼠标 HID 提取与轨迹图优化报告

署名：Codex

时间：2026-05-19 20:12:00 +08:00（Asia/Shanghai）

## 本轮目标

- 减少鼠标 HID 完成帧被归入其他 USB 流量。
- 保留鼠标混合轨迹图，并新增左键、右键、无按键三类独立轨迹图。
- 使用本地样本 `C:\Users\QAQ\Downloads\鼠标流量\鼠标流量.pcapng` 做回归验证。

## 文档评审

- `docs/audit-development-report-archive-2026-05-10/frontend-engineering-report-2026-05-10.md` 已记录 USB HID 前端拆分边界，本轮继续沿用 `UsbMouseTrajectory`、`UsbHidPanel`、`usbHidRules` 的职责划分。
- `docs/audit-development-report-archive-2026-05-11/frontend-engineering-report-2026-05-11.md` 已记录 USB mapper 与分析链路拆分，本轮不改变 API/mapper/wire DTO。
- `docs/public-sample-corpus-2026-05-06.md` 当前 USB 公共样本侧重 Mass Storage，本轮额外使用本地鼠标 HID 样本验证，不把样本提交入库。

## 修改摘要

- `backend/internal/tshark/usb_analysis.go`
  - `detectUSBMouseSnapshot()` 支持已确认鼠标端点上的空 payload `Interrupt` 完成帧继续归入 HID。
  - 空完成帧不生成鼠标行为事件，并保留上一帧鼠标状态。
  - 增加带 Report ID 前缀的 4/5/6 字节 mouse boot report 解析。

- `backend/internal/tshark/usb_analysis_test.go`
  - 覆盖鼠标端点空完成帧不再落入 Other 的判定。
  - 覆盖 Report ID 鼠标 payload 解析。
  - 增加 `GSHARK_USB_MOUSE_SAMPLE` 本地样本回归测试。

- `frontend/src/app/features/usb/*`
  - 新增鼠标轨迹状态分类：左键、右键、无按键、其他/多键。
  - 混合轨迹图按状态分色。
  - 新增左键轨迹图、右键轨迹图、无按键轨迹图。
  - 拆出 `UsbMouseTrajectorySvg.tsx` 控制组件尺寸预算。

- `frontend/src/app/pages/UsbAnalysis.test*`
  - 扩展 HID 鼠标 fixture 为左键、右键、无按键多段轨迹。
  - 覆盖四张轨迹图与图例渲染。

## 验证记录

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\backend
go test ./internal/tshark -run "TestUSB|TestDetectUSB|TestBuildUSBMouse" -count=1
$env:GSHARK_USB_MOUSE_SAMPLE='C:\Users\QAQ\Downloads\鼠标流量\鼠标流量.pcapng'; go test ./internal/tshark -run TestUSBMouseTrafficSampleRegression -count=1 -v
go test ./...

cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec vitest run src/app/pages/UsbAnalysis.test.tsx src/app/features/usb/UsbTablesSplit.test.tsx
pnpm run size:check
pnpm run typecheck
pnpm run lint
pnpm run format:check
pnpm run ci
```

结果：全部通过。前端完整 CI 覆盖 221 个测试文件、683 个测试。

## 提交说明

- 本报告按用户要求仅作为本地开发记录，不纳入提交。
- 本地鼠标样本只用于回归验证，不纳入提交。
