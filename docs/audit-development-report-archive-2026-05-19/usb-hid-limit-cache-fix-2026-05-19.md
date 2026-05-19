# USB HID 事件上限与缓存隔离修复报告

署名：Codex

时间：2026-05-19 22:17:25 +08:00（Asia/Shanghai）

## 本轮目标

- 修复 USB HID 分析在 `auto` / 手动 source 切换时的缓存污染。
- 新增 HID 事件 `hid_event_limit` 可配置能力。
- 输出 HID 事件截断与真实键盘/鼠标事件总量元数据。

## 最新文档评审

- 已阅读 `usb-hid-source-selection-optimization-2026-05-19.md`：现状已支持 `hid_source`、手动数据源与 source metadata，本轮继续沿用该接口并补齐 limit 缓存维度。
- 已阅读 `usb-mouse-hid-trajectory-optimization-2026-05-19.md`：现状要求空完成帧归入 HID 但不生成鼠标事件，本轮未改变该行为。
- 本轮只改后端相关文件；未回退工作区内既有前端、CI、misc、capture 等其他改动。

## 修改摘要

- `backend/internal/model/types.go`
  - `USBAnalysisOptions` 增加 `HIDEventLimit`。
  - `USBAnalysis` 增加 `hid_event_limit`、`hid_events_truncated`、`hid_mouse_events_total`、`hid_keyboard_events_total`。
  - 新增 HID 事件 limit 默认值与 clamp：默认 `20000`，最小 `500`，最大 `100000`。

- `backend/internal/tshark/usb_analysis.go`
  - 保留 `usbRecordLimit=2000` 用于通用 USB 记录、Mass Storage 与 Other。
  - HID keyboard/mouse event 数组改用 `HIDEventLimit`。
  - 即使事件数组达到上限，也继续统计真实键盘/鼠标事件总量。
  - 超过上限时设置 `hid_events_truncated=true` 并在 HID notes 记录截断说明。
  - 空完成帧仍只维持鼠标状态，不生成事件。

- `backend/internal/engine/service.go`
  - USB 分析缓存键纳入 `hid_source` 与规范化后的 `hid_event_limit`。
  - 默认 auto 缓存与手动 source 缓存隔离，manual source 不复用 auto cache。

- `backend/internal/transport/http_server.go`
  - `/api/analysis/usb` 解析 `hid_event_limit` query。
  - 非整数返回 `400 Bad Request`；数值按 model 规则 clamp 到合法区间。

- 测试
  - `backend/internal/tshark/usb_analysis_test.go` 覆盖 HID event limit、真实总量和截断 metadata。
  - `backend/internal/engine/usb_analysis_cache_test.go` 覆盖 source + limit cache key。
  - `backend/internal/transport/http_server_test.go`、`http_contract_test.go` 覆盖 query 参数与 JSON contract。

## 验证记录

```powershell
cd C:\Users\QAQ\Desktop\gshark\backend
go test ./internal/tshark -run "TestUSB|TestDetectUSB|TestBuildUSBMouse" -count=1
go test ./internal/transport -run "Test.*USB" -count=1
go test ./internal/engine -run "Test.*USB" -count=1
```

结果：全部通过。
