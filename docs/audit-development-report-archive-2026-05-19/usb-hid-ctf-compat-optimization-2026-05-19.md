# USB HID CTF 兼容优化报告

署名：Codex

时间：2026-05-19 20:59:00 +08:00（Asia/Shanghai）

## 本轮目标

- 借鉴 `Mumuzi7179/UsbKeyboard_Mouse_Hacker_Gui` 对键鼠流量的 CTF 兼容处理。
- 不实现导出功能。
- 强化键盘/鼠标 HID payload 兼容与前端复原展示。

## 文档评审

- 已阅读本日最新 USB 鼠标 HID 优化报告，当前改动延续同一 USB HID 分层：后端只增强识别与事件生成，前端只增强复原展示。
- 本轮不改变 HTTP API 路由，不引入导出产物，不提交样本。

## 修改摘要

- 后端 `backend/internal/tshark/usb_analysis.go`
  - USB 分析字段新增 `btatt.value`，支持蓝牙 HID 键盘 payload 来源。
  - 键盘 raw boot report 增加候选窗口：原始前 8 字节、跳过 1 字节前缀、尾部 8 字节。
  - 蓝牙/HID 摘要记录允许进入键盘 raw 解析，不依赖 USB Interrupt transfer type。
  - 鼠标增加 8 字节偏移布局解析，兼容部分 CTF/笔记本鼠标流量。

- 前端 `frontend/src/app/features/usb/*`
  - 新增键盘“编辑后文本”和“删除字符”展示，处理 Backspace 与 CapsLock。
  - 鼠标轨迹支持 screen/recovered 坐标模式；混合轨迹图使用 Y 轴取反，贴近 CTF 还原图形习惯。
  - 拆分 keyboard edit / mouse geometry 小模块，保持 size budget。

- 测试
  - 后端新增 btatt/prefixed keyboard payload、8 字节鼠标 offset payload 覆盖。
  - 前端 USB fixture 增加 Backspace、CapsLock、编辑文本断言。

## 验证记录

```powershell
cd C:\Users\QAQ\Desktop\gshark\backend
go test ./internal/tshark -run "TestUSB|TestDetectUSB|TestBuildUSBMouse|TestBuildUSBKeyboard" -count=1
go test ./...
$env:GSHARK_USB_MOUSE_SAMPLE='C:\Users\QAQ\Downloads\鼠标流量\鼠标流量.pcapng'; go test ./internal/tshark -run TestUSBMouseTrafficSampleRegression -count=1 -v

cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run ci

git diff --check
```

结果：全部通过。前端完整 CI：221 个测试文件、683 个测试通过；Vite build 通过。

## 提交说明

- 本报告为本地开发记录，按用户先前要求不纳入 commit。
- 未提交样本、`frontend/dist/`、`build/`。
