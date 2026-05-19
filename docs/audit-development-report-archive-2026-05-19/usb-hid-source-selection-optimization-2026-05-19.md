# USB HID 多协议数据源选择优化报告

署名：Codex

时间：2026-05-19 21:39:18 +08:00（Asia/Shanghai）

## 本轮目标

- 将 USB HID 鼠标解析升级为默认自动评分与手动数据源选择。
- 支持 `auto`、`usbhid.data`、`usb.capdata`、`btatt.value`、`raw fallback` 复核不同协议/字段下的轨迹。
- 保留混合轨迹图，并让左键、右键、无按键单图更接近 CTF scatter 绘图习惯。

## 文档评审

- 已阅读本日 USB 鼠标 HID 轨迹优化报告与 USB HID CTF 兼容优化报告。
- 本轮延续既有方向：后端加强 payload 来源与 layout 识别，前端提供复核入口与更清晰轨迹呈现。
- 未提交样本、`frontend/dist/`、`build/` 或本报告。

## 修改摘要

- 后端
  - USB 分析新增 `hid_source` query 参数与 `USBAnalysisOptions`。
  - 服务层按 HID source 缓存 USB 分析结果，避免不同手动源互相污染。
  - 鼠标 raw payload 构建候选源：`usbhid.data`、`usb.capdata`、`btatt.value`、`usb.control.Response`、`usb.frame.data`。
  - `auto` 模式按候选分数选择最佳鼠标 payload；同分优先 `usbhid.data`。
  - 支持 boot、report-id、GitHub 4/6/8 字节鼠标布局。
  - 鼠标事件增加 `source`、`layout`，USB 分析增加 source metadata。
  - 保留 Mass Storage 优先排除、键盘 hint 排斥鼠标误判、空完成帧归 HID 不产出鼠标事件。
  - 补充全零 release payload 回归，避免把真实释放事件误当空完成帧。

- 前端
  - USB HID 鼠标面板新增数据源选择器。
  - USB 分析请求携带 `hid_source`，缓存键增加 HID source 维度。
  - wire DTO、mapper、核心类型接收 source metadata 与鼠标事件 source/layout。
  - 鼠标明细表显示来源与布局。
  - 混合轨迹图保留连续分色线；左键、右键、无按键单图使用点阵模式、Y 轴取反、等比例缩放。
  - 热区图跟随 recovered 坐标方向。
  - 拆分 `UsbMousePanel.tsx` 维持前端 size budget。

## 验证记录

```powershell
cd C:\Users\QAQ\Desktop\gshark\backend
go test ./internal/tshark -run "TestUSB|TestDetectUSB|TestBuildUSBMouse" -count=1
go test ./...
$env:GSHARK_USB_MOUSE_SAMPLE='C:\Users\QAQ\Downloads\鼠标流量\鼠标流量.pcapng'; go test ./internal/tshark -run TestUSBMouseTrafficSampleRegression -count=1 -v

cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec vitest run src/app/pages/UsbAnalysis.test.tsx src/app/pages/analysisCacheKeys.test.ts src/app/integrations/clients/analysisClient.test.ts src/app/integrations/httpBridgeAggregation.test.ts
pnpm run ci

git diff --check
```

结果：全部通过。前端完整 CI 覆盖 221 个测试文件、683 个测试；Vite build 通过。样本回归通过，TShark 仅提示 `usbms.scsi.opcode` 可选字段缺失，不影响 HID 测试。

## 提交说明

- 本报告按用户要求仅本地保留，不纳入 commit。
- 本地鼠标样本只用于回归验证，不纳入提交。
