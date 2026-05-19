# USB HID 事件上限前端优化报告

署名：Codex

时间：2026-05-19 22:05:49 +08:00（Asia/Shanghai）

## 本轮目标

- USB HID 鼠标 source 选择器改用项目公用 Select 控件。
- 新增 HID 事件 limit 控制，支持用户调整后重新请求。
- 当后端返回 HID 事件达到上限时，在鼠标面板展示截断提示与总量信息。

## 文档评审

- 已阅读本日 `usb-mouse-hid-trajectory-optimization-2026-05-19.md`、`usb-hid-ctf-compat-optimization-2026-05-19.md`、`usb-hid-source-selection-optimization-2026-05-19.md`。
- 既有文档已明确 HID source 选择、轨迹拆分、CTF 兼容方向；本轮前端改动延续该方向，只补足大样本事件上限交互。
- 本轮未评审后端 limit 实现细节；前端按 `hid_event_limit`、`hid_events_truncated`、`hid_mouse_events_total`、`hid_keyboard_events_total` wire 字段对接。

## 修改摘要

- `analysisClient` 的 `getUSBAnalysis(signal?, hidSource?, hidEventLimit?)` 会同时携带 `hid_source` 与 `hid_event_limit` query。
- USB wire/core/mapper 新增 HID limit 与截断元数据。
- `useUsbAnalysis` 缓存 key 加入 `hidEventLimit`，source 或 limit 变化都会重新请求。
- `UsbAnalysis.tsx` 持有默认 `hidEventLimit=20000` 并传入 HID 鼠标面板。
- `UsbMousePanel.tsx`
  - source selector 改用 `SelectField` / `SelectControl` 所在的项目公用 Select 体系。
  - limit 输入改用项目公用 `Input`。
  - blur 或 Enter 提交 limit；小于 500 clamp 到 500，大于 100000 clamp 到 100000，非数字恢复上次有效值。
  - 截断时展示当前 limit、mouse/keyboard total，并在轨迹区域提示“轨迹已按事件上限截断”。
- 前端测试覆盖 client 参数、mapper 字段、cache key、页面 source 公用控件、limit 请求与截断提示。

## 验证记录

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec vitest run src/app/pages/UsbAnalysis.test.tsx src/app/pages/analysisCacheKeys.test.ts src/app/integrations/clients/analysisClient.test.ts src/app/integrations/mappers/usbMapper.test.ts
pnpm run typecheck
```

结果：全部通过。Vitest 指定 4 个测试文件、18 个测试通过；TypeScript typecheck 通过。
