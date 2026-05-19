# USB HID 性能优化执行报告

署名：Codex

时间：2026-05-19 23:43:44 +08:00（Asia/Shanghai）

## 本轮目标

- 后端 USB/HID 分析改为轻量内存缓存：原始扫描只跑一次，`hid_source` 与 `hid_event_limit` 只做投影。
- 前端 USB/HID 鼠标轨迹与表格改为大样本友好渲染。
- 分工执行后由主线程复审，确保不提交样本、构建产物或开发报告。

## 文档评审

- 已阅读本日 USB HID source、limit、轨迹优化相关开发报告。
- 当前实现延续既有接口：`hid_source` 与 `hid_event_limit` API 语义保持不变，前端缓存键继续包含 capture revision、file path、packet total、source、limit。
- 本报告仅作为本地开发记录，不纳入 commit。

## 修改摘要

- 后端
  - USB 分析拆为 raw scan cache 与 source/limit projection。
  - 同一 capture 的 `auto/usbhid/capdata/btatt/raw` 切换复用原始扫描。
  - 同一 source 下调整 `hid_event_limit` 只重新投影和截断。
  - raw scan 增加 in-flight 去重，避免并发请求重复运行 TShark。
  - capture replacement、clear capture、capture commit 均清理 USB raw scan cache。
  - raw scan 失败不再被持久缓存，后续请求可重试。
  - USB 分析完成后若 capture 已切换，旧结果不会写入新 capture 缓存。
  - 移除 USB 分析路径不相关的 `WarmSpecializedFieldCache` 预热。

- 前端
  - 鼠标轨迹索引改为一次循环生成。
  - 坐标归一化改为单次 loop，避免大数组展开。
  - 混合图、左键图、右键图、无按键图共享归一化几何结果。
  - 鼠标轨迹从海量 SVG 节点改为 Canvas 绘制，保留颜色、起终点、Y 轴取反、连续/点阵语义。
  - HID keyboard/mouse 明细表默认渲染前 1000 行，提供“显示更多”递增。
  - source、limit、设备过滤变化时重置可见行数。
  - USB 分析前端缓存改为容量 5 的 LRU，并按 source+limit 隔离。

## 复审补丁

- 主线程复审额外补充：
  - `commitLoadedCapture()` 成功提交新 capture 时清理 raw USB scan cache。
  - `loadUSBAnalysisRawScan()` 遇到扫描失败时删除失败缓存项。
  - `USBAnalysisWithOptions()` 写缓存前校验当前 capture 是否仍为扫描开始时的 capture，防止陈旧结果污染缓存。

## 验证记录

```powershell
cd C:\Users\QAQ\Desktop\gshark\backend
go test ./internal/tshark -run "TestUSB|TestDetectUSB|TestBuildUSBMouse" -count=1
go test ./internal/engine -run "Test.*USB|Test.*Cache" -count=1
go test ./...
$env:GSHARK_USB_MOUSE_SAMPLE='C:\Users\QAQ\Downloads\鼠标流量\鼠标流量.pcapng'; go test ./internal/tshark -run TestUSBMouseTrafficSampleRegression -count=1 -v

cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec vitest run src/app/pages/UsbAnalysis.hidPanel.test.tsx src/app/features/usb/UsbTablesSplit.test.tsx src/app/features/usb/UsbTablesSplit.page.test.tsx src/app/features/usb/UsbMouseTrajectory.test.tsx src/app/features/usb/usbMouseGeometry.test.tsx src/app/features/usb/UsbMassStorageTables.test.tsx src/app/pages/analysisCacheKeys.test.ts
pnpm run ci

cd C:\Users\QAQ\Desktop\gshark
git diff --check
```

结果：全部通过。样本回归仅出现 `usbms.scsi.opcode` 可选字段缺失提示，TShark 仍可用，不影响 USB HID 样本验证。

## 复审结论

- 首次 USB 分析仍执行一次 TShark raw scan。
- source / limit 切换复用 raw scan，不重复跑 TShark。
- 并发同 capture USB 请求共享同一次 raw scan。
- capture 替换、清空、重新提交后缓存失效。
- 鼠标轨迹和 HID 表格已避免大样本 SVG/DOM 放大风险。
- 未提交样本、`frontend/dist/`、`build/` 或本开发报告。
