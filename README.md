# GShark-Sentinel

GShark-Sentinel 是一款面向安全分析师、CTF 选手、应急响应人员、协议研究和危险应用分析场景的桌面端离线流量分析工具。项目以 `tshark` 为解析核心，前端提供高信息密度的分析工作区与专项页面，后端负责抓包加载、分页、流重组、对象提取、协议专项分析、威胁狩猎和 MISC 模块执行。

## 核心特性

- 离线 PCAP / PCAPNG 加载、分页浏览、包定位和显示过滤。
- 数据包列表、协议树、Hexdump、tshark 原始列值联动查看。
- HTTP / TCP / UDP 流重组，支持从分析结果回跳原始包和关联流。
- 对象提取、TLS 解密配置、流量图、威胁狩猎和规则匹配。
- 工控、车机、媒体、USB 等专项分析页面。
- MISC 工具箱支持内建协议辅助工具和 zip 自定义模块。
- JavaScript / Python 扩展运行时，用于威胁狩猎插件与 MISC 自定义模块。

## 技术栈

- 桌面框架：Wails v2
- 后端：Go 1.22+（桌面壳）/ Go 1.25（后端模块）
- 前端：React 18、TypeScript、Vite、Tailwind CSS、Radix UI
- 解析核心：tshark
- 本地通信：Wails 绑定 + 本地 HTTP / SSE
- 扩展运行时：JavaScript、Python

## 功能概览

### 主工作区

- 抓包文件加载、分页、跳页和包号定位。
- 显示过滤表达式直接使用 tshark display filter 语义。
- 协议树、Hexdump、原始协议列和选中包联动。
- 从选中包跟踪 HTTP / TCP / UDP 流。
- 支持包级证据回跳，便于从专项结论追溯原始上下文。

### 流与对象

- HTTP stream 查看与搜索。
- TCP / UDP 原始流分页查看。
- 流内容解码工作台。
- 对象提取、预览和导出。
- TLS key log / 私钥配置辅助。

### 专项协议分析

- 工控分析：Modbus、S7comm、DNP3、CIP / EtherNet-IP、PROFINET、BACnet、IEC 104、OPC UA。
- 车机分析：CAN、J1939、DoIP、UDS、OBD-II、CANopen。
- CAN DBC 导入、信号解码和时间线预览。
- 媒体流分析、播放素材生成、语音转写和批量导出。
- USB HID、Mass Storage、控制传输与原始包分析。
- 威胁狩猎中心和规则匹配。

### MISC 工具箱

MISC 工具箱用于承载低频但高价值的协议辅助能力。当前内建模块包括：

- HTTP 登录行为分析：聚合登录/认证请求，识别成功、失败、二次验证和疑似爆破。
- SMTP 会话重建：还原认证、发件人、收件人、邮件内容和附件线索。
- MySQL 会话重建：提取握手、登录用户、默认库、SQL、OK/ERR 和结果集响应。
- Shiro rememberMe 分析：定位 rememberMe Cookie，识别 deleteMe 痕迹，测试默认/自定义 AES key。
- NTLM 会话材料中心：统一提取 HTTP / WinRM / SMB3 中的 challenge、NT proof、session key 和方向信息。
- WinRM 解密辅助：对 WinRM over HTTP + NTLM 流量做明文提取、预览和导出。
- SMB3 Random Session Key：基于 SMB3 / NTLM 会话材料辅助生成 Random Session Key。

MISC 模块特性：

- 内建模块支持统一卡片式工作台。
- 结构化结果支持 JSON / TXT 导出。
- 协议线索可联动包号定位和关联流跳转。
- 支持导入 zip 自定义模块。
- 自定义模块以 `manifest.json + api.json + form.json + backend.js/.py` 交付。
- 自定义模块可使用 JavaScript 或 Python 运行时。

相关文档：

- [MISC 模块接口文档](./docs/misc-module-interface.md)

## 扩展方式

### 威胁狩猎插件

威胁狩猎插件用于对数据包进行扫描、命中上报和规则化分析，适合：

- IOC 扫描；
- 危险应用特征匹配；
- payload 关键字提取；
- 自定义风险标记。

插件接口见：

- [插件接口文档](./docs/plugin-interface.md)

### MISC 自定义模块

MISC 自定义模块适合把轻量、低频、强场景化的辅助工具接入桌面工作台，例如：

- 字段提取；
- 协议辅助分析；
- 文本解码；
- key / token / IOC 快速处理；
- 针对单类题目或单类流量的专用小工具。

脚手架：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\new-misc-module.ps1 -Id echo-demo -Title "Echo Demo" -Runtime javascript -Zip
```

Python 模块示例：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\new-misc-module.ps1 -Id py-scan-demo -Title "Python Scan Demo" -Runtime python -Zip
```

示例模块：

- [examples/misc-modules/echo-demo](./examples/misc-modules/echo-demo)

## 目录结构

```text
.
├─ frontend/              React 前端、页面、组件和 Wails bridge
├─ backend/               Go 后端、tshark 封装、协议分析和模块运行
├─ docs/                  接口文档、方案文档和教程
├─ examples/              示例插件和 MISC 模块
├─ scripts/               启动、构建、发布和脚手架脚本
├─ app.go                 Wails 桌面壳桥接入口
├─ main.go                桌面应用入口
└─ wails.json             Wails 配置
```

## 环境要求

- Windows 环境下开发体验最佳。
- Go 1.22+（桌面壳）/ Go 1.25（后端模块，go.work 统一管理）。
- Node.js 20+。
- pnpm。
- Wireshark / tshark。

说明：

- 如果系统 `PATH` 中找不到 `tshark`，应用启动后会要求填写 `tshark.exe` 路径或 Wireshark 安装目录。
- 如果 `PATH` 中已有可用 `tshark`，应用会直接使用。
- 后端进程会读取 `GSHARK_FFMPEG`、`GSHARK_PYTHON`、`GSHARK_VOSK_MODEL` 作为 FFmpeg、Python 与 Vosk 模型目录的显式配置；这些值会显示在运行时组件设置的“显式配置”输入框中。
- 运行时组件设置里的输入框为空，不等于组件不可用。输入框代表用户固定保存的显式路径；下方状态卡显示后端从环境变量、`PATH` 或默认目录探测到的当前实际路径。
- 保存空的 FFmpeg / Python / Vosk 字段会清除当前后端进程中的对应 `GSHARK_*` 显式配置，随后回到 `PATH` 或默认目录探测。
- 旧版前端可能留下全空的运行时配置缓存；新版启动会把这类缓存迁移为“自动观测配置”，不会再用空值覆盖后端进程已经读取到的 `GSHARK_*` 环境变量。只有用户在设置侧栏点击“保存并应用”的字段才会作为显式配置写回后端。
- `tshark` 能力探测中出现 `profile=compat` 或缺少 `usbms.scsi.opcode` 等可选字段时，表示部分专项分析降级，不表示 `tshark` 不可用。抓包入口只以 `tshark.available` 作为可用判断。
- 语音转写状态会拆分显示 Python、`vosk` 包、Vosk 模型目录和 FFmpeg。Python 已就绪但默认模型目录不存在时，`speech.available=false` 是模型缺失，不是 Python 不可读。
- Wails 配置默认使用 `pnpm install` 和 `pnpm run build:wails`。

## 快速启动

一键桌面开发启动：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start-dev.ps1
```

直接启动 Wails 开发模式：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start-wails-dev.ps1
```

说明：

- 项目当前是桌面端优先工作流。
- `scripts/start-dev.ps1` 会委托给 `scripts/start-wails-dev.ps1`。
- `start-wails-dev.ps1` 默认会清理旧的内嵌后端缓存：`frontend/dist/sentinel-backend.exe`、`build/bin/sentinel-backend.exe` 和 `%TEMP%\gshark-sentinel\backend`，避免 Wails dev 复用过期后端。需要跳过清理时可传 `-NoClean`；怀疑 Go 构建缓存命中旧产物时可额外传 `-CleanGoCache`。
- Wails 桌面环境的运行时组件探测优先走 Wails IPC 代理；HTTP 只作为普通浏览器模式或 Wails binding 不存在时的 fallback。这样可以避免“后端已连接，但 `/api/tools/runtime-config` 因 token、origin 或端口复用失败导致设置页全是未检测”的链路分裂。
- 启动页和运行时组件设置都提供“重新探测工具”，用于重新读取 TShark、FFmpeg、Python/Vosk 与 YARA 状态。运行时探测分为快速状态和完整能力探测：启动时先读取 `probe=fast`，只确认路径、解释器和模型目录等低成本状态；随后后台执行 `probe=full`，再补齐 TShark 字段能力、Python `vosk` 包和 YARA 规则包等慢探测。设置页会显示最近一次探测链路（Wails IPC / HTTP fallback）、探测模式、组件耗时和失败原因。
- `/api/tools/runtime-config` 默认保持完整探测；前端启动和手动刷新会显式请求 `?probe=fast`，避免 3500ms 启动预算被 TShark `-G fields` 或 Python `import vosk` 等慢探测拖成“工具不可读”。Wails IPC 快速探测若 2 秒内没有返回，会自动尝试 HTTP fast fallback，并保留原始 IPC 超时原因。
- `/api/runtime/identity` 会返回后端 `build_id`、可执行文件路径、工作目录和启动时间；`start-wails-dev.ps1` 也会输出端口和探测提示。若控制台仍出现旧文案 `tshark capability: ... missing optional fields ...`，优先检查旧后端进程、旧二进制或缓存，而不是把它判断为 TShark 不可读。
- `tshark capability degraded ... optional fields missing ... (tshark remains available)` 只表示可选字段降级，不表示 TShark 不可用。
- 抓包首屏加载默认使用轻量 `first_screen` 字段集快速生成包列表；颜色特征、UDP payload、checksum 和专项协议辅助字段会通过后台 enrichment 补齐，不阻塞进入工作区。
- 预加载诊断中的 `page=0/0 status=-` 表示前端读到的 committed capture 仍为空。若后端正在解析，`/api/capture/status` 会同时返回 `load.phase`、`parser_profile`、`processed`、`accepted`、`staged_count` 等 active load 信息，前端会显示“后端正在解析，尚未提交首屏数据”，而不是误报首屏数据失败。
- Wails 桌面环境下抓包状态和首屏分页都优先走 Wails IPC；失败时会回退 HTTP，并在预加载诊断中分别显示 `pageTransport` 和 `statusTransport`。

## 测试与验证

统一校验：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check-all.ps1
```

后端测试：

```powershell
cd backend
go test ./...
```

前端测试：

```powershell
cd frontend
pnpm run test:run
```

前端生产构建：

```powershell
cd frontend
pnpm run build
```

说明：`pnpm run build` 只执行 Vite 静态前端构建，不能作为桌面运行验收。它不会保证 `frontend/dist` 中存在内嵌后端二进制和 YARA 规则。

桌面资源构建：

```powershell
cd frontend
pnpm run build:wails
```

`build:wails` 会在 Vite 构建后生成并复制 `sentinel-backend.exe` 与 `rules/yara/default.yar`，随后执行桌面资源检查。也可以单独运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1
```

## 构建与发布

构建桌面应用：

```powershell
wails build
```

准备发布包与 `version.json`：

```powershell
python .\scripts\build_release_package.py v0.0.5
```

复用现有 exe 并跳过构建：

```powershell
python .\scripts\build_release_package.py v0.0.5 --skip-build
```

发布脚本默认行为：

- 执行桌面应用构建；
- 整理发布包到 `release/out/<version>/`；
- 生成 `release/out/<version>/version.json`；
- 同步更新仓库内的 `release/version.json`；
- 优先读取 `release/notes/<version>.md` 作为 release notes。

## 文档入口

- [文档中心](./docs/README.md)
- [MISC 模块接口文档](./docs/misc-module-interface.md)
- [插件接口文档](./docs/plugin-interface.md)
- [车机流量分析方案](./docs/automotive-analysis-plan.md)
- [车机流量分析 0 基础教程](./docs/automotive-analysis-zero-basics.md)
- [车机与工控分析重点说明](./docs/ctf-vehicle-industrial-focus.md)

## 当前边界

- 显示过滤直接使用 tshark display filter 语义，表达式无效时按 tshark 错误处理。
- Python / JavaScript 以外的扩展运行时尚未打通。
- zip 自定义模块当前使用统一卡片模板，不支持自定义前端样式。
- DBC 当前优先支持常见 `BO_ / SG_` 语法，multiplexing 与 ARXML 仍需继续扩展。
- 超大流和超大抓包场景下，部分专项模块仍需要更细的增量化优化。

## 适用场景

- CTF 流量题分析；
- 应急响应中的离线包取证；
- 协议专项排查；
- 工控流量审计；
- 车载网络抓包研判；
- 危险应用和威胁流量分析；
- 低频但高价值的安全辅助工具集成。

## 许可与说明

本仓库中的示例流量、规则、模块、插件和文档可能随着分析能力扩展继续调整。若要新增协议分析能力，建议优先在后端增加字段提取与聚合逻辑，再在前端页面中增加可视化结果；若只是补一个轻量辅助工具，优先考虑接入 MISC zip 模块体系。
