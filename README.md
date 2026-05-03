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
- pnpm 或 npm。
- Wireshark / tshark。

说明：

- 如果系统 `PATH` 中找不到 `tshark`，应用启动后会要求填写 `tshark.exe` 路径或 Wireshark 安装目录。
- 如果 `PATH` 中已有可用 `tshark`，应用会直接使用。
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
npm test
```

前端生产构建：

```powershell
cd frontend
npm run build
```

桌面资源构建：

```powershell
cd frontend
npm run build:wails
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
