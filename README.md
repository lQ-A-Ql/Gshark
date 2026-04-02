# GShark-Sentinel

GShark-Sentinel 是一款面向安全分析师、CTF 选手、应急响应人员和协议分析场景的桌面端离线流量分析工具。项目以 `tshark` 为解析核心，前端提供面向分析工作的工作区视图，后端负责抓包加载、分页、对象导出、流重组、协议专项分析和插件执行。

## 技术栈

- 前端：React 18、TypeScript、Vite、Tailwind CSS、Radix UI、Monaco Editor
- 后端：Go 1.22、Wails v2
- 解析核心：tshark
- 通信方式：Wails 绑定 + 本地 HTTP/SSE
- 插件运行时：JavaScript、Python

## 当前能力

### 基础流量分析

- PCAP / PCAPNG 加载与分页浏览
- 主工作区数据包列表、协议树、Hexdump 联动
- 直接显示 tshark 提供的协议列
- 显示过滤、包定位、分页加载
- HTTP / TCP / UDP 流重组
- 流切换、流展示方式切换
- 对象导出与按文件后缀分类
- TLS 解密配置管理
- 流量图统计与协议分布查看

### 检测与专项分析

- 威胁狩猎与规则匹配
- 插件管理、插件编辑、插件运行日志
- 工控分析：Modbus、S7comm、DNP3、CIP、PROFINET、BACnet、IEC 104、OPC UA
- 车机分析：CAN、J1939、DoIP、UDS、OBD-II、CANopen
- CAN DBC 导入与信号解码
- 车机 0 基础教程与协议分析文档

## 目录结构

```text
.
├─ frontend/              前端界面与页面逻辑
├─ backend/               Go 后端、tshark 封装、专项分析模块
├─ docs/                  接口文档、方案文档、教程文档
├─ scripts/               启动与构建脚本
├─ app.go                 Wails 桌面端桥接入口
└─ wails.json             Wails 配置
```

## 环境要求

- Windows 环境下开发体验最佳
- Node.js 20+
- Go 1.22+
- `tshark`

说明：

- 如果系统 `PATH` 中找不到 `tshark`，应用启动页会直接要求填写 `tshark.exe` 路径或 Wireshark 安装目录。
- 若 `PATH` 中已存在可用的 `tshark`，应用会直接使用。

## 快速启动

### 方式一：前后端分开启动

启动后端：

```powershell
cd backend
go run ./cmd/sentinel serve :17891
```

启动前端：

```powershell
cd frontend
npm install
npm run dev
```

### 方式二：一键开发启动

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start-dev.ps1
```

### 方式三：Wails 桌面模式

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start-wails-dev.ps1
```

构建桌面应用：

```powershell
wails build
```

## 测试与构建

统一校验：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check-all.ps1
```

说明：

- 根目录 `go test ./...` 只覆盖桌面壳 module，不会替代 `backend` 目录下的后端测试
- `check-all.ps1` 会串行执行桌面壳测试、后端格式检查、后端测试、前端测试和前端构建

后端测试：

```powershell
cd backend
go test ./...
```

前端测试：

```powershell
cd frontend
npm install
npm run test
```

前端构建：

```powershell
cd frontend
npm run build
```

## 重点模块说明

### 1. 主工作区

主工作区用于完成常规离线分析，包含：

- 数据包列表
- 协议树
- Hexdump
- 显示过滤
- 包详情定位

协议列优先显示 tshark 原始列值，避免前端自行归一化带来的显示偏差。

### 2. 流量图

流量图模块用于查看整体分布信息，目前包括：

- 协议分布
- 源 IP
- 目标 IP
- 计算机名
- 域名
- 源端口 / 目标端口

其中：

- 计算机名优先从 NBNS 等协议字段提取
- 域名来自 HTTP Host、TLS SNI、DNS 查询等字段

### 3. 工控分析

工控分析模块用于提取 ICS 场景中的关键信息，当前已实现：

- Modbus 事务和功能码提取
- S7comm 操作和对象信息提取
- DNP3 明细与关键字段提取
- CIP / EtherNet-IP 关键信息提取
- PROFINET / PN-DCP / PN-IO 对象级信息提取
- BACnet、IEC 104、OPC UA 基础解析

### 4. 车机分析

车机分析模块用于查看车载网络中的协议和行为特征，当前已实现：

- CAN、J1939、DoIP、UDS 协议识别
- ISO-TP、UDS over CAN、OBD-II、CANopen payload 提取
- DBC 导入和 CAN 信号解码
- UDS 请求/响应配对
- DBC 信号时间线预览

## 插件系统

插件系统当前支持 JavaScript 和 Python 两类运行时。项目已经定义了插件和宿主之间的接口规范，详见：

- [插件接口文档](./docs/plugin-interface.md)

插件页面支持：

- 创建插件
- 编辑插件逻辑与 JSON 配置
- Monaco 编辑器
- JSON 实时校验
- 运行状态日志查看

## 文档入口

- [插件接口文档](./docs/plugin-interface.md)
- [车机流量分析方案](./docs/automotive-analysis-plan.md)
- [车机流量分析 0 基础教程](./docs/automotive-analysis-zero-basics.md)

## 当前边界

项目已经能满足离线分析和专项协议提取的主体流程，但仍有明确边界：

- 显示过滤当前直接使用 tshark display filter 语义；过滤表达式无效时会按 tshark 错误处理，不再回退旧的前端子集过滤逻辑
- Python / JavaScript 以外的插件运行时还未真正打通
- DBC 目前优先支持常见 `BO_ / SG_` 语法，`multiplexing` 与 `ARXML` 仍未覆盖
- 超大流和超大抓包场景下，个别专项模块仍需要继续做更细的增量化优化

## 适用场景

- CTF 流量题分析
- 应急响应中的离线包取证
- 协议专项排查
- 工控流量审计
- 车载网络抓包研判

## 许可与说明

本仓库中的示例流量、规则、插件和文档可能随着分析能力扩展继续调整。若你需要补充新的协议分析模块，建议优先在 `backend/internal/tshark/` 中增加字段提取与聚合逻辑，再在前端页面中增加可视化结果。
