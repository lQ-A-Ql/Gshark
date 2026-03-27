# 车联网与工控流量题考点整理

本文档基于公开题解、训练平台和协议资料，提炼在 CTF / 靶场中最常见、最值得直接产品化支持的流量考点。

## 车联网方向

### 高频考点

- `CAN` 状态位识别
  - 通过低基数 CAN ID、周期翻转、位变化找灯光、门锁、档位、刹车、转向等状态。
- `ISO-TP / UDS` 诊断链路
  - 常见题型围绕 `ReadDataByIdentifier`、`Security Access`、`Routine Control`、`Request Download / Transfer Data / Request Transfer Exit`。
- `KWP2000`
  - 重点看会话切换、鉴权和读 DID。
- `XCP`
  - 重点看 `GET_SEED / UNLOCK`、标定区读写、DAQ、`DOWNLOAD / UPLOAD`。
- `DoIP`
  - 重点看寻址、VIN、逻辑地址、是否存在未授权诊断入口。
- `DBC`
  - 题目经常会给 DBC 或可推导信号语义，核心是把 CAN Payload 还原为可读状态。

### 当前已落地

- CAN / ISO-TP / UDS / OBD-II / CANopen 基础解析
- DoIP 关键字段提取
- DBC 导入、报文映射、信号时间线
- UDS 请求响应配对
- 车机页补充了更偏 CTF 的提示：
  - `0x22` 读取 DID
  - `0x27` Security Access
  - `0x2E / 0x2F` 写类 / IO 控制
  - `0x34 / 0x36 / 0x37` 刷写链路
  - `XCP / KWP2000` 提示入口

### 下一步建议

- 增加 `XCP` 明细解析页面
- 增加 `KWP2000` 请求/响应配对
- 增加“状态位候选 CAN ID”自动排序

## 工控方向

### 高频考点

- `Modbus`
  - 读写线圈、保持寄存器、自动模式开关、设备状态位、异常码。
- `S7comm`
  - 十六进制数据、DB 块偏移、`Write Var`、`Download / Upload`、读块内容找 flag。
- `DNP3 / IEC104`
  - 遥控命令、对象索引、CauseTx、取值、时钟同步、重启。
- `BACnet`
  - `Write Property`、对象名、设备重初始化、属性值变更。
- `PROFINET`
  - `DCP Set`、station name、设备标识、IP 重新配置。

### 当前已落地

- Modbus、S7comm、DNP3、CIP、BACnet、IEC104、OPC UA、PROFINET 字段级解析
- 工控页补充了更偏 CTF 的提示：
  - Modbus 写类功能码
  - S7 下载 / 上传 / 写块
  - DNP3 控制 / 重启
  - BACnet 写属性 / 重初始化
  - IEC104 控制 / 设点 / 时钟同步
  - PROFINET DCP Set

### 下一步建议

- 增加 Modbus“可疑写目标”排序
- 增加 IEC104 / DNP3 控制指令专门面板
- 增加 S7 数据块十六进制转字符串辅助视图

## 产品化原则

- 先把“题目最常考的动作”做成显性提示，再继续扩协议深度。
- 优先支持“读 flag / 改状态 / 过鉴权 / 找异常命令”四类动作。
- 页面上要直接展示目标对象、结果状态和值，不要只堆协议字段。
