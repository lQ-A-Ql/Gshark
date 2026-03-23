# 0 基础车机流量分析教程

## 这份教程适合谁

- 没做过车机安全
- 只会一点抓包，但看不懂 `CAN / UDS / DoIP / J1939`
- 想知道在 GShark-Sentinel 里应该先点哪里、先看什么

## 先建立最小概念

### 1. 车机流量不只一种

常见会遇到 4 类：

- `CAN`
  - 车里最常见的总线报文
  - 特点是报文短、频率高、靠 `ID` 区分含义
- `J1939`
  - 建立在 CAN 之上，重型车和部分工业车辆常见
  - 重点看 `PGN / Source Address / Target Address`
- `UDS`
  - 诊断协议
  - 重点看 `SID`，例如 `0x10/0x27/0x31/0x34/0x36/0x37`
- `DoIP`
  - Diagnostics over IP，诊断走以太网
  - 经常和 UDS 一起出现

### 2. 你真正要回答的问题

分析车机抓包，本质上是在回答这些问题：

- 抓包里到底有哪些协议
- 有没有诊断行为
- 有没有高风险诊断行为
- CAN 报文到底代表什么信号
- 某个 ECU 是否在异常通信

## 在 GShark-Sentinel 里的推荐顺序

### 第一步：先打开“车机分析”

进入 [VehicleAnalysis.tsx](/C:/Users/QAQ/Desktop/gshark/frontend/src/app/pages/VehicleAnalysis.tsx) 对应页面后，先看这 4 个区域：

- `车载协议分布`
  - 先确认抓包里到底有 `CAN / J1939 / UDS / DoIP` 哪些协议
- `网络 / 总线视图`
  - 看通信双方或者总线分布是否集中
- `CAN 总线`
  - 看 `Bus ID`、`Message ID`、错误帧、扩展帧
- `UDS`
  - 看是否出现诊断服务、负响应、DTC

如果连 `UDS` 和 `DoIP` 都没有，通常就先不要硬往“诊断攻击”方向推，先回到 CAN/J1939 基线分析。

## 如何看 CAN

### 1. 先看 Message ID 分布

如果某几个 `CAN ID` 数量特别高，先不要紧张，这可能是正常周期报文。你真正要关注的是：

- 某个 ID 突然异常密集
- 错误帧明显增多
- 平时不常见的 ID 突然出现
- 报文长度、扩展帧属性和历史不一致

### 2. 没有 DBC 时怎么办

没有 DBC 时，CAN 只能看到：

- `ID`
- `长度`
- `原始 payload`

这时你能做的是：

- 看哪些 ID 最活跃
- 看哪些 ID 与特定行为同时出现
- 看 payload 是否有明显模式变化

### 3. 有 DBC 时怎么看

如果你有 `.dbc` 文件，可以在车机分析页顶部的 `DBC 映射` 区域导入。

导入后，页面会出现：

- `DBC 报文分布`
- `DBC 信号分布`
- `DBC 解码明细`
- `DBC 信号时间线`

这时分析就从“看十六进制”升级成“看语义”：

- `VehicleSpeed=60 km/h`
- `BrakeSwitch=1`
- `DoorStatus=Open`

### 4. DBC 信号时间线怎么用

先看：

- `样本数`
- `最新值`
- `最小值`
- `最大值`

它适合快速判断：

- 某个速度信号是否跳变异常
- 某个开关量是否频繁抖动
- 某个状态位是否长时间保持异常值

## 如何看 UDS

### 1. 先记住几个高风险 SID

- `0x10` Diagnostic Session Control
- `0x27` Security Access
- `0x31` Routine Control
- `0x34` Request Download
- `0x36` Transfer Data
- `0x37` Request Transfer Exit

只要这几个服务出现，就值得重点看。

### 2. 先看“UDS 明细”

这里能快速回答：

- 谁在发诊断请求
- 请求了什么服务
- 有没有 DID / DTC
- 有没有负响应

### 3. 再看“UDS 配对事务”

这里比原始明细更重要，因为它把请求和响应配对了。重点看：

- `状态`
  - `positive`：正常响应
  - `negative`：负响应
  - `request-only`：只有请求，没有响应
  - `orphan-response`：只有响应，没匹配到请求
- `耗时(ms)`
  - 明显偏高时，通常要关注 ECU 处理异常、链路拥塞或诊断失败
- `对象`
  - 看 `DID / DTC / SubFunction`

### 4. 常见判断方式

- 如果连续出现 `0x27`，说明有人在做安全访问尝试
- 如果出现 `0x34/0x36/0x37`，要怀疑刷写或固件传输
- 如果大量 `negative`，要看是不是权限不足、会话不对、条件不满足
- 如果大量 `request-only`，要看是链路丢包还是 ECU 不响应

## 如何看 DoIP

DoIP 主要是“诊断入口”视角。

优先看：

- `VIN`
- `逻辑地址`
- `消息类型`
- `响应码`

重点问题：

- 是否暴露了 VIN
- 是否出现了异常逻辑地址探测
- 是否存在未授权路由激活或诊断接入

如果 `DoIP` 和 `UDS` 同时存在，通常说明这是完整的以太网诊断链路。

## 如何看 J1939

J1939 重点不是 SID，而是：

- `PGN`
- `Source Address`
- `Target Address`

建议看法：

- 先看最常见 PGN
- 再看源地址和目标地址是否异常集中
- 最后结合 `DataPreview` 看是否存在明显控制/诊断类数据

## 一套实战检查清单

拿到一个未知车机抓包后，按下面顺序走：

1. 先看协议分布，确认有没有 `UDS / DoIP / CAN / J1939`
2. 看 CAN ID 分布和错误帧，建立总线基线
3. 如果有 DBC，立刻导入，切到信号视角
4. 看 UDS 服务分布，先筛高风险 SID
5. 看 UDS 配对事务，筛负响应、高延迟、孤立响应
6. 看 DoIP 地址和 VIN，确认有没有诊断入口暴露
7. 结合 DBC 信号时间线，判断诊断行为是否引起状态变化

## 常见误区

### 1. 看到 UDS 就等于攻击

不对。售后、调试、产线、研发都可能有正常 UDS。

真正要看的是：

- 服务类型
- 频率
- 是否失败
- 是否涉及鉴权、刷写、例程

### 2. 没有 DBC 就完全没法分析

不对。没有 DBC 仍然可以做：

- ID 基线
- 频率分析
- 诊断行为识别
- 地址关系分析

只是做不到精确的“信号语义解释”。

### 3. 负响应一定是异常攻击

不对。很多正常诊断流程也会出现负响应。

更重要的是看：

- 负响应码类型
- 是否持续重复
- 是否集中在高风险服务上

## 在当前项目里对应的主要能力

- 后端车机分析主入口：
  - [vehicle_analysis.go](/C:/Users/QAQ/Desktop/gshark/backend/internal/tshark/vehicle_analysis.go)
- CAN payload / OBD / CANopen：
  - [vehicle_can_payload.go](/C:/Users/QAQ/Desktop/gshark/backend/internal/tshark/vehicle_can_payload.go)
- DBC 解析：
  - [dbc.go](/C:/Users/QAQ/Desktop/gshark/backend/internal/tshark/dbc.go)
  - [vehicle_dbc.go](/C:/Users/QAQ/Desktop/gshark/backend/internal/tshark/vehicle_dbc.go)
- UDS 配对与信号时间线：
  - [vehicle_postprocess.go](/C:/Users/QAQ/Desktop/gshark/backend/internal/tshark/vehicle_postprocess.go)
- 前端页面：
  - [VehicleAnalysis.tsx](/C:/Users/QAQ/Desktop/gshark/frontend/src/app/pages/VehicleAnalysis.tsx)

## 下一步该学什么

如果你已经能看懂这份教程，下一步建议是：

1. 学会区分 `UDS request / positive response / negative response`
2. 学会从 DBC 中找到关键安全信号
3. 学会把 `DoIP + UDS + DBC` 三者串起来看
4. 再往后才是更深的 `ARXML / 刷写流程 / ECU 状态机`
