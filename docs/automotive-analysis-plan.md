# 车机流量分析方案

## 目标

在 GShark-Sentinel 中形成一套面向车载总线与诊断协议的分层分析能力，既能快速看懂抓包里出现了什么协议，也能把安全风险直接落到可审计的对象上。

## 分层策略

### 第一层：总线与链路基线

- CAN / CAN FD
  - 统计报文 ID、Bus ID、RTR/扩展帧/错误帧占比
  - 识别异常喷发、错误恢复、Bus-Off、异常 ACK
- J1939
  - 聚焦 PGN、源地址、目标地址
  - 区分广播类 PGN、诊断类 PGN、控制类 PGN

### 第二层：以太网诊断路径

- DoIP
  - 审计 VIN、逻辑地址、测试设备地址、路由激活
  - 识别是否存在未授权诊断入口或异常发现/激活流程
- UDS
  - 审计 SID、SubFunction、DID、DTC、负响应码
  - 重点跟踪会话切换、安全访问、例程控制、刷写链路

### 第三层：安全专项

- 高风险服务
  - `0x27 Security Access`
  - `0x31 Routine Control`
  - `0x34 Request Download`
  - `0x36 Transfer Data`
  - `0x37 Request Transfer Exit`
- 高价值信息
  - VIN
  - ECU 逻辑地址
  - DTC
  - DID
- 异常信号
  - 大量负响应码
  - 非预期会话切换
  - 固件下载/传输痕迹
  - 未经鉴权的诊断控制

## 当前实现边界

- 已实现
  - CAN / J1939 / DoIP / UDS 协议识别
  - 关键字段提取与聚合展示
  - 面向安全审计的建议输出
- 待扩展
  - OBD-II PID 级解析
  - CAN payload 语义解码（DBC）
  - UDS 请求-响应关联与时序图
  - 刷写流程完整事务链重建

## 后续优先级

1. DBC/ARXML 映射，让 CAN/J1939 不只展示 ID，而能落到信号语义
2. UDS request/response 配对，补充耗时与失败链
3. DoIP + UDS 组合事务视图，直接标出诊断会话、鉴权、刷写动作
4. 风险规则库，将安全访问、下载、例程、异常负响应纳入自动告警
