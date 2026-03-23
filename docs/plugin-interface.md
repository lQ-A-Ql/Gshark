# 插件接口规范 v1

本文档定义 GShark-Sentinel 当前插件系统与项目之间的稳定接口。目标是明确插件包结构、运行时约束、输入输出数据结构和兼容边界。

## 1. 适用范围

- 当前可执行运行时只支持 `JavaScript` 和 `Python`
- 可被发现但当前不会执行的后缀包括 `.ts`、`.lua`、`.go`
- 插件执行场景目前为“威胁狩猎”阶段的数据包扫描

## 2. 插件包结构

每个插件由两部分组成：

1. 配置文件：`<plugin-id>.json`
2. 逻辑文件：由 `entry` 指定，例如 `<plugin-id>.js` 或 `<plugin-id>.py`

示例：

```text
plugins/
  my-flag-detector.json
  my-flag-detector.py
```

## 3. 配置文件格式

配置文件为 JSON，对应字段如下：

```json
{
  "id": "my-flag-detector",
  "name": "My Flag Detector",
  "version": "0.1.0",
  "tag": "custom",
  "author": "User",
  "enabled": true,
  "entry": "my-flag-detector.py",
  "runtime": "python"
}
```

字段说明：

- `id`: 插件唯一标识，建议稳定且只使用字母、数字、`.`、`_`、`-`
- `name`: 展示名称
- `version`: 插件版本
- `tag`: 分类标签，例如 `custom`、`detect`、`extract`
- `author`: 作者
- `enabled`: 是否启用
- `entry`: 逻辑入口文件名
- `runtime`: 运行时类型；当前由入口文件后缀推导，建议与后缀保持一致

## 4. 项目传给插件的数据包结构

项目会把每个数据包以 JSON 对象形式传给插件。当前字段如下：

```json
{
  "id": 12,
  "time": "12:00:00.123",
  "src": "192.168.1.10",
  "srcPort": 52344,
  "dst": "10.0.0.5",
  "dstPort": 80,
  "protocol": "HTTP",
  "length": 512,
  "info": "GET /index.html HTTP/1.1",
  "payload": "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
  "rawHex": "47455420...",
  "streamId": 7,
  "ipHeaderLen": 20,
  "l4HeaderLen": 20
}
```

约束：

- 字段名大小写固定
- 允许字段为空字符串或 `0`
- 插件不应假设 `payload` 一定是文本，也不应假设 `rawHex` 一定存在

## 5. 插件产出格式

插件通过输出 `ThreatHit` 结构向项目回传命中结果。字段如下：

```json
{
  "packetId": 12,
  "category": "CTF",
  "rule": "my-flag-detector",
  "level": "high",
  "preview": "GET /index.html HTTP/1.1 ...",
  "match": "flag{...}"
}
```

字段约束：

- `packetId`: 命中的包号；没有明确包号时允许为 `0`
- `category`: 分类，默认可使用 `CTF`、`OWASP`、`Anomaly`、`Sensitive`
- `rule`: 规则名；为空时项目会回退为插件 `id`
- `level`: 仅支持 `critical`、`high`、`medium`、`low`
- `preview`: 命中摘要
- `match`: 触发关键字或证据；为空时项目会回退为插件 `id`

## 6. JavaScript 插件接口

JavaScript 插件必须导出：

- `onPacket(packet, ctx)`：必需
- `onFinish(ctx)`：可选

示例：

```javascript
export function onPacket(packet, ctx) {
  const info = String(packet.info || "");
  if (info.includes("flag{")) {
    ctx.emitHit({
      category: "CTF",
      rule: "my-flag-detector",
      level: "high",
      packetId: packet.id,
      preview: info.slice(0, 120),
      match: "flag",
    });
  }
}

export function onFinish(ctx) {
  ctx.log("scan finished");
}
```

`ctx` 当前提供：

- `ctx.emitHit(hit)`: 提交一条命中
- `ctx.log(message)`: 记录运行日志；当前日志只作为扩展点保留

## 7. Python 插件接口

Python 插件通过标准输入和标准输出与项目通信：

- `stdin`: 每行一个数据包 JSON
- `stdout`: 每行一条 `ThreatHit` JSON，或一行一个 `ThreatHit[]`

示例：

```python
import json
import sys

for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    packet = json.loads(raw)
    info = str(packet.get("info", ""))
    if "flag{" in info:
        sys.stdout.write(json.dumps({
            "category": "CTF",
            "rule": "my-flag-detector",
            "level": "high",
            "packetId": int(packet.get("id", 0) or 0),
            "preview": info[:120],
            "match": "flag"
        }, ensure_ascii=False) + "\n")
        sys.stdout.flush()
```

约束：

- 插件必须持续读取 `stdin`，直到 EOF
- 每一行输出必须是合法 JSON
- `stderr` 当前不会被前端展示，调试信息不要依赖 `stderr`

## 8. 执行模型

- 仅启用状态的插件会被创建运行会话
- 项目会按批次把多个包送入插件
- JavaScript 插件在同一 VM 中执行完整扫描
- Python 插件在独立进程中执行完整扫描
- 插件错误不会中断主流程，但会记录为 warning

## 9. 兼容性约定

- v1 不保证 `.ts`、`.lua`、`.go` 逻辑文件可执行
- 未来如果扩展运行时，优先新增文档版本，不直接破坏现有字段
- 新增字段只能追加，现有字段名和语义不应重定义

## 10. 当前实现对应位置

- 插件加载与保存：`backend/internal/plugin/manager.go`
- 插件运行时：`backend/internal/plugin/runtime.go`
- 前端插件编辑器：`frontend/src/app/pages/Plugins.tsx`

