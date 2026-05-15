# MISC 模块接口规范 v3

本文档描述当前 `MISC` 区模块化能力的真实落地形态，重点覆盖：

- 单 `exe` 客户端下为什么采用 zip 模块包
- zip 模块包的目录结构
- `manifest.json`、`api.json`、`form.json`、`backend.js/.py` 的约定
- JavaScript / Python 模块可用的宿主能力
- 统一结果格式，包括文本、JSON、表格
- 脚手架生成方式

## 1. 设计边界

当前客户端是单 `exe` 形态，因此不支持在运行时直接热加载：

- 新的 Go 后端源码
- 新的 React / TSX 卡片源码
- 自定义前端样式体系

所以当前可导入模块采用的是“声明式 + 脚本后端”方案：

- 模块元数据：`manifest.json`
- 调用元数据：`api.json`
- 卡片表单：`form.json`
- 后端逻辑：`backend.js` 或 `backend.py`

对应结论是：

- `zip 模块包 = 元数据 + 接口声明 + 表单声明 + 脚本后端`

### 1.1 执行信任边界

`MISC` zip 自定义模块是本地可信扩展点，不是强沙箱。导入模块等价于允许该模块在本机以当前用户权限运行 `backend.js` 或 `backend.py`，因此只应导入自己编写、来源可信或已经审查过的模块。

当前宿主提供的是工程约束和能力收口，而不是恶意代码隔离：

- zip 包会经过路径、模块 ID、入口文件和大小等导入校验，防止误导入、路径穿越和明显损坏的包。
- 模块不能注册任意 HTTP 路由，也不能携带自定义前端源码或样式；所有表单和结果由宿主统一渲染。
- `host_bridge` 只暴露宿主明确实现的 helper 方法；未开启时，Python 模块只能通过标准输入/输出与宿主交换一份 JSON。
- JavaScript/Python 运行时仍属于本地代码执行面，不能承诺抵御恶意脚本读取文件、发起本机进程行为或消耗资源。

安全使用规则：

- 不要导入未知来源 zip 模块。
- 不要把 `host_bridge` 当作权限模型；它只是宿主能力桥接开关。
- 需要强隔离、远程不可信代码执行或细粒度权限审计时，应在系统级沙箱、虚拟机或独立进程策略中解决，而不是依赖 MISC 模块机制本身。
- 需要深度访问 Go 服务、长期维护或更强治理的能力，应升级为内置模块，并通过后端代码审查和测试覆盖。

## 2. 当前两类模块

### 2.1 内置模块

适合复杂、深耦合、需要专属页面逻辑的能力。

当前示例：

- `winrm-decrypt`
- `smb3-session-key`

特点：

- 通过 Go 代码注册
- 可以拥有专属前端渲染器
- 适合复杂协议分析和深度交互

相关入口：

- 后端注册：`backend/internal/transport/misc_modules.go`
- 前端专属渲染器注册：`frontend/src/app/misc/registry.tsx`

### 2.2 zip 自定义模块

适合无需重新编译客户端、可由用户导入的轻量模块。

特点：

- 通过 zip 包导入
- 后端运行时支持 `JavaScript` / `Python`
- 前端统一卡片模板渲染
- 模块不允许自带卡片样式

当前安装目录：

- 默认：用户配置目录下的 `gshark-sentinel/plugins/misc/<module-id>/`
  - Windows 通常为 `%AppData%\gshark-sentinel\plugins\misc\<module-id>`
  - macOS/Linux 以 Go `os.UserConfigDir()` 返回值为准
- 可通过环境变量 `GSHARK_MISC_PACKAGE_DIR` 覆盖 zip 模块安装根目录。
- 旧版曾按进程 cwd 写入 `plugins/misc/<module-id>/`；新开发和测试不应再写入源码树。

## 3. 模块发现接口

前端通过下面的接口拉取所有可见模块：

- `GET /api/tools/misc/modules`

返回类型为 `MiscModuleManifest[]`，内置模块和 zip 模块会一起返回。

示例：

```json
[
  {
    "id": "ioc-demo",
    "kind": "custom",
    "title": "IOC Demo",
    "summary": "在文本或流量结果中提取 IOC。",
    "tags": ["IOC", "Regex"],
    "api_prefix": "/api/tools/misc/packages/ioc-demo",
    "docs_path": "docs/misc-module-interface.md",
    "requires_capture": false,
    "interface_schema": {
      "method": "POST",
      "invoke_path": "/api/tools/misc/packages/ioc-demo/invoke",
      "runtime": "javascript",
      "entry": "backend.js",
      "host_bridge": false
    },
    "form_schema": {
      "description": "使用统一卡片模板渲染的自定义模块。",
      "submit_label": "运行 IOC 模块",
      "result_title": "执行结果",
      "fields": [
        {
          "name": "keyword",
          "label": "Keyword",
          "type": "text",
          "default_value": "mimikatz"
        }
      ]
    }
  }
]
```

关键字段：

- `kind`: `builtin` 或 `custom`
- `api_prefix`: 模块 API 前缀
- `protocol_domain`: 模块面向的协议/场景域，例如 `HTTP / Shiro`
- `supports_export`: 模块结果是否提供导出能力
- `cancellable`: 模块执行能力位，表示前端请求支持中途取消或切换时自动中断；它不是协议语义，也不表示操作可回滚
- `depends_on`: 模块依赖的基础能力，例如 `capture`、`http`、`ntlm`
- `interface_schema`: 宿主托管的统一执行信息
- `form_schema`: 宿主渲染统一卡片时使用的表单定义

## 4. zip 模块包结构

推荐结构：

```text
ioc-demo.zip
  manifest.json
  api.json
  form.json
  backend.js
```

也支持 zip 内多包一层根目录：

```text
ioc-demo.zip
  ioc-demo/
    manifest.json
    api.json
    form.json
    backend.js
```

## 5. `manifest.json`

负责声明模块元信息和入口文件位置。

示例：

```json
{
  "id": "ioc-demo",
  "title": "IOC Demo",
  "summary": "在文本中提取 IOC。",
  "version": "0.1.0",
  "author": "User",
  "tags": ["IOC", "Regex"],
  "requires_capture": false,
  "backend": "backend.js",
  "api": "api.json",
  "form": "form.json"
}
```

字段说明：

- `id`: 模块唯一标识，只允许字母、数字、`.`、`_`、`-`
- `title`: 模块标题，必填
- `summary`: 模块摘要
- `version`: 可选版本号
- `author`: 可选作者
- `tags`: 模块标签
- `requires_capture`: 是否依赖当前已加载抓包
- `backend`: 后端脚本相对路径，默认 `backend.js`
- `api`: 调用元数据文件相对路径，默认 `api.json`
- `form`: 表单定义文件相对路径，默认 `form.json`

## 6. `api.json`

负责声明统一执行入口的元信息。

示例：

```json
{
  "method": "POST",
  "entry": "backend.js",
  "host_bridge": false,
  "permissions": ["exec.local"]
}
```

字段说明：

- `method`: 当前固定建议 `POST`
- `entry`: 后端脚本入口，相对模块目录
- `host_bridge`: 主要给 Python 模块使用，开启后可使用宿主桥接 helper
- `permissions`: 候选权限声明字段；当前文档化为治理模型，运行时尚未强制校验

### 6.1 候选权限模型

`permissions` 用于把 MISC 模块的本地执行、抓包读取和宿主桥接能力显式化。它是后续治理模型的兼容字段：旧模块没有该字段时仍按现有行为运行；新模块建议主动声明所需权限，便于后续 UI 提示、导入审查和运行时 gate 逐步落地。

候选权限如下：

| Permission | Meaning | Current Compatibility |
|---|---|---|
| `exec.local` | 允许运行模块脚本后端，即本地 `backend.js` 或 `backend.py`。 | 当前所有 zip 自定义模块隐含具备；未来可要求显式声明。 |
| `capture.read` | 允许读取当前抓包路径、抓包上下文摘要或使用抓包派生数据。 | 当前 `requires_capture` 和 `capture_path` 已表达部分语义；未来应与该权限合并校验。 |
| `field.scan` | 允许通过宿主能力扫描抓包字段，例如 JavaScript `ctx.scanFields()` 或 Python host bridge `scan_fields()`。 | 当前已开放给 JS ctx 和 Python `host_bridge`；未来可作为细粒度 gate。 |
| `host.bridge` | 允许 Python 模块启用宿主桥接 helper。 | 当前由 `host_bridge: true` 控制；未来可要求同时声明该权限。 |

兼容策略：

- `permissions` 缺失时，宿主按 v3 现有行为处理，不拒绝旧模块。
- `host_bridge: true` 等价于声明需要 `host.bridge`，但不自动表示未来所有 host 方法都可用。
- `requires_capture: true` 等价于声明需要 `capture.read`。
- 使用 `ctx.scanFields()` 或 `scan_fields()` 的模块应声明 `field.scan`。
- 未来如果运行时强制权限，应先增加导入/执行 warning，再切换到 hard fail，避免直接破坏已安装模块。
- `permissions` 不是沙箱；它只控制宿主是否暴露能力，不能隔离脚本自己的本地代码执行风险。

当前宿主统一执行地址始终为：

- `POST /api/tools/misc/packages/<module-id>/invoke`

注意：

- zip 模块不能自定义注册新的 HTTP 路由
- `api.json` 是声明式元信息，不是自由路由配置

## 7. `form.json`

负责声明统一卡片表单。

示例：

```json
{
  "description": "使用统一卡片模板渲染。",
  "submit_label": "运行模块",
  "result_title": "模块结果",
  "fields": [
    {
      "name": "keyword",
      "label": "Keyword",
      "type": "text",
      "default_value": "mimikatz",
      "placeholder": "请输入关键字",
      "help_text": "模块会用该关键字做检索"
    },
    {
      "name": "mode",
      "label": "模式",
      "type": "select",
      "default_value": "contains",
      "options": [
        { "label": "包含", "value": "contains" },
        { "label": "正则", "value": "regex" }
      ]
    },
    {
      "name": "payload",
      "label": "输入文本",
      "type": "textarea",
      "rows": 8
    }
  ]
}
```

当前宿主支持的字段类型：

- `text`
- `number`
- `textarea`
- `select`

密码输入的正确做法不是写 `type: "password"`，而是：

- `type: "text"`
- `secret: true`

字段说明：

- `name`: 提交字段名
- `label`: 页面显示名
- `type`: 字段类型
- `placeholder`: 占位文本
- `default_value`: 默认值
- `help_text`: 帮助文本
- `required`: 仅作为元数据保留
- `secret`: 是否按密码框渲染
- `rows`: `textarea` 行数
- `options`: `select` 的选项数组

## 8. `backend.js` / `backend.py`

真正的后端逻辑文件。当前只支持：

- `JavaScript`
- `Python`

不支持：

- `Go`
- `TSX`
- `Vue`
- `Svelte`
- 直接注册新的 HTTP 服务

## 9. JavaScript 模块约定

JavaScript 模块必须导出：

- `onRequest(input, ctx)`

示例：

```javascript
export function onRequest(input, ctx) {
  const keyword = String(input.values.keyword || "");
  const capturePath = String(input.capture_path || "");
  const scan = capturePath ? ctx.scanFields(["frame.number", "http.host"], "http") : { rows: [] };

  return {
    message: "IOC 模块执行完成",
    text: `keyword=${keyword}; capture=${capturePath}; host=${scan.rows[0]?.["http.host"] || ""}`,
    table: {
      columns: [
        { key: "field", label: "Field" },
        { key: "value", label: "Value" }
      ],
      rows: [
        { field: "keyword", value: keyword },
        { field: "host", value: String(scan.rows[0]?.["http.host"] || "") }
      ]
    },
    output: {
      matched: keyword.length > 0
    }
  };
}
```

`input` 当前包含：

- `values`: 表单提交值
- `capture_path`: 当前抓包路径，没有则为空
- `tshark_path`: 当前 `tshark` 路径
- `python_path`: 当前 Python 路径
- `host_context`: 宿主上下文摘要
- `module.id`
- `module.title`
- `module.api_prefix`

`ctx` 当前包含：

- `ctx.moduleDir`: 模块目录
- `ctx.readText(relPath)`: 读取模块目录内文本文件
- `ctx.capturePath`: 当前抓包路径
- `ctx.tsharkPath`: 当前 `tshark` 路径
- `ctx.scanFields(fields, displayFilter?)`: 使用宿主 `tshark` 扫描当前抓包字段

环境变量边界：

- JavaScript 模块运行在 Go 进程内的 Goja VM，不是 Node.js 运行时。
- JavaScript 模块没有 `process.env`，也不会获得完整系统环境变量快照。
- 本轮不向 JavaScript 模块开放完整环境变量，避免把本机 token、代理、路径等敏感信息扩散到自定义脚本执行面。
- 如果后续确实需要让 JavaScript 模块读取少量环境变量，应设计为受限宿主 API，例如 `ctx.env(name)`，并只允许 `GSHARK_MISC_` 前缀或 `manifest.json` 显式声明的白名单项。

JavaScript 模块有执行超时保护，可中断模块内的 JS 死循环和长时间计算。该保护不是完整 sandbox，也不保证强制中断正在执行的 Go 宿主回调；例如 `ctx.scanFields()` 进入宿主 `tshark` 扫描后，需要宿主 API 自身支持取消才能立即停止。编写模块时应避免长时间阻塞 host API，并把重型能力升级为内置模块。

`ctx.scanFields()` 返回结构：

```json
{
  "fields": ["frame.number", "http.host"],
  "display_filter": "http",
  "rows": [
    {
      "frame.number": "12",
      "http.host": "example.com"
    }
  ]
}
```

## 10. Python 模块约定

### 10.1 普通模式

未开启 `host_bridge` 时，Python 模块通过标准输入读取一份 JSON，请向标准输出写一份 JSON。

示例：

```python
import json
import sys

payload = json.load(sys.stdin)
keyword = str(payload.get("values", {}).get("keyword", ""))
capture_path = str(payload.get("capture_path", ""))
tshark_path = str(payload.get("tshark_path", ""))

sys.stdout.write(json.dumps({
    "message": "模块执行完成",
    "text": f"keyword={keyword}; capture={capture_path}; tshark={tshark_path}",
    "output": {
        "length": len(keyword)
    }
}, ensure_ascii=False))
```

普通模式下，Python 模块可直接拿到：

- `capture_path`
- `tshark_path`
- `python_path`
- `host_context`

Python 环境变量边界：

- Python 模块以独立本地进程运行，默认继承当前后端进程的 `os.Environ()`，因此可以通过 `os.environ` 读取后端进程可见的环境变量。
- 普通模式下宿主主要通过标准输入传入 JSON payload；不会额外设置 `GSHARK_MISC_INPUT_JSON`。
- `host_bridge: true` 模式会在继承环境的基础上追加 `GSHARK_MISC_INPUT_JSON`、`PYTHONIOENCODING=utf-8` 和包含临时 helper 目录的 `PYTHONPATH`。
- JavaScript 与 Python 的差异是有意设计：JavaScript 暂不暴露完整环境变量；Python 本身是本地进程执行面，导入前必须按可信脚本处理。

### 10.2 宿主桥接模式

如果在 `api.json` 中设置：

```json
{
  "method": "POST",
  "entry": "backend.py",
  "host_bridge": true
}
```

宿主会在运行前注入 helper 模块：

- `gshark_misc_host`

然后 Python 模块可以这样写：

```python
from gshark_misc_host import run, scan_fields

def on_request(payload):
    rows = []
    if payload.get("capture_path"):
        rows = scan_fields(["frame.number", "_ws.col.Protocol"]).get("rows", [])

    first = rows[0] if rows else {}
    return {
        "message": "模块执行完成",
        "table": {
            "columns": [
                {"key": "frame", "label": "Frame"},
                {"key": "protocol", "label": "Protocol"}
            ],
            "rows": [
                {
                    "frame": str(first.get("frame.number", "")),
                    "protocol": str(first.get("_ws.col.Protocol", ""))
                }
            ] if rows else []
        }
    }

if __name__ == "__main__":
    run(on_request)
```

桥接模式下，当前开放的宿主方法是：

- `scan_fields(fields, display_filter="")`

它会直接调用宿主已有的字段扫描能力，而不是让 Python 自己重新拼 `tshark` 命令。

## 11. 统一执行接口

zip 模块统一通过下面的宿主接口执行：

- `POST /api/tools/misc/packages/<module-id>/invoke`

请求体：

```json
{
  "values": {
    "keyword": "mimikatz"
  }
}
```

返回体：

```json
{
  "message": "模块执行完成",
  "text": "keyword=mimikatz",
  "table": {
    "columns": [
      { "key": "field", "label": "Field" },
      { "key": "value", "label": "Value" }
    ],
    "rows": [
      { "field": "matched", "value": "true" }
    ]
  },
  "output": {
    "matched": true
  }
}
```

字段说明：

- `message`: 状态消息
- `text`: 适合直接预览的文本
- `table`: 可选的统一表格结果，前端会自动渲染
- `output`: 可选的结构化 JSON，前端会格式化显示

## 12. 导入接口

当前已支持 zip 模块包导入：

- `POST /api/tools/misc/import`

请求格式：

- `multipart/form-data`
- 文件字段名固定为 `file`

返回示例：

```json
{
  "module": {
    "id": "ioc-demo",
    "kind": "custom",
    "title": "IOC Demo",
    "summary": "在文本中提取 IOC。",
    "tags": ["IOC", "Regex"],
    "api_prefix": "/api/tools/misc/packages/ioc-demo",
    "docs_path": "docs/misc-module-interface.md",
    "requires_capture": false
  },
  "installed_path": "%AppData%/gshark-sentinel/plugins/misc/ioc-demo",
  "message": "模块包导入成功"
}
```

## 13. 删除已安装模块

当前已支持删除已安装的 zip 自定义模块：

- `DELETE /api/tools/misc/packages/<module-id>`

说明：

- 只作用于已安装的 zip 自定义模块
- 不作用于内置模块
- 删除时会移除当前安装根目录下的 `<module-id>/` 目录，并从当前模块清单中消失

返回示例：

```json
{
  "id": "ioc-demo",
  "deleted": true
}
```

## 14. 为什么不允许模块自带卡片样式

这是当前设计中的强约束。

原因：

- `MISC` 区需要统一视觉语言
- 一旦放开自定义样式，维护成本和页面质量会迅速失控
- 单 `exe` 客户端不适合运行时动态注入任意前端源码和样式

所以当前策略是：

- 模块只定义表单结构
- 卡片布局、输入框、按钮、结果区和表格全部由宿主统一渲染

如果一个模块确实需要高度定制 UI，它就不应该走 zip 自定义模块路线，而应该升级成内置模块。

## 15. 什么时候应该写成内置模块

满足以下任一条件，建议直接写成内置模块：

- 需要复杂可视化，不只是表单 + 结果
- 需要多步骤交互、弹窗、预览器或复杂状态机
- 需要深度访问项目内 Go 服务
- 需要和主页面状态强耦合
- 需要专属页面样式或交互编排

## 16. 推荐开发流程

### 16.1 写 zip 自定义模块

适用于：

- 轻量 IOC 提取
- 特定文本解码
- 简单辅助脚本
- 快速验证一个想法

步骤：

1. 编写 `manifest.json`
2. 编写 `api.json`
3. 编写 `form.json`
4. 编写 `backend.js` 或 `backend.py`
5. 打包成 zip
6. 在 `MISC` 页点击“导入模块 ZIP”

### 16.2 用脚手架生成模块

当前项目已经提供脚手架：

- `scripts/new-misc-module.ps1`

JavaScript 示例：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\new-misc-module.ps1 -Id echo-demo -Title "Echo Demo" -Runtime javascript -Zip
```

Python 示例：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\new-misc-module.ps1 -Id py-scan-demo -Title "Python Scan Demo" -Runtime python -Zip
```

脚手架会自动生成：

- `manifest.json`
- `api.json`
- `form.json`
- `backend.js` 或 `backend.py`

如果传入 `-Zip`，还会直接打包出可导入 zip。

### 16.3 写内置模块

适用于：

- WinRM、SMB3 这类协议级能力
- 需要复杂前端状态
- 需要更高性能或更强耦合

入口：

- 后端：`backend/internal/transport/misc_modules.go`
- 前端：`frontend/src/app/misc/registry.tsx`

## 17. 最小可运行示例

当前仓库自带示例：

- `examples/misc-modules/echo-demo`

一个最小的 `manifest.json`：

```json
{
  "id": "echo-demo",
  "title": "Echo Demo",
  "summary": "把输入内容原样输出。",
  "tags": ["Demo"],
  "backend": "backend.js"
}
```

一个最小的 `api.json`：

```json
{
  "method": "POST",
  "entry": "backend.js",
  "host_bridge": false,
  "permissions": ["exec.local"]
}
```

一个最小的 `form.json`：

```json
{
  "submit_label": "运行 Echo",
  "fields": [
    {
      "name": "message",
      "label": "Message",
      "type": "textarea",
      "rows": 6
    }
  ]
}
```

一个最小的 `backend.js`：

```javascript
export function onRequest(input) {
  return {
    message: "Echo 完成",
    text: String(input.values.message || "")
  };
}
```

打包后即可导入使用。
