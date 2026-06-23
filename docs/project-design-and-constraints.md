# meow~traffic 设计与工程约束

本文记录当前桌面应用、后端服务、前端传输层和扩展面的工程约束。当代码上下文不足以判断设计取舍时，以本文为默认约束依据。

## 产品边界

meow~traffic 是桌面优先的离线流量分析工作台，面向安全分析师、CTF 选手、应急响应、协议研究、工控/车机流量分析和危险应用研判。后端以 `tshark` 为解析核心，并叠加专项分析、证据聚合、媒体处理、YARA 和 MISC 模块能力。

以下兼容名暂不迁移：

- Go module 仍使用 `github.com/gshark/sentinel/...`。
- 内部目录、事件和缓存路径可能仍使用 `meow-traffic` 或 `sentinel`。
- 历史发布资产或归档中可能出现 `sentinel-backend.exe`，但当前 Wails 桌面构建产物不再嵌入或启动该后端二进制。
- 环境变量仍使用 `MEOW_TRAFFIC_*`。

除非迁移方案覆盖代码、文档、发布资产、用户数据和回滚路径，否则不要直接改名。

## 后端边界

后端 HTTP 使用 `net/http.ServeMux`，路由注册在 `backend/internal/transport/http_server.go`。不要按 chi/gin/echo 的模式设计 handler。

分层约束：

```mermaid
flowchart LR
    Transport["transport\nHTTP、SSE、鉴权、审计"] --> Contract["servicecontract\n只读接口"]
    Transport --> Engine["engine\nService 编排"]
    Engine --> TShark["tshark\n子进程与解析"]
    Engine --> Model["model\n共享 DTO"]
    Engine --> MiscPkg["miscpkg\nzip 模块运行时"]
    Engine --> Report["report\n调查报告规则"]
    Transport --> MCP["mcp\nJSON-RPC tools"]
    Transport --> Governance["governance\n缺陷登记与报告"]
```

约束：

- 新 HTTP handler 必须把 `r.Context()` 传给 `WithContext` 服务方法。
- `context.Background()` 包装方法只为桌面同步 binding 兼容保留，不要在 HTTP handler 中使用。
- 长任务必须能被请求取消、抓包替换或关闭流程中断。
- 传输层逻辑留在 `transport`；tshark 子进程逻辑留在 `tshark`；领域分析逻辑留在 `engine`。
- `engine` 根包新增生产文件必须登记领域归属；新增超过大文件阈值的根包文件必须拆分或显式进入 grandfather 例外清单。
- `engine` 纯逻辑子包不得反向依赖根 `engine`、`transport`、`tshark`、HTTP 或外部进程执行能力；当前 WebShell payload inspection 已下沉到 `engine/payloadinspect`。
- `engine.Service` 是 transport/Wails 的稳定门面，但内部状态必须通过显式 controller 字段组合；controller 只拥有自己的 state group，不跨 controller 持锁调用。
- YARA 等长任务必须使用真实 goroutine/命令完成信号，不得把 request/capture cancel channel 当作成功完成信号；底层错误应保留 `%w` cause，用户中文提示在 transport/mapper/display 层处理。
- Go 只使用 `gofmt` 格式化。

正确 HTTP handler 模式：

```go
result, err := s.analysis.VehicleAnalysisWithContext(r.Context())
```

错误模式：

```go
result, err := s.analysis.VehicleAnalysis()
```

## 前端边界

前端数据面通过 bridge 抽象传输：

```mermaid
flowchart LR
    UI["pages/features/hooks"] --> BridgeFactory["bridgeFactory"]
    BridgeFactory --> Desktop["desktopBridge"]
    BridgeFactory --> HTTP["httpBridge"]
    Desktop --> Typed["desktopTypedBridge*"]
    Typed --> Wails["Wails typed binding"]
    HTTP --> Fetch["fetch + EventSource"]
    Typed --> Wire["wire DTO"]
    Fetch --> Wire
    Wire --> Mapper["mappers"]
    Mapper --> Types["core/types"]
```

约束：

- 桌面数据面调用必须优先走明确的 typed Wails binding。
- 已迁移的桌面数据面缺少 typed binding 时，应以 `typed_binding_required` 失败，不允许静默回退到浏览器 HTTP。
- 普通 browser-dev 模式继续使用 HTTP REST 和 SSE。
- Wails 桌面构建产物不得让 WebView 直接请求 `127.0.0.1:17891`；HTTP/SSE 只保留给 browser-dev/CLI。
- wire DTO 表示后端 JSON；mapper 负责归一化到 `core/types`；feature hooks 和 pages 只消费归一化类型。
- 避免在 pages/features 中直接 `fetch` 后端；应新增 bridge/client 方法。
- 分析 hook 应使用公共 cache/guard 语义：同 key inflight 去重、force refresh 绕过缓存、capture revision/filePath/totalPackets 变化刷新、空样本或无可用路径时不发 IPC/HTTP 请求。
- core enum 需要兼容未知后端值时使用 `KnownOrUnknown<T>` 或领域等价类型，不直接新增开放 `| string`；wire DTO 需要宽动态结构时必须登记到 type governance 例外。
- 前端包管理保持 `pnpm`，保留 `frontend/pnpm-lock.yaml`。
- Vite 配置不得把 `.css`、`.tsx`、`.ts` 加入 `assetsInclude`。

## API 与 IPC 契约

HTTP route 权威来源：

- `backend/internal/transport/http_server.go`
- `backend/internal/transport/misc_modules.go`
- `docs/api/openapi.yaml`

桌面 IPC 权威来源：

- `app.go`
- `frontend/wailsjs/go/main/DesktopApp.d.ts`
- `frontend/src/app/integrations/desktopTypedBridgeRequirements.ts`
- `frontend/src/app/integrations/desktopTypedBridge*.ts`

维护要求：

- 每个新增 HTTP route 都要同步 OpenAPI。
- 每个新增 typed 桌面数据面 binding 都要进入前端 bridge requirements。
- 每个新增桌面控制面 IPC binding 都要进入 `frontend/scripts/check-wails-bindings.mjs` 对应分组；Wails 绑定生成失败不得手工绕过。
- 每个供前端消费的新后端 JSON shape 都应有 wire DTO 和 mapper；MISC 动态输出等明确动态结构除外。

## 证据模型

证据是跨模块调查主契约。后端聚合入口是 `backend/internal/engine/evidence.go`；前端展示使用 `frontend/src/app/core/types/evidence.ts` 中的 `UnifiedEvidenceRecord` 以及 evidence feature 的 re-export。

产出证据的模块应保留：

- `module` 或 `source_module`
- `severity`
- `confidence`
- 可用时保留 `packet_id` 和/或 `stream_id`
- 足以让分析员解释结论的 `metadata`、`tags` 和 `caveats`

不要新增无法追溯到包、流、对象、模块或明确 caveat 的证据记录。

## 安全与运行时约束

- standalone 后端 API 在设置或自动生成 `MEOW_TRAFFIC_BACKEND_TOKEN` 后使用 bearer token。
- `/health`、`/api/events`、`/api/audit/logs` 在 middleware 中有特殊鉴权处理；修改暴露面前先检查 `http_middleware.go`。
- 桌面事件应从进程内 `transport.Hub` 订阅并通过 Wails runtime events 桥接，不要让 WebView 页面直连 `/api/events`。
- 桌面 blob 响应有大小上限，避免 WebView 内存尖峰。
- zip MISC 模块通过受控 JavaScript/Python 运行时执行，不要把任意压缩包内容视为可信。
- 外部工具（`tshark`、FFmpeg、Python、Vosk、YARA）必须清晰报告降级状态，不能阻塞应用启动主路径。

## CI 与格式约束

后端 CI：

- `gofmt -l .`
- 后端架构边界测试
- 证据/报告/公开样本/governance 聚焦测试
- feature gap remediation 聚焦测试
- `go test ./...`

前端 CI：

- Corepack + `pnpm@10.31.0`
- `pnpm install --frozen-lockfile`
- `pnpm run ci:quality`
- `pnpm run ci:boundaries`
- `pnpm run ci:desktop`
- `pnpm run ci:test-build`
- `pnpm run ci` 仍保留为本地全量聚合命令，顺序调用以上四组。
- `pnpm run type-governance:check` 属于 `ci:boundaries`，用于阻止新增裸 `as any`、开放核心 `| string` union 和未登记宽 wire DTO。

仓库门禁：

- `.gitignore` 覆盖的本地产物不得继续被 Git 跟踪；本地与 CI 通过 ignored tracked files check 拦截。

桌面 CI：

- `pnpm run build:wails`
- 桌面资源检查
- 根模块 `dev` 和 `production` tag 测试

具体本地命令见 [项目开发指南](./project-development-guide.md)。
