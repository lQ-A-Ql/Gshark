# meow~traffic 架构总览

meow~traffic（内部兼容名：sentinel）是基于 Wails、Go 后端和 React 前端的桌面端离线流量分析应用。本文是当前架构图谱入口，图中的模块名以仓库真实目录、文件和接口为准。整体模型、信任边界、扩展模型和门禁矩阵见 [项目整体模型](../project-model.md)。

## 1. 系统上下文

```mermaid
flowchart LR
    Analyst["分析员"] --> Wails["Wails 桌面壳\nmain.go / app.go"]
    Wails --> WebView["React WebView\nfrontend/src/app"]
    Wails --> DesktopBindings["typed Wails bindings\nDesktopApp"]
    DesktopBindings --> Runtime["backend/desktopruntime\nin-process handler"]
    Runtime --> Engine["backend engine.Service"]
    Runtime --> Hub["transport.Hub\nbackend events"]

    WebView --> BridgeFactory["bridgeFactory"]
    BridgeFactory --> DesktopBridge["desktopBridge\ntyped IPC only"]
    BridgeFactory --> HttpBridge["httpBridge\nbrowser-dev HTTP/SSE"]
    DesktopBridge --> DesktopBindings
    HttpBridge --> HTTPServer["transport.Server\n127.0.0.1:17891"]
    HTTPServer --> Engine

    Engine --> TShark["tshark\nPCAP 解析与流重组"]
    Engine --> YARA["YARA\n对象/流目标扫描"]
    Engine --> FFmpeg["FFmpeg\n媒体播放素材"]
    Engine --> PythonVosk["Python + Vosk\n语音转写"]
    Engine --> MiscRuntime["MISC JS/Python runtime\nzip 自定义模块"]
    HTTPServer --> MCP["MCP JSON-RPC\n/api/mcp"]
    Hub --> WailsEvents["Wails runtime events\nmeow:backend:*"]
```

关键约束：

- 桌面模式的数据面和控制面走 typed Wails IPC，缺 binding 时直接失败。
- 普通浏览器开发模式保留 HTTP REST 与 SSE。
- 两条传输路径最终都汇聚到同一个 `engine.Service`。
- 外部工具能力降级应被报告，不应阻塞应用启动主路径。

## 2. 后端分层

```mermaid
flowchart TD
    Entry["cmd/sentinel\nbackend/main.go"] --> Transport["transport\nHTTP/SSE/auth/audit"]

    Transport --> ServiceContract["servicecontract\n只读服务接口"]
    Transport --> Engine["engine\nService 核心编排"]
    Transport --> MCP["mcp\nJSON-RPC tools/resources/prompts"]
    Transport --> MiscRoutes["misc_modules.go\n内建与 packaged MISC 端点"]

    Engine --> Capture["capture lifecycle\nBeginCaptureLoad / LoadPCAPWithRun"]
    Engine --> PacketStore["packet_store.go\n分页、定位、过滤"]
    Engine --> Streams["service_streams.go\nHTTP/TCP/UDP 流"]
    Engine --> Analysis["service_analysis.go\n工控、车机、USB、媒体、C2、APT"]
    Engine --> Hunting["service_tools.go\nThreatHunt + YARA"]
    Engine --> Evidence["evidence.go\n统一证据聚合"]
    Engine --> Reports["analysis_report_*.go\n调查报告"]

    Capture --> TShark["tshark package\n子进程、字段探测、解析"]
    Streams --> TShark
    Analysis --> TShark
    Hunting --> YaraBatch["yara_batch.go / yara_stream_targets.go"]
    Evidence --> Model["model\n共享 JSON DTO"]
    Reports --> ReportRules["report\n规则元数据"]
    MiscRoutes --> MiscPkg["miscpkg\nmodule loader + JS/Python runtime"]
    Transport --> Governance["governance\n缺陷登记、自审、报告渲染"]
```

后端维护规则：

- HTTP 路由注册权威来源是 `backend/internal/transport/http_server.go` 和 `misc_modules.go`。
- 新 HTTP handler 必须使用 `WithContext` 变体和 `r.Context()`。
- 领域分析留在 `engine`；外部解析和字段兼容留在 `tshark`；传输、鉴权、审计留在 `transport`。

## 3. 前端数据面

```mermaid
flowchart LR
    Pages["pages\n路由级页面"] --> Features["features\n领域 hooks 与面板逻辑"]
    Features --> Clients["backendClients\nbridgeDomains"]
    Pages --> State["state\nCapture/Packet/Stream/Tool"]
    State --> Clients

    Clients --> Bridge["bridgeFactory"]
    Bridge --> Desktop["desktopBridge"]
    Bridge --> HTTP["httpBridge"]

    Desktop --> Typed["desktopTypedBridge*.ts"]
    Typed --> Requirements["desktopTypedBridgeRequirements.ts"]
    Requirements --> WailsDTS["DesktopApp.d.ts"]
    Typed --> Wire["wire DTO"]

    HTTP --> Fetch["fetch + EventSource"]
    Fetch --> Wire

    Wire --> Mappers["integrations/mappers"]
    Mappers --> CoreTypes["core/types"]
    CoreTypes --> Features
```

前端维护规则：

- pages/features 不直接调用后端 `fetch`，而是通过 bridge/client。
- wire DTO 表示后端 JSON；mapper 负责归一化；`core/types` 是功能层消费的稳定类型。
- 已迁移桌面数据面缺少 typed binding 时，应以 `generic_ipc_disabled` 失败，不静默回退 HTTP。

## 4. Capture 生命周期

```mermaid
sequenceDiagram
    participant User as 分析员
    participant FE as 前端 Workspace
    participant Bridge as bridgeFactory
    participant BE as transport.Server
    participant SVC as engine.Service
    participant TS as tshark
    participant Store as packet_store
    participant Events as SSE/Wails events

    User->>FE: 选择 PCAP/PCAPNG
    FE->>Bridge: upload/start capture
    Bridge->>BE: /api/capture/upload 或 typed binding
    BE->>SVC: BeginCaptureLoad(ctx)
    SVC->>SVC: 注册 capture task scope
    SVC->>TS: LoadPCAPWithRun(runCtx, opts, runID)
    TS-->>SVC: packet rows / fields
    SVC->>Store: 写入分页索引与首屏数据
    SVC->>Events: ready/status/packet/error
    Events-->>FE: SSE 或 Wails runtime event
    FE->>Bridge: 请求 packet page / stream / analysis
    Bridge->>SVC: typed IPC 或 HTTP handler

    User->>FE: 替换或关闭抓包
    FE->>Bridge: prepareForCaptureReplacement
    Bridge->>BE: /api/capture/prepare-replacement 或 typed binding
    BE->>SVC: PrepareCaptureReplacement()
    SVC->>SVC: 取消 capture task scope
    SVC->>Store: 清理旧 capture 相关缓存
```

取消链路要求：

- HTTP handler 使用 `r.Context()`。
- 媒体播放、语音转写、YARA、专项分析等长任务必须尊重 context。
- 前端使用 capture task scope 和 abortable request 避免旧抓包结果回写新页面状态。

## 5. Evidence 聚合模型

```mermaid
flowchart TD
    Packets["Packet Store"] --> Hunting["Threat Hunting\nThreatHit"]
    Streams["Reassembled Streams"] --> C2["C2 Analysis / Decrypt"]
    Streams --> WebShell["WebShell Payload Inspector"]
    Packets --> Industrial["Industrial Analysis"]
    Packets --> Vehicle["Vehicle Analysis"]
    Packets --> USB["USB Analysis"]
    Objects["Extracted Objects"] --> ObjectEvidence["Object Evidence"]
    Objects --> YARA["YARA Hits"]
    Media["Media Artifacts"] --> MediaEvidence["Media / Speech Evidence"]
    Hunting --> APT["APT Analysis"]
    C2 --> APT

    Hunting --> Gather["engine.GatherEvidence"]
    C2 --> Gather
    WebShell --> Gather
    Industrial --> Gather
    Vehicle --> Gather
    USB --> Gather
    ObjectEvidence --> Gather
    YARA --> Gather
    MediaEvidence --> Gather
    APT --> Gather

    Gather --> Unified["UnifiedEvidenceRecord\nmodule / severity / confidence / context"]
    Unified --> Frontend["Evidence feature\nfilter / sort / detail / export"]
    Unified --> Report["Investigation Report"]
```

证据记录应尽量保留 `packet_id`、`stream_id`、来源模块、严重性、置信度、tags、metadata 和 caveats。无法追溯上下文的记录必须显式说明 caveat。

## 6. C2 检测与解密流程

```mermaid
flowchart TD
    Capture["已加载抓包"] --> Stats["Global traffic stats\n会话、域名、端点"]
    Capture --> Streams["HTTP/TCP/UDP streams"]
    Capture --> DNS["DNS / Host / URI 聚合"]
    Streams --> Indicators["C2 indicators\nbeacon、端点、UA、方向"]
    DNS --> Indicators
    Stats --> Indicators
    Indicators --> Family["家族/画像评分\nVShell、CS、Winos/HFS 等"]
    Family --> C2Result["C2SampleAnalysis"]

    Streams --> DecryptReq["C2DecryptRequest\nfamily + key/material"]
    DecryptReq --> VShell["VShell 3-KDF\nmd5(salt)、md5(salt+vkey)、md5(saltPad32+vkey)"]
    DecryptReq --> CS["Cobalt Strike keyed workbench"]
    DecryptReq --> Raw["raw-stream candidates"]
    VShell --> DecryptResult["C2DecryptResult"]
    CS --> DecryptResult
    Raw --> DecryptResult
    C2Result --> Evidence["C2 evidence"]
    DecryptResult --> Evidence
```

## 7. WebShell Payload 分析流程

```mermaid
flowchart TD
    HTTPPackets["HTTP packets"] --> SourceScan["stream_payload_sources.go\n可疑 URI、参数、重复 burst"]
    Streams["Reassembled streams"] --> SourceScan
    SourceScan --> Candidates["StreamPayloadSource\npayload、confidence、signals"]
    Candidates --> Decode["stream_decoder.go\nbase64 / Behinder / AntSword / Godzilla / auto"]
    Decode --> Inspect["stream_payload_inspector.go\n命令执行、编码层级、失败阶段"]
    Inspect --> Result["StreamPayloadInspection\nconfidence + decoded preview"]
    Result --> Evidence["WebShell / payload evidence"]
```

## 8. YARA 扫描目标流程

```mermaid
flowchart TD
    Objects["Extracted ObjectFile"] --> Targets["buildYaraScanTargetsWithContext"]
    Streams["HTTP/TCP/UDP stream context"] --> Targets
    Targets --> TempFiles["临时扫描目标\n对象 + 重组流"]
    Config["YaraConfig\nbin、rules、timeout"] --> Preflight["preflightYaraScanConfig"]
    Preflight --> Scan["BatchScanTargetsWithYaraConfigContext"]
    TempFiles --> Scan
    Scan --> Hits["ThreatHit\ncategory=YARA"]
    Scan --> Warning["YARA warning hit\n配置/执行异常"]
    Hits --> Cache["yaraHits cache"]
    Warning --> Cache
```

## 9. 专项协议分析流程

```mermaid
flowchart TD
    Capture["PCAP/PCAPNG"] --> TSharkFields["tshark 字段扫描与兼容降级"]
    TSharkFields --> Industrial["工控\nModbus / S7 / DNP3 / CIP / IEC104"]
    TSharkFields --> Vehicle["车机\nCAN / J1939 / DoIP / UDS / OBD-II"]
    TSharkFields --> USB["USB\nHID / Mass Storage / Control"]
    TSharkFields --> Media["媒体\nRTP/RTSP/媒体对象"]

    Industrial --> IndustrialUI["IndustrialAnalysis 页面"]
    Vehicle --> DBC["DBC profile\nBO_ / SG_ 信号解码"]
    DBC --> VehicleUI["VehicleAnalysis 页面"]
    USB --> USBUI["UsbAnalysis 页面"]
    Media --> FFmpeg["FFmpeg 播放素材"]
    Media --> Speech["Python/Vosk 转写"]
    FFmpeg --> MediaUI["MediaAnalysis 页面"]
    Speech --> MediaUI

    Industrial --> Evidence["Unified evidence"]
    Vehicle --> Evidence
    USB --> Evidence
    Media --> Evidence
```

## 10. MISC 模块执行流程

```mermaid
flowchart TD
    Catalog["/api/tools/misc/modules\n内建 + packaged manifest"] --> Workbench["MiscModuleWorkbench"]
    Zip["zip package\nmanifest.json + api.json + form.json + backend.js/.py"] --> Import["/api/tools/misc/import"]
    Import --> Manager["miscpkg.Manager\nLoadFromDir"]
    Manager --> Catalog
    Workbench --> Invoke["/api/tools/misc/packages/{id}/invoke\n或 typed binding"]
    Invoke --> Loader["module_loader.go"]
    Loader --> JS["runtime_javascript.go"]
    Loader --> PY["runtime_python.go"]
    JS --> Result["MiscModuleRunResult\nmessage / text / output / table"]
    PY --> Result
    Result --> Export["JSON / TXT / table export"]
```

MISC 适合低频、高价值、强场景化辅助工具。稳定威胁狩猎能力优先使用 Go 内建检测、YARA 或 playbook；可执行 JS/Python 工具优先使用 MISC zip 模块。
