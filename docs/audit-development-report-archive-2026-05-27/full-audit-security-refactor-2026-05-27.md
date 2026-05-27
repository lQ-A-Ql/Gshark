# Full Audit: Security Hardening & Structural Refactor — 2026-05-27

Author: OpenCode

Timestamp: 2026-05-27 19:47:00 +08:00

## 1. Background

meow~traffic 后端经过多轮功能迭代后，积累了安全风险、代码重复和结构膨胀问题。本次审计使用 4 个 cavecrew 子代理对项目进行全量扫描，覆盖安全、代码质量、架构三个维度，并分 Phase 执行修复。

## 2. 审计发现与修复状态

### 2.1 Phase 1: 安全加固 (Security Hardening)

| # | 发现 | 严重度 | 修复方案 | 状态 |
|---|------|--------|----------|------|
| 1.1 | URL query `access_token` 认证 | CRIT | 移除 query param，仅保留 Authorization header | ✅ |
| 1.2 | 无请求体大小限制 (15+ 处 `json.NewDecoder`) | CRIT | 新增 `decodeJSONBody` helper (1MB 限制)，替换 21 处调用 | ✅ |
| 1.3 | 缺少安全响应头 | HIGH | 添加 `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` | ✅ |
| 1.4 | 错误信息泄露内部路径 | HIGH | 新增 `sanitizeErrorMessage`，移除 `executable_path`/`working_dir` | ✅ |
| 1.5 | 对象下载无数量限制 | HIGH | 添加 100 个对象限制 + 256MB/文件 `io.Copy` 限制 | ✅ |
| 1.6 | SSE 事件注入 (event type 含换行符) | MED | `safeType` 过滤 `\n`/`\r` | ✅ |

**关键变更文件**: `backend/internal/transport/http_server.go`, `http_capture.go`, `http_tools.go`, `http_packet_stream.go`, `misc_package_handlers.go`

### 2.2 Phase 2: 结构重构 (Structural Refactor)

| # | 发现 | 修复方案 | 状态 |
|---|------|----------|------|
| 2.1 | `service.go` 2922 行 God file | 拆分为 5 文件: `service.go`(191), `service_capture.go`(830), `service_streams.go`(470), `service_analysis.go`(858), `service_tools.go`(627) | ✅ |
| 2.2 | 分析缓存模式重复 (6 处) | 提取 `cachedAnalysis[T]` 泛型 helper，重写 GlobalTrafficStats/Industrial/Vehicle | ✅ |
| 2.3 | 流解析回调重复 (3 处) | 提取 `streamParseState` + `makeStreamCallbacks` 方法 | ✅ |
| 2.4 | 状态重置逻辑重复 (2 处) | 提取 `resetAnalysisCachesLocked()`，`commitLoadedCapture` 和 `resetCaptureAnalysisStateLocked` 共用 | ✅ |
| 2.5 | `types.go` 1691 行类型膨胀 | 拆分为 12 个领域文件 | ✅ |

**types.go 拆分方案**:

| 新文件 | 领域 |
|--------|------|
| `types_packet.go` | 数据包、流、流量桶 |
| `types_capture.go` | 抓包生命周期状态 |
| `types_c2.go` | C2 指标、解密 |
| `types_apt.go` | APT 组织画像 |
| `types_industrial.go` | 工控协议 (Modbus 等) |
| `types_vehicle.go` | 车辆协议 (CAN/UDS/DoIP) |
| `types_media.go` | 媒体分析、语音转写 |
| `types_usb.go` | USB HID/存储分析 |
| `types_tools.go` | 工具运行时配置 |
| `types_plugins.go` | 插件、MISC 模块 |
| `types_protocols.go` | 协议分析 (HTTP/SMTP/MySQL/Shiro) |
| `types_evidence.go` | 证据记录 |

### 2.3 Phase 3: 代码质量 (Code Quality)

| # | 发现 | 修复方案 | 状态 |
|---|------|----------|------|
| 3.1 | `NewService` 中 `panic(err)` | 替换为 `log.Fatalf` | ✅ |
| 3.2 | `pluginManger` 拼写错误 (18 处) | 全局替换为 `pluginManager` | ✅ |
| 3.3 | `handleMediaBatchTranscription` 静默吞错 | 使用 `decodeJSONBody` 正确处理错误 | ✅ |

### 2.4 额外修复 (审计过程中发现)

| 发现 | 修复方案 | 状态 |
|------|----------|------|
| 桌面端 `checkTShark`/`checkFFmpeg`/`checkSpeechToText` 走已禁用的 generic IPC | 改为通过 `getToolRuntimeSnapshot` 获取 (已有 typed IPC + HTTP fallback) | ✅ |
| 桌面端后端子进程弹出终端窗口 | 添加 `hideChildProcessWindow` 平台特定 helper (`SysProcAttr.HideWindow`) | ✅ |

## 3. 关键设计决策

### 3.1 `cachedAnalysis` 泛型 helper

```go
type analysisCacheInput[T any] struct {
    getCached func() *T
    setCached func(*T)
    builder   func(pcap string) (T, error)
}

func cachedAnalysis[T any](ctx context.Context, mu *sync.RWMutex, pcap string, input analysisCacheInput[T]) (T, error)
```

**决策**: 使用 Go 1.18+ 泛型而非 `any` 类型，保持类型安全。仅适用于 GlobalTrafficStats/Industrial/Vehicle 三个模式最接近的方法；C2/APT/USB/Media 因模式差异太大保留原有实现。

### 3.2 `decodeJSONBody` 统一请求体限制

```go
const maxJSONBody = 1 << 20 // 1MB

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
    r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
    return json.NewDecoder(r.Body).Decode(dst)
}
```

**决策**: 1MB 限制适用于所有 JSON API 端点。`MaxBytesReader` 放在 helper 内部确保一致性。特殊场景 (如文件上传) 已有独立的 100MB 限制。

### 3.3 桌面端 IPC fallback 链路

```
checkFFmpeg()
  → getToolRuntimeSnapshot()
    → typed IPC: DesktopApp.GetToolRuntimeSnapshot (如有)
    → fallback: fallbackBridge.getToolRuntimeSnapshot() (HTTP)
  → snapshot.ffmpeg
```

**决策**: 不为 `checkFFmpeg`/`checkTShark`/`checkSpeechToText` 创建独立的 typed binding，因为它们的数据已包含在 `GetToolRuntimeSnapshot` 响应中。

## 4. 变更统计

| Commit | 描述 | 文件数 | 行数变化 |
|--------|------|--------|----------|
| `986381bb` | Security hardening + service.go refactor | 12 | +2866 / -2781 |
| `68ef1a81` | Desktop IPC check methods fix | 1 | +66 / -48 |
| `201364da` | Hide backend child process window | 3 | +24 |
| `a7899b63` | Phase 2 structural refactoring | 15 | +1861 / -1916 |

**总计**: 31 文件变更，+4817 / -4745 行

## 5. 验证矩阵

| 检查项 | 结果 |
|--------|------|
| `go build ./...` (backend) | ✅ |
| `go test ./...` (backend, 8 packages) | ✅ |
| `gofmt -l .` (backend) | ✅ 无格式问题 |
| `go build -tags dev ./...` (root) | ✅ |
| `go test -tags dev ./...` (root) | ✅ |
| `pnpm run typecheck` (frontend) | ✅ |
| `pnpm run lint` (frontend) | ✅ |
| `pnpm run test:run` (frontend) | ✅ |

## 6. 遗留项与后续建议

### 6.1 已知不修复项

| 项 | 原因 |
|----|------|
| `miscpkg/manager.go` 中 `panic(vm.NewGoError(...))` | goja VM 的正确异常抛出方式，非 Go panic |
| `mediaAnalysisWithForce` 未迁移到 `cachedAnalysis` | force 标记 + 临时目录 + 进度回调模式差异太大 |
| `C2SampleAnalysis`/`APTAnalysis` 未迁移到 `cachedAnalysis` | 无 pcap 前置检查，从其他模块构建 |

### 6.2 后续建议

1. **API contract snapshot tests**: 在 transport 层添加端点响应快照测试，防止 JSON 形状意外变更
2. **Service 拆分**: `Service` struct 仍有 20+ 字段，可考虑按领域拆分为子结构体
3. **Context 传播强制检查**: 在 architecture boundary tests 中添加 `WithContext` 调用检查
4. **前端测试覆盖**: 当前 0.33，建议补充核心 hooks 和 integrations 测试

## 7. 关联文档

- `docs/backend-engineering-audit-spec-2026-05-14.md` — 前次后端工程审计
- `docs/frontend-engineering-audit-spec-2026-05-15.md` — 前次前端工程审计
- `docs/governance-defect-register.json` — 治理缺陷登记
- `AGENTS.md` — 项目构建与测试约定
