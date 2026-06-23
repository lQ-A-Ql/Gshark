# 项目安全与质量复查报告

**复查日期**：2026-06-21
**复查范围**：`backend/internal/engine`、`backend/internal/transport`、`backend/internal/tshark`、`backend/internal/miscpkg`、`frontend/src` 关键路径
**复查方式**：多模块并行深度审计（通读关键文件 + 关键路径跟踪）
**测试基线**：
- `cd backend && go test ./...` ✅
- `cd backend && go test -race ./internal/engine/...` ✅
- `cd frontend && pnpm run ci` ✅
- `./scripts/check-all.ps1` ✅

---

## 1. 总体结论

V0 安全修复阶段（R1–R6）整体上已落地并通过全量 CI，项目基线健康。但本轮复查发现若干**高风险缺口**需要立即修复，主要集中在：

1. **MISC 模块签名验证覆盖不完整**：导入阶段已验签，但加载已安装模块时未验签，存在生产环境绕过风险。
2. **EventSource URL 传递鉴权 token**：违反 `AGENTS.md` 安全规则，存在日志/历史/referrer 泄露风险。
3. **tshark 二进制路径未实际接入白名单校验**：`engine/tool_runtime_validator.go` 已存在，但 `applyConfig` / `SetBinaryPath` 未调用。
4. **路径穿越校验仍依赖 `strings.Contains("..")`**：capture 启动、Vehicle DBC、媒体/对象导出等场景未做 base-dir 校验。
5. **Context 取消未真正下沉到所有子进程**：`DetectLikelyRTPPorts`、能力探测、多个遗留 builder 仍使用 `context.Background()`。

**整体评级**：功能正常，但在上述 critical/high 项修复前不建议发布 release。

---

## 2. Critical 级别问题（立即修复）

| # | 模块 | 文件路径 | 问题描述 | 建议修复 |
|---|------|---------|---------|---------|
| 1 | miscpkg | `backend/internal/miscpkg/manager.go` | `LoadFromDir` 加载磁盘上已安装的 MISC 模块时**不验证签名**。攻击者只要具备模块安装目录写权限，即可在生产构建中植入/篡改模块并绕过签名要求。 | 在 `loadModuleFromDir` 阶段重新校验模块目录的签名文件；签名应覆盖 manifest、api、form、backend 等全部文件。 |
| 2 | transport | `backend/internal/transport/misc_package_handlers.go:33` | `handleImportMiscModulePackage` 通过 `io.ReadAll(file)` 把整个上传 zip 读入内存，之后才交给 `ImportZipBytes`。`ParseMultipartForm(32MB)` 只限制内存，未限制文件流大小，可触发 OOM。 | 改为流式读取并限制总大小（如 32MB）；或在 `miscpkg` 提供 `ImportZip(io.Reader, sizeLimit)` 接口。 |
| 3 | frontend | `frontend/src/app/integrations/clients/eventClient.ts:33` | `EventSource` URL 直接拼接 `access_token=${token}`。URL 中的 token 会进入浏览器历史、服务端 access log、referrer，违反安全规则。 | 后端 `/api/events` 支持 `Authorization: Bearer <token>` header；前端使用 `eventSourceInitDict.headers` 传入。 |
| 4 | tshark | `backend/internal/tshark/config.go` / `backend/internal/engine/tool_runtime.go` | `SetBinaryPath` 仅 `strings.TrimSpace` 后直接写入全局变量，未调用 `engine.ValidateExecutablePath`。`applyConfig` 直接调用 `tshark.SetBinaryPath(...)`，未接入白名单。 | 在 `applyConfig` 或 `SetBinaryPath` 中调用 `ValidateExecutablePath(path, []string{"tshark"}, ...)`，拒绝非法路径。 |

---

## 3. High 级别问题（本周内修复）

| # | 模块 | 文件路径 | 问题描述 | 建议修复 |
|---|------|---------|---------|---------|
| 5 | engine | `backend/internal/transport/http_analysis_handlers.go:26-43` | `handleHuntingConfig` POST 直接调用 `SetHuntingRuntimeConfig(cfg)`，未对 `YaraBin` / `YaraRules` 执行白名单/目录校验。 | 在 handler 中调用 `engine.ValidateExecutablePath(cfg.YaraBin, []string{"yara","yara64"})`；对 `YaraRules` 做 base-dir 校验。 |
| 6 | engine | `backend/internal/transport/http_capture.go:28-79` | `handleCaptureStart` 仅通过 `strings.Contains(path, "..")` 校验用户传入的 `FilePath`，未做 base-dir 限定。 | 统一使用 base-dir 校验；限制 `FilePath` 必须为上传注册表或 `%TEMP%/meow-traffic/*` 下的文件。 |
| 7 | engine | `backend/internal/transport/http_analysis_handlers.go:250-286` 等 | Vehicle DBC 增删接口仅检查 `..`，engine 直接 `os.Open(path)` / `LoadDBCDatabase(path)`，存在目录穿越与任意文件读取。 | 在 transport 层对 DBC 路径做 base-dir 校验；engine 层增加二次校验；拒绝相对路径与跨目录路径。 |
| 8 | engine | `backend/internal/engine/rule_manager.go:479-497` | `fetchManifest` 直接 `rm.client.Get(baseURL + "/manifest.json")`，未校验 `RemoteURL` scheme，可导致 SSRF。 | 校验 `parsed.Scheme == "http" || parsed.Scheme == "https"`；必要时加 IP / 主机白名单。 |
| 9 | tshark | `backend/internal/tshark/runner.go:440` / `media_analysis.go:1284` | `ExportObjectsContext` 与 `buildMediaArtifact` 缺少路径 base-dir 校验；媒体导出无大小/数量上限。 | 对 `pcapPath`/`exportDir` 做 base-dir 校验；限制单会话 artifact 大小与包数上限。 |
| 10 | tshark | `backend/internal/tshark/media_analysis.go:617` | `DetectLikelyRTPPorts` 使用 `context.Background()`，无法被取消，是 MediaAnalysis context 链中的断点。 | 新增 `DetectLikelyRTPPortsContext` 并迁移 engine 调用点。 |
| 11 | miscpkg | `backend/internal/miscpkg/runtime_python.go` | Python 模块以独立子进程运行，但**完整继承父进程环境变量**，无任何网络、文件系统、环境变量白名单限制，可读取 `MEOW_TRAFFIC_BACKEND_TOKEN` 等敏感变量。 | 为 Python 子进程构造干净的最小环境变量集合，移除敏感变量，禁止继承外部 `PYTHONPATH`。 |
| 12 | miscpkg | `backend/internal/miscpkg/manager.go` | `Invoke` 直接根据模块文件扩展名决定运行时，导入 zip 即等同于授予本地代码执行能力；缺少运行时的权限声明校验。 | 在 `Invoke` 前校验 `api.json` 中声明的 `permissions`（如 `exec.local`），未声明或越权则拒绝执行。 |
| 13 | frontend | `frontend/src/app/integrations/clients/mediaClient.ts:71,76` | `downloadMediaArtifact` / `getMediaPlaybackBlob` 把 artifact token 放在 URL query string 中。 | 改为 POST body 或 header 传递 token；使用一次性短 token 或 signed URL，并在后端做有效期限制。 |

---

## 4. Medium 级别问题（近期修复）

### 4.1 Engine

| 文件路径 | 问题描述 | 建议修复 |
|---------|---------|---------|
| `backend/internal/engine/rule_manager.go:291-322` | `RefreshPackFromDisk` 直接 `filepath.Join(cacheDir, packID+".yar")`，未调用 `validateRulePackID` / `safeCachePath`。 | 复用 `validateRulePackID(packID)` + `safeCachePath(cacheDir, packID)`。 |
| `backend/internal/engine/media_playback.go:49-52, 258-277` | FFmpeg 环境变量解析未经过 `ValidateExecutablePath`。 | 在 `resolveFFmpegBinary` 中对自定义路径调用 `ValidateExecutablePath`。 |
| `backend/internal/engine/speech_to_text.go:535-604` | Python 环境变量解析未经过 `ValidateExecutablePath`。 | 在 `resolveSpeechPythonCommandWithContext` 中对自定义路径调用 `ValidateExecutablePath`。 |
| `backend/internal/engine/evidence.go:47-49` | `gatherWebShellEvidence` 不接受 context，无法被取消。 | 为 `gatherWebShellEvidence` 增加 context 参数并检查 `ctx.Err()`。 |
| `backend/internal/engine/service_analysis.go:820-900` | `USBAnalysisWithOptions` 的 `HIDEventLimit` 未设上限，过大时可能导致内存/CPU 爆炸。 | 设置合理上限（如 10,000），超限返回错误。 |
| `backend/internal/engine/service_analysis.go:300-380` | `mediaAnalysisCold` 临时目录清理逻辑依赖 `s.captureCtl.pcap != pcap` 字符串比较，可能误删。 | 将临时目录绑定到 runID / task 生命周期，统一清理。 |

### 4.2 Transport

| 文件路径 | 问题描述 | 建议修复 |
|---------|---------|---------|
| `backend/internal/transport/http_analysis_handlers.go:355` | `handleObjectsDownload` 直接 `os.Open(obj.Path)`，未校验 `obj.Path` 是否落在预期输出目录。 | 对 `obj.Path` 做 base-dir 白名单校验。 |
| `backend/internal/transport/http_media_handlers.go:28-54` | `handleMediaArtifactDownload`、`handleMediaArtifactPlayback` 直接使用 service 返回的 `path` 打开文件。 | 增加 `validateArtifactPath(path, allowedBaseDirs)` helper 统一校验。 |
| `backend/internal/transport/http_middleware.go:57-82` | `withAuth` 未豁免 `/api/events`；浏览器 `EventSource` 无法设置 `Authorization` 头。 | 豁免 `/api/events` 或设计 Cookie/短效 token 方案。 |
| `backend/internal/transport/http_middleware.go:33-55` | CORS `Access-Control-Allow-Methods` 缺少 `PUT`。 | 将 `PUT` 加入允许方法列表。 |
| `backend/internal/transport/http_helpers.go:45-60` | `sanitizeErrorMessage` 已定义但 transport 层无人调用，500 错误泄露内部路径。 | 所有返回 500 的路径统一使用 `sanitizeErrorMessage`。 |
| `backend/internal/transport/http_tool_handlers.go:72-87` | `handleMCP` 透传请求体，无 body 大小限制。 | 在 `handleMCP` 入口包 `http.MaxBytesReader`（如 1MB）。 |
| `backend/internal/transport/http_rule_handlers.go:120` | `handleRulesDownload` 允许用户指定任意 URL 下载规则包，存在 SSRF。 | 增加 URL 黑名单/内网限制、校验 remote URL 与配置白名单一致。 |
| `backend/internal/transport/http_capture.go:66` | `handleCaptureStart` 使用 `context.WithoutCancel(r.Context())` 启动后台 goroutine，请求取消不会中断加载。 | 返回 `loadRunID` 并新增取消接口，或改用可取消 context。 |

### 4.3 Tshark

| 文件路径 | 问题描述 | 建议修复 |
|---------|---------|---------|
| `backend/internal/tshark/field_scan_plan.go:75` | `planFieldScanByCapabilities` 使用 `context.Background()` 探测能力，会阻塞最多 5 秒。 | 给 `planFieldScanByCapabilities` 增加 `ctx` 参数并传给 `CurrentFieldSet`。 |
| `backend/internal/tshark/analysis_helpers.go:55,119` 等 | 多个遗留入口仍使用 `context.Background()`。 | 提供 `WithContext` 版本并标记无 context 版本 deprecated；在 engine 中迁移。 |
| `backend/internal/tshark/runner.go:384` / `filter_ids.go:14` | `EstimatePackets`、`ScanFrameIDs` 循环内未检查 context。 | 替换为 `bufio.Reader` + `ReadString('\n')` 并在读取后检查 `ctx.Err()`。 |
| `backend/internal/tshark/analysis_helpers.go:186` 等 | `bufio.Scanner` 单行超限（2MB/4MB）会导致 `token too long` 硬失败，是 DoS 风险。 | 替换为 `bufio.Reader` + 行长度上限，超长行可截断或跳过。 |
| `backend/internal/tshark/analysis_helpers.go:167` | `scanFieldRowsWithOptionsContext` 超时硬编码为 30s。 | 将 timeout 作为 `fieldScanOptions` 可选字段，默认值 30s，调用方可覆盖。 |
| `backend/internal/tshark/field_scan_cache.go` | 字段扫描缓存单条目内存无上限，大抓包可能使单个缓存条目占用大量内存。 | 对单个 entry 设置行数/字节上限。 |

### 4.4 Miscpkg

| 文件路径 | 问题描述 | 建议修复 |
|---------|---------|---------|
| `backend/internal/miscpkg/zip_utils.go` | `extractZipToDir` 未处理 zip 中的符号链接、硬链接、特殊文件模式；Unix 平台恶意 zip 可通过 symlink 指向模块目录外。 | 拒绝 `ModeSymlink`、`ModeNamedPipe` 等非普通文件/目录条目。 |
| `backend/internal/miscpkg/result.go` | `defaultScanFields` 直接调用无 context 的 `tshark.ScanFieldRowsWithDisplayFilter`。 | 给 tshark 扫描提供 context-aware 版本。 |
| `backend/internal/miscpkg/manager_test.go` | `TestMain` 全局设置 `MEOW_TRAFFIC_ALLOW_UNSIGNED_MISC=1`，默认测试走未签名路径，可能掩盖签名回归。 | 默认测试模拟生产环境，仅在需要未签名的子测试中显式设置。 |

### 4.5 Frontend

| 文件路径 | 问题描述 | 建议修复 |
|---------|---------|---------|
| `frontend/src/app/state/useSentinelProviderBody.ts` + `useCaptureStartWorkflow.ts` | `clients`/`hooks` 参数每次渲染都是新对象，导致 `startCapture`/`openCapture` 不稳定。 | 用 `useMemo` 稳定对象；或拆分依赖。 |
| `frontend/src/app/layouts/MainLayout.tsx:113-131` | `useEffect` 依赖 `[navigate, openCapture]`，`openCapture` 不稳定导致全局 `keydown` 监听器重复注册/卸载。 | 修复 `openCapture` 稳定性后消除。 |
| `frontend/src/app/misc/hooks/useMiscModuleAnalysis.ts` 及 `misc/modules/*` | 这些模块仍直接 `useSentinel()` 取 `fileMeta`，未使用子 context hooks。 | 迁移到 `useCapture()`。 |
| `frontend/src/app/components/StreamDecoderSettingsStorage.ts` | 把 webshell 解码密钥完整持久化到 `localStorage`，存在 XSS 时泄露风险。 | 敏感字段不持久化，使用内存态。 |
| `frontend/src/app/misc/modules/BruteforceModule.tsx` / `UDPTunnelModule.tsx` / `SMB3SessionKeyModule.tsx` / `WinRMDecryptModule.tsx` | 这些 MISC 模块的 API 调用无 `AbortSignal` 取消机制。 | 接入 `useAbortableRequest` 或 `AbortController`。 |

---

## 5. Low 级别问题（排期优化）

- **Engine**: `rule_manager.go` `ValidateRules` 简单行扫描不理解 YARA 字符串常量中的大括号；`speech_to_text.go` batch task seed 仅依赖 `time.Now().UnixNano()`；IOC 导入/索引小 bug。
- **Transport**: `/api/runtime/identity` 暴露敏感环境信息；`withAudit` `Authenticated` 字段固定为 `true`；部分只读 handler 未校验 HTTP Method。
- **Tshark**: `StreamPackets*` 四段高度重复；`parseFastListLine` 魔法数字；解析错误静默丢弃；`ExportObjectsContext` 错误信息不足。
- **Miscpkg**: `LoadFromDir` 静默跳过错误；签名与加载入口不一致；`miscpkg` 对 `tshark` 的直接依赖；签名文件解析错误信息不清晰。
- **Frontend**: `desktopWebviewSmoke.ts` 多处 `any`；部分 wire DTO 仅做防御性断言，可引入 zod 做运行时校验。

---

## 6. V0 修复回归风险矩阵

| 规则 | 当前状态 | 风险说明 |
|------|---------|---------|
| S1 可执行路径白名单 | ⚠️ 部分覆盖 | tool 路径已校验，但 hunting config、env-var 解析（FFmpeg/Python/tshark）、YARA 规则路径未完全覆盖。 |
| S2 MISC zip 签名 | ❌ 加载入口未覆盖 | 导入阶段已落地，但 `LoadFromDir` 未验签，是最大的绕过路径。 |
| S3 base-dir 路径校验 | ❌ 未完全落地 | capture 启动、DBC 路径、对象/媒体导出仍用 `strings.Contains("..")`。 |
| S4 http.Client 超时 | ✅ 已配置 | rule manager 30s 超时；未发现 transport 层新建无超时 client。 |
| S5 禁止硬编码 IV / key-as-IV | ✅ 未发现 | C2 / WebShell AES-CBC IV 均从密文前缀或请求传入。 |
| R6 context 进入长任务 | ⚠️ 外壳可取消 | tshark 子进程实际无法被完全取消，`DetectLikelyRTPPorts`、能力探测、多个遗留 builder 仍用 `context.Background()`。 |

---

## 7. 优先修复清单（按严重级别排序）

### P0 - Critical（立即）

1. `miscpkg/manager.go`：`LoadFromDir` 加载已安装模块时必须重新校验目录级签名。
2. `transport/misc_package_handlers.go`：流式化 MISC zip 导入并限制大小。
3. `frontend/src/app/integrations/clients/eventClient.ts`：移除 URL token，改为 header/cookie 鉴权。
4. `tshark/config.go` / `engine/tool_runtime.go`：接入 tshark 路径白名单校验。

### P1 - High（本周内）

5. `transport/http_analysis_handlers.go`：补齐 hunting config 的 YARA 路径白名单校验。
6. `transport/http_capture.go`：capture 启动路径使用 base-dir 校验。
7. `transport/http_analysis_handlers.go` / `engine/service_analysis.go` / `tshark/dbc.go`：Vehicle DBC 路径 base-dir 校验。
8. `engine/rule_manager.go`：YARA manifest URL scheme / SSRF 校验。
9. `tshark/runner.go` / `media_analysis.go`：`ExportObjectsContext` 与 `buildMediaArtifact` 路径遍历与大小上限。
10. `tshark/media_analysis.go`：新增 `DetectLikelyRTPPortsContext` 并迁移调用点。
11. `miscpkg/runtime_python.go`：Python 子进程环境变量最小化隔离。
12. `miscpkg/manager.go`：`Invoke` 前校验模块声明的 `permissions`。
13. `frontend/src/app/integrations/clients/mediaClient.ts`：把 artifact token 从 URL 移到 body/header。

### P2 - Medium（近期）

14. Engine: `RefreshPackFromDisk` 路径安全加固；FFmpeg/Python 环境变量路径校验；`gatherWebShellEvidence` 接入 context；`HIDEventLimit` 上限。
15. Transport: 对象/媒体/WinRM 导出 base-dir 校验；SSE 认证豁免；CORS 加入 `PUT`；统一错误脱敏；MCP/MISC 请求体大小限制；Shutdown 超时。
16. Tshark: `planFieldScanByCapabilities` 传 context；遗留入口提供 `WithContext` 版本；scanner token 过长修复；字段扫描缓存单条目上限。
17. Miscpkg: 拒绝 zip 中的 symlink/特殊文件；context-aware tshark fallback；`LoadFromDir` 错误聚合；测试默认环境调整。
18. Frontend: 稳定 `startCapture/openCapture`；迁移 `useSentinel` 使用；webshell 密钥持久化策略；MISC 模块 API 取消机制。

### P3 - Low（排期）

19. Engine: `ValidateRules` 语法检查说明；batch task seed 唯一性；IOC 小 bug。
20. Transport: `/api/runtime/identity` 信息暴露；`withAudit` 认证状态；只读 handler Method 校验。
21. Tshark: `StreamPackets*` 抽象；魔法数字；解析错误计数；30s 超时可配置。
22. Miscpkg: 清理重复 root 计算；解耦 `miscpkg` 与 `tshark`。
23. Frontend: `desktopWebviewSmoke.ts` 清理 `any`；引入 zod 做 wire DTO 运行时校验。

---

## 8. 验证建议

修复后请至少执行：

```bash
# 后端
cd backend
go test ./...
go vet ./...
go test -race ./internal/engine/... ./internal/transport/... ./internal/tshark/...
gofmt -l .

# 前端
cd frontend
pnpm run ci
```

并针对新增校验补充单测：

- Transport 层：非法 YARA 路径、非法 capture 路径、非法 DBC 路径返回 400；MISC 上传大小超限返回 413。
- Engine 层：`RefreshPackFromDisk` 对 `../` packID 报错；`LoadFromDir` 对篡改签名模块报错。
- Tshark 层：context 取消后子进程被终止；`DetectLikelyRTPPortsContext` 取消用例。
- Frontend：`EventSource` 不再在 URL 中带 token；`mediaClient` 下载/播放使用 header token。

---

## 9. 修复状态

上述 Critical 级别问题（#1–#4）已于 2026-06-21 在 V0 收尾阶段修复并验证通过：

| # | 状态 | 关键提交 |
|---|------|---------|
| 1 | ✅ 已修复 | `backend/internal/miscpkg/signature.go` 新增 `verifyModuleDirSignature`；`manager.go#LoadFromDir` 加载前校验目录签名。 |
| 2 | ✅ 已修复 | `backend/internal/miscpkg/manager.go` 新增 `ImportZip(io.Reader, int64)`；`transport/misc_package_handlers.go` 使用 `MaxBytesReader` 并返回 413。 |
| 3 | ✅ 已修复 | `frontend/src/app/integrations/clients/eventClient.ts` 改为 fetch-based SSE，token 走 `Authorization` header。 |
| 4 | ✅ 已修复 | `backend/internal/engine/tool_runtime.go#applyConfig` / `#setTSharkPath` 调用 `ValidateExecutablePath`。 |

High/Medium/Low 级别问题按规划归入 V1 阶段处理。

**复查人**：Kimi Code CLI
**报告文件**：`docs/review-round-2026-06-21.md`
