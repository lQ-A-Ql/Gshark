# meow~traffic 全项目深度审计报告

**审计日期**：2026-06-20
**审计范围**：后端引擎、后端传输层、后端支撑包、前端、桌面与构建/CI
**审计方法**：4 个专项子代理逐函数走查 + 人工精读关键文件 + 测试基线验证
**报告版本**：v1.0

---

## 执行摘要

本项目（meow~traffic / gshark-sentinel）是一个面向网络流量分析、威胁狩猎与取证的安全桌面应用。经过逐模块深度审计，项目功能已相当完整，测试覆盖率与 CI 门禁能够守住基本质量底线，但**在安全设计、架构一致性、context 取消契约方面存在系统性债务**。

### 关键结论

- **测试基线**：后端 `go test ./...` ✅ 通过，`gofmt`/`go vet` ✅ 通过；前端 `typecheck`/`lint`/`test:run` ✅ 通过（913 个测试）。
- **严重安全漏洞**：工具路径配置 RCE、MISC zip 任意代码执行、C2 解密密码学缺陷、规则下载 SSRF+路径遍历、react-router 多个已知高危漏洞。
- **架构性债务**：`WithContext` 规范执行不彻底、包级可变函数变量滥用、`SentinelContext` 巨型 value、内置模块与 zip MISC 模块生命周期不统一。
- **整体健康度**：**5.5 / 10**

---

## 1. 项目架构概览

### 1.1 模块边界

| 层级 | 模块路径 | 职责 |
|------|---------|------|
| 桌面壳 | `github.com/gshark/sentinel/desktop`（root） | Wails 生命周期、嵌入前端、启动后端、事件桥 |
| 后端业务 | `github.com/gshark/sentinel/backend` | 全部分析逻辑、HTTP API、插件运行时 |
| 前端 | `@meow-traffic/sentinel-frontend` | React + Vite UI、状态管理、后端客户端 |
| MISC 插件 | `backend/internal/miscpkg` | JS/Python 模块加载与执行 |
| 规则 | `backend/internal/engine/rule_manager.go` | YARA 规则包下载与管理 |

### 1.2 关键数据流

1. 桌面壳或独立后端启动 `cmd/sentinel serve 127.0.0.1:17891`
2. HTTP 层 `internal/transport` 暴露 60+ REST/SSE 端点
3. `engine.Service` 作为统一门面，调度各 controller
4. 大量外部工具调用：`tshark`、`ffmpeg`、`python`、`yara/yarac`

---

## 2. 测试与质量基线

| 检查项 | 命令 | 结果 |
|--------|------|------|
| 后端全量测试 | `cd backend && go test ./...` | ✅ 通过 |
| 后端格式化 | `cd backend && gofmt -l .` | ✅ 无异常 |
| 后端静态检查 | `cd backend && go vet ./...` | ✅ 通过 |
| 根模块 dev 测试 | `go test -tags dev ./...` | ✅ 通过 |
| 前端类型检查 | `pnpm run typecheck` | ✅ 通过 |
| 前端 Lint | `pnpm run lint` | ✅ 通过 |
| 前端测试 | `pnpm run test:run` | ✅ 277 files / 913 tests 通过 |
| 前端安全审计 | `pnpm audit --prod` | ❌ 7 个 react-router 漏洞（4 high / 2 moderate / 1 low） |
| 被 gitignore 追踪文件 | `git ls-files -ci --exclude-standard` | ✅ 无 |

### 缺失的安全/深度静态检查

- 未集成 `gosec`
- 未集成 `staticcheck`
- CI 未运行 `pnpm audit`

---

## 3. 后端引擎（`backend/internal/engine`）

### 3.1 捕获生命周期（`service_capture.go`）

**健康度：6.5/10**

状态集合完整，runID 代、loadMu、activeLoadMu、任务注册表设计合理，能支撑基本并发安全。但在取消响应精度、后台 enrichment 生命周期绑定、mediaCtl 锁职责划分、状态转换原子性方面存在改进空间。

| 等级 | 问题 | 位置 | 说明 | 修复建议 |
|------|------|------|------|----------|
| High | onPacket 在 runID 不匹配时返回 nil | `service_capture.go:64-66` | 解析器继续读取并丢弃包，tshark 不能立即退出 | 改为 `return context.Canceled` |
| High | 后台 enrichment 使用 context.Background() | `service_capture.go:384-386` | enrichment 不与加载 run 生命周期绑定 | 改为使用加载的 runCtx |
| Medium | mediaCtl 字段访问全部依赖 captureCtl.mu | `service_capture.go:339-341, 355, 726-728` | 锁职责边界模糊 | 为 mediaController 引入独立锁 |
| Medium | PrepareCaptureReplacement 不等待旧加载完成 | `service_capture.go:675-688` | 返回时旧 tshark 可能仍在运行 | 文档明确异步语义或提供同步版本 |
| Medium | ClearCapture 仅等待 5 秒获取 loadMu | `service_capture.go:703-709` | 超时后不清除状态 | 增加可配置超时或强制模式 |
| Medium | commit 前 runID 检查位置偏后 | `service_capture.go:247-249` | 可能已调用 commitLoadedCapture | 将检查提前或 commit 内部再校验 |
| Low | LoadPCAPWithRun 空路径校验时机不当 | `service_capture.go:26-30` | activeLoadStatus 尚未创建 | 统一状态记录时机 |
| Low | ActiveCaptureTaskCount 使用 Lock 而非 RLock | `service_capture.go:516-520` | 只读长度无需排他锁 | 改为 RLock |

### 3.2 C2 解密算法（`c2_decrypt.go`）

**健康度：4/10**

功能覆盖完整，但密码学实现存在多项高危缺陷。

| 等级 | 问题 | 位置 | 说明 | 修复建议 |
|------|------|------|------|----------|
| Critical | CS AES-CBC 使用硬编码/全零 IV | `c2_decrypt.go:1456-1459` | `[]byte("abcdefghijklmnop")` 与全零 IV 破坏语义安全 | 删除常量 IV，仅保留 ciphertext 前缀 IV |
| Critical | VShell CBC 把派生 key 同时当 IV | `c2_decrypt.go:1202-1207` | key == IV 是已知设计缺陷 | 确认真实 IV 来源并修正 |
| High | PKCS7 unpadding 不是常量时间 | `stream_decoder.go:864-878` | 存在侧信道风险 | 重写为常量时间或改用 GCM |
| High | lenient unpadding 放大误报 | `stream_decoder_extended.go:41-59` | 随机字节极易被判为成功解密 | 无 HMAC 时要求明文结构校验 |
| Medium | VShell GCM key 使用 hex 编码后的 MD5 | `c2_decrypt.go:912-932` | 需确认公开样本派生方式 | 对照样本验证并注释来源 |
| Medium | 大 payload/长流无硬内存上限 | `c2_decrypt.go:723-759, 1222-1234` | frame 数量无上限 | 增加 maxCandidateBytes/maxStreamBytes/maxFrameCount |
| Medium | tshark 字段扫描不受 ctx 控制 | `c2_decrypt.go:463-481` | 取消无法终止子进程 | 改用支持 ctx 的变体 |
| Low | decodeColonOrPlainHex 每次编译正则 | `c2_decrypt.go:577-584` | 性能开销 | 提升为包级变量 |

### 3.3 流载荷分析（`stream_payload_sources.go` / `stream_decoder*.go` / `payloadinspect/*`）

**健康度：5.5/10**

| 等级 | 问题 | 位置 | 说明 | 修复建议 |
|------|------|------|------|----------|
| High | 正则复杂度/ReDoS 风险 | `stream_payload_sources.go` 多处 | WebShell 家族匹配、URI 扫描使用复杂正则 | 评估最坏情况并加超时 |
| High | 大流重组无内存上限 | `stream_payload_sources.go:652` | HTTPStream 触发 file-fallback 未限制总大小 | 增加总大小上限 |
| Medium | decoder 错误累积 | `stream_decoder.go` | 自动检测链可能传播错误解码 | 增加置信度阈值 |
| Medium | InspectStreamPayload 是 10 行 wrapper | `stream_payload_inspector.go` | 实际逻辑在下层包 | 合并或明确说明 |
| Low | 大量 magic number | 多处 | 截断长度、置信度阈值 | 使用具名常量 |

### 3.4 分析/YARA/语音/媒体/证据/规则管理

**健康度：5/10**

| 等级 | 问题 | 位置 | 说明 | 修复建议 |
|------|------|------|------|----------|
| High | MediaAnalysis/RefreshMediaAnalysis 使用 context.Background() | `service_analysis.go:292-316, 318-395` | 违反 WithContext 规范 | 增加 MediaAnalysisWithContext |
| High | tshark builder 不接收 context | `service_analysis.go:201, 223, 258, 516` | 取消无法中断 | 改造 builder 签名 |
| High | single-flight goroutine 在取消后继续运行 | `service_analysis.go:39-83` | 底层 fn() 可能继续运行重型任务 | 让 builder 可取消 |
| Critical | RuleManager.DownloadPack 路径遍历 | `rule_manager.go:250, 279` | packID 可用 ../ 写任意文件 | 严格校验 packID |
| High | RuleManager.DownloadPack SSRF + 无 checksum | `rule_manager.go:222-274` | URL 无白名单，checksum 未校验 | URL 白名单 + checksum 校验 |
| Medium | 内置规则数量硬编码 | `rule_manager.go:50-84` | 与实际数量可能不一致 | 实际解析后计算 |
| Medium | countYARARules / extractRuleEntries 解析鲁棒性差 | `rule_manager.go:539-633` | 简单行匹配 | 使用专用解析器 |
| Medium | 批量语音入口依赖不可取消 MediaAnalysis | `speech_to_text.go:181-241` | 应改为 MediaAnalysisWithContext |
| Medium | 媒体证据破坏 context 契约 | `evidence.go` + `evidence_collectors_assets.go:78` | gatherMediaEvidence 调用 s.MediaAnalysis() |
| Medium | evidence.go 取消时丢弃已收集结果 | `evidence.go:61-63` | 应返回部分结果 + notes |
| Low | yara_stream_targets 目标数量无上限 | `yara_stream_targets.go:48-88` | 大量 stream 时资源激增 |

---

## 4. 后端传输层（`backend/internal/transport`）

**健康度：5/10**

| 等级 | 问题 | 位置 | 说明 | 修复建议 |
|------|------|------|------|----------|
| Critical | 工具路径配置导致命令注入/RCE | `http_tool_handlers.go:22, 38` | 直接执行用户传入的 tshark/ffmpeg/python/yara 路径 | 白名单/签名校验 |
| Critical | MISC zip 模块导入后即可执行 | `misc_package_handlers.go:12-45` | 无签名/沙箱/来源校验 | 强制签名验证 + 沙箱 |
| High | 规则下载 SSRF + 路径遍历 | `http_rule_handlers.go:98-127` / `rule_manager.go:250` | URL 无白名单，packID 未过滤 | URL 白名单 + packID 校验 |
| High | 敏感信息泄露 | 多处 | sanitizeErrorMessage 已定义却很少使用 | 统一使用 sanitizeErrorMessage |
| High | MediaAnalysis handler 调用非 Context 版本 | `http_analysis_handlers.go:99-103` | 违反 AGENTS.md | 改为 MediaAnalysisWithContext |
| High | http.Server 无超时 | `http_server.go:232` | 易受慢连接 DoS | 增加 Read/Write/Idle Timeout |
| Medium | 路径遍历校验不足 | `http_capture.go:43-46` / `http_analysis_handlers.go:262-265, 278-280` | 仅检测子串 .. | 使用 filepath.Clean + base-dir |
| Medium | Token 比较非常量时间 | `http_middleware.go:68-75` | strings.ToLower + == | 使用 subtle.ConstantTimeCompare |
| Medium | CORS 未校验 scheme/port | `http_helpers.go:96-109` | 仅校验 hostname | 增加 scheme 校验 |
| Medium | 审计日志 Authenticated 恒为 true | `http_middleware.go:103` | 应反映实际认证状态 |
| Low | statusRecorder 丢失 Flusher/Hijacker | `http_middleware.go:109-117` | 可能影响 SSE/WebSocket |

---

## 5. 后端支撑包

### 5.1 `miscpkg`（MISC 模块运行时）

**健康度：4/10**

| 等级 | 问题 | 位置 | 说明 | 修复建议 |
|------|------|------|------|----------|
| Critical | JS 模块在进程内 Goja VM 执行 | `runtime_javascript.go:25` | 与后端同权限 | 沙箱化或独立进程 |
| Critical | Python 模块继承完整环境变量 | `runtime_python.go:160-164` | 可读取 MEOW_TRAFFIC_BACKEND_TOKEN | 构建最小 Env |
| High | zip 导入无签名/来源验证 | `manager.go:134-186` | 任意代码执行 | 强制签名验证 |
| High | Python 子进程无资源限制 | `runtime_python.go:79, 147` | 无内存/CPU 限制 | 增加 rlimit/cgroup |
| Medium | permissions 字段不强制 | `module_loader.go` | 已文档化但不校验 | 运行时强制 |
| Medium | host bridge 非 JSON 输出行覆盖 result | `runtime_python.go:174-195` | 调试输出可能丢失结果 | 改进协议解析 |
| Low | zip 路径穿越校验依赖 filepath.Rel | `zip_utils.go` | 未处理 symlink/点文件 |

### 5.2 `tshark`

**健康度：7/10**

| 等级 | 问题 | 位置 | 说明 | 修复建议 |
|------|------|------|------|----------|
| Medium | ExportObjects 使用 context.Background() | `runner.go:436-438` | 应改为 Context 版本 |
| Low | EstimatePackets 输出缓冲 2MB 固定 | `runner.go:409-410` | 极端输出可能截断 |
| Low | commandContextFn 可变 | `config.go:30` | 生产代码不应被替换 |

### 5.3 `yara`（`engine/yara_batch.go`）

**健康度：6/10**

| 等级 | 问题 | 位置 | 说明 | 修复建议 |
|------|------|------|------|----------|
| High | 自定义 yara 路径导致命令注入 | `yara_batch.go:122-124` | yc.Bin 直接执行 | 校验路径 |
| Medium | 默认 context.Background() | `yara_batch.go:142-144` | 应要求传 context |
| Medium | yarc 缓存目录可配置但无校验 | `yara_batch.go:52, 97-102` | 空时写规则同级目录 |
| Low | 规则元信息解析简单行匹配 | `yara_batch.go:540-615` | 对复杂语法鲁棒性差 |

---

## 6. 前端（`frontend/src`）

**健康度：5.5/10**

| 等级 | 问题 | 位置 | 说明 | 修复建议 |
|------|------|------|------|----------|
| Critical | react-router@7.13.0 多个高危漏洞 | `package.json:62` | RCE/XSS/DoS/CSRF | 升级至 >=7.15.1，CI 加 pnpm audit |
| High | EventSource URL 传 token | `eventClient.ts:32-35` | token 进入日志/历史/Referer | 改 fetch-based SSE |
| High | ESLint 关闭关键规则 | `eslint.config.js:65,67` | react-hooks/exhaustive-deps 与 no-explicit-any 关闭 | 开启并修复 |
| High | SentinelContext 巨型 value | `useSentinelContextValues.ts:28-30` | 任一字段变化触发所有消费者重渲染 | 废弃 useSentinel，迁移到子 context hooks |
| Medium | 8 个 feature hook 结构重复 | `features/*/use*.ts` | 应抽象通用 useAnalysisResource |
| Medium | 全局缺少 Error Boundary | - | 单点渲染错误可崩溃应用 | 增加 Error Boundary |
| Medium | Evidence 类型与转换分散 | `core/evidenceSchema.ts` / `core/evidenceTypes.ts` / `core/types/evidence.ts` / `mappers/evidenceMapper.ts` | 应统一 |
| Medium | MCP 端点硬编码 | `MCPSettingsSection.tsx` / `useRuntimeSettingsSidebarModel.ts` | 硬编码 http://127.0.0.1:17891/api/mcp |
| Low | pnpm 字段已弃用 | `package.json:89-97` | overrides/onlyBuiltDependencies 不生效 |
| Low | 部分 hook 未复用 useAbortableRequest | `useObjectExport.ts` / `useThreatHuntingWorkbench.ts` | 无法真正取消底层请求 |

---

## 7. 桌面与构建（root / scripts / CI）

**健康度：5/10**

| 等级 | 问题 | 位置 | 说明 | 修复建议 |
|------|------|------|------|----------|
| High | release smoke env 变量名不一致 | `build_release_package.py:83` vs `app.go:63,69` | 脚本 GSHARK_*，代码 MEOW_TRAFFIC_* | 统一为 MEOW_TRAFFIC_RELEASE_SMOKE_CHECK |
| High | 启动不等待后端 ready | `app.go:325-330` | cmd.Start() 后立即返回 | 增加 /health 轮询 |
| High | 嵌入二进制无签名验证 | `app.go:450-497` | 解压到用户可写临时目录 | 增加 Authenticode/minisign 校验 |
| Medium | 复用已有后端与随机 token 不兼容 | `app.go:286-306` | MEOW_TRAFFIC_ALLOW_EXISTING_BACKEND=1 多数场景无法工作 |
| Medium | dev 脚本无条件 kill 端口 | `start-wails-dev.ps1:77-78` | 可能误杀其他服务 |
| Medium | CI desktop job 未跑发布脚本 | `.github/workflows/ci.yml:104-157` | 不运行 build_release_package.py |
| Medium | 后端终止非 Windows 只发 TERM 不等待 | `app.go:600-609` | 可能导致资源泄漏 |
| Low | 多处硬编码路径/版本 | `build_release_package.py:16-19` / `build-backend-binary.ps1` / `ci.yml` | 应集中配置 |
| Low | main.go 嵌入目录缺失时 build 失败 | `main.go:14` | 应提供清晰错误提示 |
| Low | AGENTS.md 与脚本行为不一致 | `AGENTS.md` vs `start-wails-dev.ps1:63-84` | 文档称不自动清理，脚本已实现 |

---

## 8. 跨模块综合风险矩阵

| 风险编号 | 涉及模块 | 风险描述 | 利用面 | 优先级 |
|----------|----------|----------|--------|--------|
| R1 | transport + tool runtime | 任意可执行文件路径配置 | 本地/远程 RCE | P0 |
| R2 | transport + miscpkg | MISC zip 任意代码执行 | 本地/供应链 | P0 |
| R3 | engine(c2_decrypt) | 密码学实现缺陷 | 分析结果可信度 | P0 |
| R4 | frontend | react-router 已知漏洞 | XSS/RCE/DoS/CSRF | P0 |
| R5 | transport + rule_manager | 规则下载 SSRF + 路径遍历 | 写任意文件、内网探测 | P1 |
| R6 | engine(analysis) | 长任务不可取消 | 资源耗尽、IPC 超时 | P1 |
| R7 | miscpkg | Python/JS 模块无隔离 | 信息泄露、token 泄露 | P1 |
| R8 | frontend | EventSource URL 传 token | token 泄露 | P1 |
| R9 | desktop/build | release smoke 环境变量名错误 | 发布流程失败 | P1 |
| R10 | engine + transport | context 契约不一致 | 取消失效、状态不一致 | P2 |

---

## 9. 修复路线图

### 本周内（P0）

1. 统一 release smoke check 环境变量名为 `MEOW_TRAFFIC_RELEASE_SMOKE_CHECK`。
2. 升级 `react-router` 并增加 CI `pnpm audit`。
3. 为 `MediaAnalysis` 增加 `WithContext` 变体并迁移所有调用点。
4. 对 `SetTSharkPath` / `SetToolRuntimeConfig` 增加白名单/签名校验。
5. 移除 CS 硬编码 IV 与全零 IV 回退；修正 VShell key-as-IV。
6. 对 MISC zip 导入增加签名验证。

### 1-2 月（P1）

1. 改造所有 tshark builder 接收 context。
2. `rule_manager.go` 路径遍历、URL 白名单、checksum 校验。
3. miscpkg Python 最小环境变量、资源限制、JS 沙箱化评估。
4. EventSource 改 fetch-based SSE。
5. 前端 `SentinelContext` 巨型 value 拆分。
6. 后端二进制签名验证。

### 3-6 月（P2）

1. 统一依赖注入替代包级 `build*FromFileFn` 变量。
2. 抽象通用前端 analysis hook。
3. 增加全局 Error Boundary。
4. 引入 `gosec`/`staticcheck` 到 CI。
5. 统一错误处理，全面使用 `sanitizeErrorMessage`。

---

## 10. 总体评分

| 模块 | 评分 | 一句话总结 |
|------|------|------------|
| 后端引擎 - 捕获生命周期 | 6.5/10 | 状态机框架合理，取消精度与锁职责需改进。 |
| 后端引擎 - C2 解密 | 4/10 | 功能完整，密码学实现存在多项高危缺陷。 |
| 后端引擎 - 流载荷分析 | 5.5/10 | ReDoS 风险与大流内存上限是主要隐患。 |
| 后端引擎 - analysis/yara/speech/media/evidence/rule_manager | 5/10 | context 传递大面积缺失，rule_manager 有严重安全问题。 |
| 后端传输层 | 5/10 | 命令注入、SSRF、路径遍历、超时缺失集中爆发。 |
| 后端支撑包 - miscpkg | 4/10 | 扩展能力强，安全模型几乎空白。 |
| 后端支撑包 - tshark | 7/10 | 封装较规范，context 传递正确。 |
| 后端支撑包 - yara | 6/10 | 自定义路径注入风险与解析鲁棒性不足。 |
| 前端 | 5.5/10 | 测试充分，依赖漏洞与 context 架构是短板。 |
| 桌面与构建 | 5/10 | 流程基本跑通，发布脚本 bug 与 CI 覆盖不足。 |

**项目整体健康度：5.5 / 10**

---

## 11. 附录：审计局限性

- 本审计以静态代码分析为主，未执行模糊测试或运行时渗透测试。
- 部分安全问题的实际利用面取决于 transport 层是否已做前置校验；engine 层应做防御性校验。
- 未对 YARA 规则内容、PCAP 样本、前端 UI 交互做逐条审计。
- 未审计 Go 依赖（`go mod`）的已知 CVE；建议补充 `govulncheck`。
