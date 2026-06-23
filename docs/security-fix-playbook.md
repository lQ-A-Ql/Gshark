# meow~traffic 安全修复规范手册

> 本手册基于 2026-06-20 全项目深度审计报告制定，作为本 session 及后续修复工作的强制准则。
> 完整审计报告：`docs/audit-development-report-archive-2026-06-20/full-project-audit-report-2026-06-20.md`

## 1. 目标与范围

### 1.1 目标

1. 优先堵住 P0 安全漏洞（RCE、任意代码执行、密码学缺陷、依赖 CVE）。
2. 统一 `WithContext` 契约，消除长任务不可取消问题。
3. 通过新增/强化的自动化门禁防止回归。
4. 全项目审计评分从 5.5/10 提升至 ≥ 7.0/10。

### 1.2 适用对象

- 所有修改 `backend/internal/transport`、`backend/internal/engine`、`backend/internal/miscpkg`、`backend/internal/tshark` 的修复。
- 所有修改 `frontend/src` 的修复。
- 所有修改构建脚本、CI、发布流程的修复。

---

## 2. 修复边界划分

### 2.1 允许修改的模块

| 模块 | 允许的修改范围 | 禁止的修改 |
|------|---------------|-----------|
| `backend/internal/transport` | handler 输入校验、错误处理、context 传递、超时、CORS | 不改变路由结构、不新增无测试的 handler |
| `backend/internal/engine` | 增加 `WithContext` 变体、修复状态机/锁、修复密码学缺陷、修复路径遍历/SSRF | 不重构整个 controller 层级、不删除 grandfathered 大文件 |
| `backend/internal/miscpkg` | 增加签名/沙箱/环境隔离/资源限制 | 不修改现有 JS/Python API contract |
| `backend/internal/tshark` | 增加 context 感知版本、修复 ExportObjects | 不改动字段扫描核心逻辑 |
| `backend/rules/yara` | 内置规则数量需与代码一致 | 不引入无来源规则 |
| `frontend/src` | 升级依赖、改 EventSource、拆分 context、抽象 hook、增加 Error Boundary | 不一次性重写所有 feature hooks |
| `app.go` / build scripts | 修复 env 变量名、增加 ready 等待、签名校验 | 不改 Wails 生命周期接口 |
| `AGENTS.md` / 本手册 | 补充安全/边界规则 | 不删除已有 build tag 规则 |
| CI scripts | 增加 audit、签名检查、发布脚本测试 | 不删除现有 job |

### 2.2 冻结/最小改动的模块

| 模块 | 原因 | 处理原则 |
|------|------|----------|
| `backend/internal/model` | 被多处依赖，改动影响面大 | 仅新增字段，不删除/重命名 |
| `backend/internal/report` | boundary test 要求 dependency-light | 不引入 engine/transport 依赖 |
| `backend/internal/servicecontract` | 是跨层契约 | 新增接口，不删除旧接口 |
| `frontend/src/app/integrations/bridge*.ts` | 桌面 IPC 迁移中 | 仅修复明确问题，不重构 bridge |
| `wails.json` / `main_nondesktop.go` | 构建 tag 控制核心 | 不改入口行为 |

### 2.3 绝对红线

1. **禁止在 HTTP handler 中调用非 `WithContext` 的同步方法**。
2. **禁止在修复中引入新的 `context.Background()` 到请求链路**。
3. **禁止直接拼接用户输入到 `exec.Command`**，必须参数化 + 白名单校验。
4. **禁止新增无单元测试的边界/安全修复**。
5. **禁止修改 `backend/internal/architecture/boundary_test.go` 中的 grandfathered 列表来逃避大文件限制**；若必须拆分，走代码重构。
6. **禁止修改 frontend boundary script 的 allowlist 来绕过规则**；新增 allowlist 条目需 PR 中明确说明理由。
7. **禁止在 EventSource URL 中传递 token**。
8. **禁止新增 `useSentinel()` 调用**。

---

## 3. 后端架构规则

### 规则 B1：HTTP handler 必须使用 `WithContext` 变体

**适用范围**：`backend/internal/transport/*.go`。

**检查方式**：扩展 `backend/internal/architecture/boundary_test.go` 的 forbidden 列表。

**当前必须新增到 forbidden 列表的调用**：

- `s.media.MediaAnalysis()`
- `s.media.RefreshMediaAnalysis()`
- `s.media.TranscribeMediaArtifact(payload.Token, payload.Force)`
- `s.toolAnalysis.ListNTLMSessionMaterials()`
- `s.toolAnalysis.ListSMB3SessionCandidates()`
- `s.toolAnalysis.RunWinRMDecrypt(req)`
- `evidence.go` 中所有调用无 context 媒体分析的方法

**实现路径**：

1. 在 `backend/internal/servicecontract/contract.go` 中为 `MediaReadService` 增加 `MediaAnalysisWithContext(ctx)`。
2. `engine.Service` 实现该接口。
3. transport 层全部改为调用 `WithContext` 版本。
4. boundary test 更新 forbidden 列表；若新增方法触及多个 controller，同步更新 `allowedServiceCrossControllerMethods()`。

**正确示例**：

```go
// ✅ correct
result, err := s.svc.ThreatHuntWithContext(r.Context(), ...)
result, err := s.svc.MediaAnalysisWithContext(r.Context())

// ❌ wrong — blocks close/replacement cancellation
result, err := s.svc.ThreatHunt(...)
result, err := s.svc.MediaAnalysis()
```

### 规则 B2：Service facade 跨 controller 访问必须登记

**适用范围**：`backend/internal/engine/*.go` 中接收者为 `*Service` 的方法。

**检查方式**：已有 `allowedServiceCrossControllerMethods()`。

**修复阶段要求**：新增或修改触及多个 controller 的 Service 方法，必须同步更新 `allowedServiceCrossControllerMethods()`，否则 CI 失败。

### 规则 B3：tshark 调用必须接受 context

**适用范围**：`backend/internal/tshark/*.go`、所有调用 tshark 的 engine 代码。

**检查方式**：

- `tshark` 包内不得新增 `func XXX(...) error` 这种无 context 的长时间运行函数。
- engine 中调用 tshark 的位置必须传递非 `context.Background()` 的 context。

**例外**：`ExportObjects` 的 legacy 版本保留，但新增代码必须调用 `ExportObjectsContext`。

### 规则 B4：规则管理路径安全

**适用范围**：`backend/internal/engine/rule_manager.go`。

**检查方式**：新增单元测试：

- `DownloadPack("../../../tmp/evil", url)` 必须返回路径遍历错误。
- URL scheme 必须为 `http`/`https`。
- checksum 不匹配必须拒绝缓存。

---

## 4. 前端架构规则

### 规则 F1：禁止 EventSource URL 传 token（已完成）

**适用范围**：`frontend/src/app/integrations/clients/eventClient.ts`。

**规则**：

- 前端 SSE 客户端使用 `fetch` + `ReadableStream` 手动解析事件流。
- token 通过 `Authorization: Bearer <token>` header 传递。
- URL 中不得出现 `access_token` 或任何鉴权凭证。

**检查方式**：

- 代码审查：`eventClient.ts` 中无 `EventSource` 构造与 `access_token=` 拼接。
- 单元测试：mock `fetch` 验证 URL 不含 token、header 含 Bearer token。

**涉及文件**：

- `frontend/src/app/integrations/clients/eventClient.ts`
- `frontend/src/app/integrations/clients/eventClient.test.ts`

### 规则 F2：逐步废弃 `useSentinel()`

**适用范围**：`frontend/src/app/state/hooks/useSentinelContextValues.ts`。

**检查方式**：

- 不新增 `useSentinel()` 调用。
- boundary script 检测新增 `useSentinel` 调用并告警（grandfathered 现有调用）。

**实现路径**：新建 `useBackendContext()`、`useCaptureContext()` 等子 hooks；现有调用逐步迁移。

### 规则 F3：clients 层禁止 `any`

**适用范围**：`frontend/src/app/integrations/clients/*.ts`。

**检查方式**：已有 `frontend/scripts/check-client-any.mjs`。

**修复阶段要求**：修复新增/修改的 client 代码时，不得引入新的 `any`。

### 规则 F4：依赖安全审计进 CI

**适用范围**：`frontend/package.json`、`.github/workflows/ci.yml`。

**检查方式**：CI 中增加 `pnpm audit --prod --audit-level=high`，失败即阻断。

**临时例外**：若某个 high 漏洞无法立即修复，需在 `package.json` 中明确 `pnpm.audit.allow` 并附 ticket 链接，且须经 reviewer 批准。

---

## 5. 安全规则（跨前后端）

### 规则 S1：可执行文件路径配置必须统一走“硬拒绝 + 警示 + 快捷加白”

**适用范围**：`SetTSharkPath`、`SetToolRuntimeConfig` 中的 `TSharkPath`、`PythonPath`、`FFmpegPath`、`YaraBin`，以及所有后端实际执行 tshark、ffmpeg、python、yara/yarac 的入口。

**统一策略**：

- 空路径表示自动探测，不报错。
- name-only 路径（如 `tshark`、`ffmpeg`、`python`、`yara64`）只能通过 `PATH` 解析，解析后继续校验 basename 与硬安全边界。
- 绝对路径若位于默认可信目录或用户显式加入的允许目录，正常保存、探测、运行。
- 绝对路径若是合法二进制但不在默认/额外允许目录中，必须只返回 `path_warning`，不阻止保存、探测或运行；前端必须展示 amber warning 与“加入白名单”按钮。
- 以下危险路径始终硬拒绝，不能降级为 warning：
  - 带目录组件的相对路径。
  - basename 不匹配预期工具名。
  - 脚本/解释型扩展名（如 `.sh`、`.bat`、`.cmd`、`.ps1`、`.js`、`.py`）。
  - 目录、不可访问文件、Unix 下无执行位文件。
  - 符号链接目标不满足同一套硬安全边界。
- 用户允许目录必须随 `ToolRuntimeConfig` 持久化并同步到后端，字段包括：
  - `tshark_allowed_dirs`
  - `ffmpeg_allowed_dirs`
  - `python_allowed_dirs`
  - `yara_allowed_dirs`
- 后端 generic API 必须支持四类工具的目录加白、查询、移除：`/api/tools/allow-dir`、`/api/tools/allowed-dirs`、`/api/tools/allowed-dirs/remove`。旧的 tshark 专用 API 可保留兼容，但新功能优先走 generic API。

**检查方式**：

- 四类工具均使用 `engine.ValidateExecutablePathWithWarning(path, expectedNames, allowedDirs...)`；硬错误返回 error，目录未加白返回非空 warning。
- `backend/internal/tool.Runtime` 以 `ModeWarn` 管理所有工具路径，确保合法但未加白路径不会阻止运行。
- 新增/修改相关代码时，必须补充覆盖：
  - 合法外部目录路径返回 warning 且仍保存/运行。
  - 点击“加入白名单”后 warning 消失。
  - 危险路径硬拒绝。
  - generic tool allow-dir API 对 ffmpeg/python/yara 生效。

**涉及文件**：

- `backend/internal/tool/validator.go`
- `backend/internal/tool/runtime.go`
- `backend/internal/transport/http_tool_handlers.go`
- `backend/internal/engine/tool_runtime.go`
- `backend/internal/engine/tool_runtime_validator.go`
- `frontend/src/app/components/TSharkPathAllowWarning.tsx`
- `frontend/src/app/components/MediaSettingsSection.tsx`
- `frontend/src/app/components/SpeechSettingsSection.tsx`
- `frontend/src/app/components/YaraSettingsSection.tsx`
- `frontend/src/app/components/useRuntimeSettingsSidebarModel.ts`

### 规则 S2：MISC 模块导入与加载必须签名验证

**适用范围**：`backend/internal/miscpkg/manager.go:ImportZipBytes`、`ImportZip`、`LoadFromDir`。

**规则**：

- zip 包内必须包含 `signature` 文件。
- 使用 Ed25519 验证签名，公钥从 `MEOW_TRAFFIC_MISC_PUBLIC_KEY` 加载（hex 或 base64）。
- 无签名或签名失败拒绝导入；签名失败的服务启动加载阶段记录错误并跳过该模块。
- 已安装模块目录在 `LoadFromDir` 时重新校验目录级签名，防止磁盘篡改绕过。
- 签名 payload 对 zip 包和目录使用同一规范化算法：所有文件（除 `signature`）按相对路径排序，格式为 `rel\0content\0`。

**过渡期**：可允许 `MEOW_TRAFFIC_ALLOW_UNSIGNED_MISC=1` 用于开发，但 release build（`production` tag）必须强制签名。

**涉及文件**：

- `backend/internal/miscpkg/manager.go`
- `backend/internal/miscpkg/signature.go`
- `backend/internal/miscpkg/module_loader.go`
- `backend/internal/transport/misc_package_handlers.go`

### 规则 S3：文件路径操作必须 base-dir 校验

**适用范围**：所有接收用户路径并拼接到文件系统的代码。

**规则**：

- 使用 `filepath.Clean(absPath)` + `strings.HasPrefix(absPath, baseDir)`。
- 禁止仅依赖 `strings.Contains(path, "..")`。

**检查方式**：新增 lint 脚本或 gosec 规则扫描 `filepath.Join(.*, userInput)` 模式。

**涉及文件**：

- `backend/internal/engine/rule_manager.go`
- `backend/internal/transport/http_tool_handlers.go`

### 规则 S4：HTTP client 必须设置超时

**适用范围**：所有 `http.Client` 实例。

**规则**：必须设置 `Timeout`，默认不超过 30 秒；下载规则等场景可配置但必须有上限。

**检查方式**：gosec G107 + 人工 review。

**涉及文件**：

- `backend/internal/engine/rule_manager.go`
- 所有新增使用 `http.Client` 的代码

### 规则 S5：密码学实现禁止硬编码 IV / key-as-IV

**适用范围**：`backend/internal/engine/c2_decrypt.go`。

**规则**：

- 禁止使用全零/硬编码 IV。
- 禁止将 key 直接作为 IV。
- 必须使用密码学安全的随机 IV（如 `crypto/rand`）。

**检查方式**：gosec G401/G501 + 密码学测试（随机输入不应产生固定输出）。

---

## 6. 开发流程规则

### 6.1 分支与 PR 规则

1. **每个修复对应独立分支**：`fix/{risk-id}-{short-desc}`，例如 `fix/R1-tshark-path-whitelist`。
2. **P0 修复必须附带安全测试**：
   - 命令注入：构造恶意路径的测试用例。
   - 路径遍历：构造 `../` 测试用例。
   - 密码学：构造随机输入误报率测试。
3. **context 修复必须附带取消测试**：
   - 启动长任务后立即取消 context，验证子进程/ goroutine 在合理时间内结束。
   - 使用 `go test -race` 跑相关包。
4. **前端依赖升级必须锁定版本并说明**：PR 描述中列出 CVE ID 与修复版本。

### 6.2 Code Review 检查清单

#### 后端 Review Checklist

- [ ] 新增 HTTP handler 是否使用 `WithContext` 变体？
- [ ] 是否引入新的 `context.Background()` 到请求链路？
- [ ] 是否直接拼接用户输入到 `exec.Command`？
- [ ] 文件路径是否使用 base-dir 校验？
- [ ] 错误返回是否经过 `sanitizeErrorMessage` 处理？
- [ ] 是否更新 `backend/internal/architecture/boundary_test.go` 的 forbidden/allowed 列表？
- [ ] 是否新增/更新单元测试？
- [ ] `go test -race ./...` 是否通过？

#### 前端 Review Checklist

- [ ] 是否引入新的 `any`？
- [ ] 是否新增 `useSentinel()` 调用？
- [ ] 是否在 EventSource URL 中传 token？
- [ ] 是否升级依赖并说明 CVE？
- [ ] 是否增加/更新测试？
- [ ] `pnpm run ci` 是否通过？

### 6.3 CI 强化

#### 后端 CI

```yaml
- name: Go security scan
  run: |
    go install github.com/securego/gosec/v2/cmd/gosec@latest
    gosec -fmt sarif -out gosec.sarif ./...

- name: Staticcheck
  run: |
    go install honnef.co/go/tools/cmd/staticcheck@latest
    staticcheck ./...

- name: Vulnerability check
  run: |
    go install golang.org/x/vuln/cmd/govulncheck@latest
    govulncheck ./...
```

#### 前端 CI

```yaml
- name: Dependency audit
  run: pnpm audit --prod --audit-level=high
```

#### 桌面/发布 CI

1. 新增发布脚本测试 job：运行 `build_release_package.py --skip-build` 并验证 env 变量名。
2. 新增签名验证步骤：验证 embedded binary 的 hash/signature 与 manifest 一致。

---

## 7. 分阶段实施计划

### Phase 1：止血（第 1-2 周）

目标：堵住 P0 漏洞，恢复发布能力。

| 任务 | 验收标准 |
|------|----------|
| 统一 release smoke env 变量名 | `build_release_package.py` 与 `app.go` 使用同一变量名；CI desktop job 跑发布脚本测试 |
| 升级 react-router 并修复 audit | `pnpm audit --prod` 0 high；CI 增加 audit 步骤 |
| 修复 `SetTSharkPath`/`SetToolRuntimeConfig` 命令注入 | 白名单校验；新增恶意路径测试；boundary test 更新 |
| 修复 MISC zip 签名验证 | 无签名拒绝；开发模式可绕过但 release 强制；新增测试 |
| 修复 CS/VShell 密码学高危缺陷 | 删除硬编码/全零 IV；修正 key-as-IV；新增密码学测试 |
| 增加 MediaAnalysisWithContext 并迁移 handler | boundary test forbidden 列表更新；取消测试通过 |

### Phase 2：契约统一（第 3-4 周）

目标：消除 context 契约不一致，所有长任务可取消。

| 任务 | 验收标准 |
|------|----------|
| 改造 tshark builder 接收 context | 所有 `build*FromFileFn` 签名带 context；boundary test 禁止 engine 中 `context.Background()` 调用 tshark |
| 改造 `ExportObjects` 为 context 版本 | 所有调用点迁移；legacy 函数标记 deprecated |
| 修复 `speech_to_text.go` 批量入口 | 使用 `MediaAnalysisWithContext(ctx)` |
| 修复 `evidence.go` 媒体证据 | 使用 `MediaAnalysisWithContext(ctx)`；取消时返回部分结果 |
| 修复 `service_analysis.go` single-flight goroutine 泄漏 | 取消后底层 goroutine 可退出；`go test -race` 通过 |

### Phase 3：架构加固（第 5-8 周）

目标：修复中高风险，引入长期防护机制。

| 任务 | 验收标准 |
|------|----------|
| 修复 RuleManager SSRF + 路径遍历 + checksum | URL 白名单；packID 严格校验；checksum 校验测试 |
| miscpkg Python 最小环境变量 | 敏感变量过滤测试 |
| miscpkg JS 沙箱化评估与 POC | 独立进程或受限 VM 方案 |
| EventSource 改 fetch-based SSE | URL 无 token；新增 boundary 规则 |
| SentinelContext 拆分 | 不新增 `useSentinel()`；子 context hooks 覆盖 80% 以上新增代码 |
| 后端二进制签名验证 | desktop 启动校验 embedded binary signature/hash |
| 引入 gosec/staticcheck/govulncheck 到 CI | 三个工具均通过或已处理 issue |

### Phase 4：长期治理（第 9-12 周）

目标：抽象复用，防止回归。

| 任务 | 验收标准 |
|------|----------|
| 抽象通用前端 analysis hook | 8 个 feature hook 中至少 4 个复用通用 hook |
| 全局 Error Boundary | 生产环境捕获渲染错误并提示 |
| 统一依赖注入替代包级函数变量 | `build*FromFileFn` 改为接口或 struct 字段 |
| 统一错误处理使用 sanitizeErrorMessage | transport 层 90% 以上错误返回经过处理 |
| 持续审计机制 | 每月跑一次全项目审计并归档 |

---

## 8. 测试与验收

### 8.1 本地强制检查

每次提交前必须运行：

```powershell
# 后端
cd backend
go test ./...
go test -race ./...
gofmt -l .

# 前端
cd frontend
pnpm run ci
pnpm audit --prod --audit-level=high

# 全量
./scripts/check-all.ps1
```

### 8.2 整体验收标准

1. 所有 P0 漏洞修复完成且通过测试。
2. CI 增加 `pnpm audit`、`gosec`、`staticcheck`、`govulncheck` 并通过。
3. `backend/internal/architecture/boundary_test.go` 和 frontend boundary scripts 更新并反映新规则。
4. AGENTS.md 更新安全/架构/前端规则。
5. 全项目审计评分从 5.5/10 提升至 ≥ 7.0/10。
6. `go test -race ./...` 和 `pnpm run ci` 均通过。

---

## 9. 工具与脚本清单

| 工具/脚本 | 用途 | 状态 |
|----------|------|------|
| `backend/internal/architecture/boundary_test.go` | 后端架构边界 | 需扩展 |
| `frontend/scripts/check-boundaries.mjs` | 前端模块边界 | 需扩展 |
| `frontend/scripts/check-client-any.mjs` | 客户端 any 检查 | 保留 |
| `gosec` | Go 安全扫描 | 新增 |
| `staticcheck` | Go 静态分析 | 新增 |
| `govulncheck` | Go 依赖漏洞 | 新增 |
| `pnpm audit` | 前端依赖漏洞 | 新增到 CI |
| `docs/security-fix-playbook.md` | 修复规范文档 | 本文件 |

---

## 10. 附录：关键文件索引

| 文件 | 关注问题 |
|------|---------|
| `backend/internal/transport/http_tool_handlers.go` | 命令注入、路径白名单 |
| `backend/internal/transport/http_misc_handlers.go` | MISC 上传、签名验证 |
| `backend/internal/engine/tool_runtime.go` | 可执行路径校验 |
| `backend/internal/engine/rule_manager.go` | 路径遍历、SSRF、checksum |
| `backend/internal/engine/c2_decrypt.go` | 硬编码 IV、key-as-IV |
| `backend/internal/engine/media_playback.go` | context 化 |
| `backend/internal/engine/speech_to_text.go` | context 化 |
| `backend/internal/engine/evidence.go` | 媒体证据 context 化 |
| `backend/internal/engine/service_analysis.go` | single-flight goroutine 泄漏 |
| `backend/internal/miscpkg/manager.go` | zip 签名、沙箱 |
| `backend/internal/miscpkg/runtime_python.go` | 环境变量最小化 |
| `frontend/src/app/integrations/clients/eventClient.ts` | EventSource token |
| `frontend/src/app/state/SentinelContext.tsx` | context 拆分 |
| `frontend/src/app/state/hooks/useSentinelContextValues.ts` | useSentinel 废弃 |
| `frontend/package.json` | react-router CVE |


## V0 安全修复阶段执行记录

- 完成时间：2026-06-20
- 验证结果：
  - `cd backend && go test ./...` ✅
  - `cd backend && go test -race ./internal/engine/...` ✅
  - `cd frontend && pnpm run ci` ✅
  - `./scripts/check-all.ps1` ✅
- 本阶段落地项：
  - R1 可执行路径白名单：`backend/internal/engine/tool_runtime_validator.go`
  - R2 MISC zip 签名：`backend/internal/miscpkg/signature.go`
  - R3 C2 密码学：移除 AES-CBC 硬编码/零 IV、key-as-IV 回退
  - R4 前端依赖：`react-router` 升级至 7.15.0
  - R5 MediaAnalysis context 化：`backend/internal/engine/service_analysis.go` + `backend/internal/tshark/media_analysis.go`
  - R6 RuleManager 路径安全：`backend/internal/engine/rule_manager_security.go` / `rule_manager_yara.go`

## V0 收尾修复记录（Critical 缺口关闭）

- 完成时间：2026-06-21
- 复查报告：`docs/review-round-2026-06-21.md`
- 验证结果：
  - `cd backend && go test ./...` ✅
  - `cd backend && go test -race ./internal/engine/... ./internal/transport/... ./internal/tshark/... ./internal/miscpkg/...` ✅
  - `cd backend && gofmt -l .` ✅
  - `cd frontend && pnpm run ci` ✅
  - `./scripts/check-all.ps1` ✅
- 本阶段落地项：
  - C1 MISC 目录级签名：`backend/internal/miscpkg/signature.go#verifyModuleDirSignature` + `manager.go#verifyModuleDir`
  - C2 MISC zip 流式上传：`backend/internal/miscpkg/manager.go#ImportZip` + `backend/internal/transport/misc_package_handlers.go`
  - C3 EventSource 改 fetch-based SSE：`frontend/src/app/integrations/clients/eventClient.ts`
  - C4 tshark 路径 engine 层白名单校验：`backend/internal/engine/tool_runtime.go#applyConfig` / `#setTSharkPath`
  - 附加：修复 `backend/internal/transport/http_server_test.go` 中 SSE handler 测试的 data race。
  - CI 新增 `pnpm audit --prod --audit-level=high` 与 `govulncheck ./...`
