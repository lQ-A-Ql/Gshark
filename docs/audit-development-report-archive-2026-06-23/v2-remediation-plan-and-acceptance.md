# meow~traffic V2 修补方案、阶段设计与验收门禁

制定日期：2026-06-23
依据审计：

- `docs/audit-development-report-archive-2026-06-20/full-project-audit-report-2026-06-20.md`
- `docs/review-round-2026-06-21.md`
- `docs/security-fix-playbook.md`
- 本轮逐模块代码审计与当前工作区实现状态

## 1. 总体结论

V2 的目标不是再做一次“大重构”，而是在 V0/V1 已关闭 Critical 缺口的基础上，把剩余 P1/P2 风险收敛成可验收、可回归、可门禁的工程闭环。

当前实现状态相较 2026-06-22 计划已有明显推进：

| 领域 | 当前状态 | 证据文件 | 风险判断 |
|------|----------|----------|----------|
| 工具链路径策略 | 已统一为 tshark/ffmpeg/python/yara “硬拒绝 + warning + 快捷加白”，合法外部路径不阻止运行 | `backend/internal/tool/validator.go`、`backend/internal/tool/runtime.go`、`backend/internal/transport/http_tool_handlers.go`、`frontend/src/app/components/TSharkPathAllowWarning.tsx` | 可进入回归验收 |
| HTTP server timeout | 已配置 `ReadTimeout`、`WriteTimeout`、`IdleTimeout` | `backend/internal/transport/http_server.go` | 可关闭 P1-7，需全量测试确认 |
| token 比较 | 已改 SHA-256 归一化后 constant-time compare | `backend/internal/transport/http_middleware.go` | 可关闭 P1-8 |
| CORS | 已校验 scheme、host、port | `backend/internal/transport/http_helpers.go` | 可关闭 P1-9 |
| RuleManager | 已有 host allowlist、checksum 必填、下载大小限制、safe cache path | `backend/internal/engine/rule_manager.go`、`rule_manager_security.go` | 可关闭 P1-10，需确认产品默认 allowlist |
| MISC Python | 已最小化环境变量，避免继承 backend token | `backend/internal/miscpkg/runtime_python.go` | 可关闭 P1-11 |
| MISC JS | 已禁用 `eval`、`Function`、`require`、`process`，并加权限门禁 | `backend/internal/miscpkg/runtime_javascript.go`、`module_loader.go` | 短期缓解完成；“独立进程沙箱”仍保留长期任务 |
| C2/stream decoder | 已修复 constant-time padding、lenient plaintext 误接收、raw payload dedupe 与资源上限 | `backend/internal/engine/c2_decrypt.go`、`stream_decoder.go` | 可关闭 P1-13，需保留密码学回归 |
| release smoke env | 已统一 `MEOW_TRAFFIC_RELEASE_SMOKE_CHECK` | `app.go`、`scripts/build_release_package.py` | 可关闭 P1-14 |
| 全局 ErrorBoundary | 已加入 App 根部 | `frontend/src/app/App.tsx`、`frontend/src/app/components/ErrorBoundary.tsx` | 可关闭 P2-11 |
| frontend `any` 清理 | 关键新增/测试债务已清理，lint/typecheck 已通过 | `frontend/src/app/integrations/bridgeFactory.test.ts` 等 | 继续以门禁防回归 |
| MCP endpoint 配置化 | 已新增 `backendEndpoint.ts` 统一 `VITE_BACKEND_URL` 派生逻辑；运行时设置页/MCP 面板不再写死 fallback endpoint | `frontend/src/app/integrations/backendEndpoint.ts`、`MCPSettingsSection.tsx`、`useRuntimeSettingsSidebarModel.ts` | P2-12 已完成当前批次实现，测试 fixtures 中的字面量不视为运行时硬编码 |
| 管理型请求取消 | object export 与 threat hunting workbench 已接入 `useAbortableRequest`，client/typed bridge 支持 `AbortSignal` | `frontend/src/app/features/object/useObjectExport.ts`、`frontend/src/app/features/hunting/useThreatHuntingWorkbench.ts` | P2-13 当前批次已覆盖 object/hunting；playbook/rule 继续沿既有计划追踪 |

尚不应关闭的项：

| ID | 问题 | 原因 | 下一步 |
|----|------|------|--------|
| P1-12 | MISC JS in-process 权限模型 | 当前是短期缓解，不是强隔离 | V2.5 设计独立子进程或 WASM/QuickJS sandbox |
| P2-8 | `sanitizeErrorMessage` 使用不统一 | 当前仅部分关键 handler 使用 | 增加 transport error sanitization 扫描与迁移 |
| P2-10 | SentinelContext 巨型 value | 已有子 hooks 基础，但未完成消费侧迁移 | 按页面分批迁移，不做一次性重写 |
| P2-12 | MCP endpoint 前端硬编码风险 | 运行时代码已集中到 `backendEndpoint.ts`；剩余匹配为测试 fixtures/断言 | 保持搜索门禁，禁止新增运行时硬编码 |
| P2-13 | 管理型 hook 取消能力 | object/hunting 已迁移；其余管理入口仍需持续核验 | useAbortableRequest 覆盖 playbook/rules 等剩余入口 |

## 2. V2 阶段设计

每个阶段必须按同一节奏推进：

1. **Design**：确认边界、风险、兼容策略、测试入口。
2. **Build**：小步修改，不跨阶段重构。
3. **Verify**：先跑模块测试，再跑相关集成测试。
4. **Evidence**：记录命令、文件、结论，更新 defect register。
5. **Gate**：未通过门禁不得进入下一阶段。

### Stage 0：基线冻结与审计索引

目标：固定 V2 起点，避免已修复内容和用户并行变更混淆。

| Phase | Task | 交付物 | Gate |
|-------|------|--------|------|
| 0.1 | 读取 `git status` 与关键 diff，标记非本轮变更 | 工作区变更清单 | 不回滚未知变更 |
| 0.2 | 对照 2026-06-20/06-21 审计报告建立 V2 缺陷表 | defect register 更新计划 | 每项必须有状态、证据、验收命令 |
| 0.3 | 明确工具链统一策略 | 更新 `docs/security-fix-playbook.md` S1 | tshark/ffmpeg/python/yara 同策略 |

### Stage 1：安全闭环 P1

目标：关闭可被利用或会阻断发布的 P1 项。

| Phase | Task | 关键文件 | 验收 |
|-------|------|----------|------|
| 1.1 | HTTP server timeout | `backend/internal/transport/http_server.go` | server timeout 单测或代码审查 + transport 测试 |
| 1.2 | constant-time token | `http_middleware.go` | `constantTimeTokenMatch` 单测覆盖相等、不同长度、空 token |
| 1.3 | CORS scheme/port | `http_helpers.go` | localhost 合法端口通过，非法 scheme/port 拒绝 |
| 1.4 | RuleManager SSRF/supply-chain | `rule_manager.go`、`rule_manager_security.go` | host allowlist、checksum 必填、不匹配拒绝、超大响应拒绝 |
| 1.5 | MISC Python env | `runtime_python.go` | `MEOW_TRAFFIC_BACKEND_TOKEN` 不出现在子进程 env |
| 1.6 | C2 crypto/resource | `c2_decrypt.go`、`stream_decoder.go` | padding constant-time、随机错误密文不产出伪明文、资源上限 |
| 1.7 | release smoke env | `app.go`、`build_release_package.py` | 变量名一致，release smoke 能触发同一逻辑 |

### Stage 2：工具链统一运行时

目标：满足用户要求：“工具链同一与 tshark 采用相同警告加快捷加白，不阻止工具运行”。

统一策略：

- 危险路径：硬拒绝。
- 合法但未在默认/用户允许目录中：返回 `path_warning`，保存和运行不断。
- 用户点击“加入白名单”：目录进入对应 `*AllowedDirs` 字段，重新探测后 warning 消失。
- 四类工具必须一致：tshark、ffmpeg、python、yara。

| Phase | Task | 关键文件 | 验收 |
|-------|------|----------|------|
| 2.1 | 后端通用 validator/runtime | `backend/internal/tool/validator.go`、`runtime.go` | 所有工具 Runtime 使用 `ModeWarn` |
| 2.2 | runtime config schema | `backend/internal/model/types_tools.go`、`frontend/src/app/core/types/tools.ts` | 四类工具均有 allowed dirs 字段 |
| 2.3 | generic allow-dir API | `backend/internal/transport/http_tool_handlers.go` | `/api/tools/allow-dir` 支持 ffmpeg/python/yara/tshark |
| 2.4 | 前端 warning UI 复用 | `TSharkPathAllowWarning.tsx`、`MediaSettingsSection.tsx`、`SpeechSettingsSection.tsx`、`YaraSettingsSection.tsx` | 三个非 tshark 工具也展示 warning + 加白按钮 |
| 2.5 | 持久化与启动同步 | `toolRuntimeStorageConfig.ts`、`backendLifecycleToolRuntimeStartup.ts` | allowed dirs 随用户配置保存并回放到后端 |

### Stage 3：MISC 运行时权限与隔离

目标：把“签名可信”升级为“能力最小化”。

| Phase | Task | 状态 | 验收 |
|-------|------|------|------|
| 3.1 | permissions 字段规范化 | 已实现 | 未声明默认 `exec.local`；未知权限拒绝 |
| 3.2 | `exec.local` 执行权限 | 已实现 | 无权限模块不能执行 |
| 3.3 | `capture.read` 抓包路径权限 | 已实现 | 未声明时不暴露 capture path |
| 3.4 | `host.scan` 扫描权限 | 已实现 | JS `ctx.scanFields()` / Python `scan_fields()` 无权限拒绝 |
| 3.5 | Python 最小环境 | 已实现 | 子进程无法读取 backend token |
| 3.6 | JS in-process 短期限制 | 已实现缓解 | `eval`、`Function`、`require`、`process` 不可用 |
| 3.7 | JS 独立进程沙箱设计 | 未完成 | 输出设计文档与 POC，不纳入当前短期关闭 |

### Stage 4：前端架构和治理

目标：继续降低状态耦合和类型债务，不破坏现有 Wails/浏览器双模式。

| Phase | Task | 验收 |
|-------|------|------|
| 4.1 | `any` 新增门禁 | `pnpm run lint` 0 warning；clients/wire/preload 不新增 `any` |
| 4.2 | hooks exhaustive-deps 策略 | 先开启审计清单，再分批修复，不一次性大改 |
| 4.3 | ErrorBoundary | 根部已接入，需补 fallback 行为测试 |
| 4.4 | SentinelContext 分批迁移 | 新代码使用子 context hooks；现有页面按模块迁移 |
| 4.5 | 管理型请求取消 | object export 与 threat hunting 已接入 abort signal；playbook/rules 继续按同一模式迁移 |
| 4.6 | MCP endpoint 配置化 | 运行时代码统一使用 `buildBackendEndpoint("/api/mcp")`，不再散落硬编码 fallback |

### Stage 5：CI、发布与长期门禁

目标：让修复变成自动化约束。

| Phase | Task | 验收 |
|-------|------|------|
| 5.1 | Go 漏洞扫描 | CI 运行 `govulncheck ./...` |
| 5.2 | Go 静态分析 | 引入 `staticcheck ./...` 或先以可复现本地命令进入 release gate |
| 5.3 | 前端依赖审计 | CI 运行 `pnpm audit --prod --audit-level=high` |
| 5.4 | 发布 smoke | release 脚本验证 `MEOW_TRAFFIC_RELEASE_SMOKE_CHECK` |
| 5.5 | 全量检查 | `./scripts/check-all.ps1` 通过 |

## 3. 测试矩阵

### 后端安全与架构

| Matrix ID | 范围 | 命令 | 通过标准 |
|-----------|------|------|----------|
| B-TLS-1 | transport timeout/auth/CORS | `cd backend; go test ./internal/transport -count=1` | 全部通过 |
| B-TOOL-1 | 工具路径 validator/runtime | `cd backend; go test ./internal/tool/... ./internal/engine -run "TestToolRuntime|TestValidateExecutablePath" -count=1` | warning/allowlist/hard reject 均覆盖 |
| B-TOOL-2 | tool API contract | `cd backend; go test ./internal/transport -run "TestRegisteredAPIRoutesHaveContractCases|TestHandleGenericToolAllowedDirs|TestToolRuntime" -count=1` | generic allow-dir 路由在 contract 中登记 |
| B-MISC-1 | MISC 签名/权限/runtime | `cd backend; go test ./internal/miscpkg/... -count=1` | 签名、权限、env、JS 限制全部通过 |
| B-C2-1 | C2/stream decoder crypto | `cd backend; go test ./internal/engine -run "TestC2Decrypt|TestStreamDecoder|TestPKCS7|TestDecryptAES" -count=1` | 无伪明文、padding 与 IV 回归通过 |
| B-RULE-1 | RuleManager | `cd backend; go test ./internal/engine -run "TestRule|TestDownloadPack|TestCheckForUpdates|TestReadLimited" -count=1` | SSRF、checksum、大小限制覆盖 |
| B-ARCH-1 | 架构边界 | `cd backend; go test ./internal/architecture -count=1` | 无新增越界 |
| B-FULL-1 | 后端全量 | `cd backend; go test ./...` | 全包通过 |
| B-RACE-1 | 关键 race | `cd backend; go test -race ./internal/engine/... ./internal/transport/... ./internal/tshark/... ./internal/miscpkg/...` | 无 race |

### 前端

| Matrix ID | 范围 | 命令 | 通过标准 |
|-----------|------|------|----------|
| F-TOOL-1 | Runtime settings UI | `cd frontend; pnpm run test:run -- RuntimeSettings TSharkPathAllowWarning toolRuntimeStorage toolRuntimeClient` | warning + 加白交互通过 |
| F-BRIDGE-1 | bridge/client/preload | `cd frontend; pnpm run test:run -- desktopBridge heavyWarmupPreload bridgeFactory` | Wails/browser 双通道不回归 |
| F-TYPE-1 | TypeScript | `cd frontend; pnpm run typecheck` | 0 error |
| F-LINT-1 | ESLint | `cd frontend; pnpm run lint` | 0 error、0 warning |
| F-TEST-1 | Vitest 全量 | `cd frontend; pnpm run test:run` | 全量通过 |
| F-CI-1 | 前端 CI bundle | `cd frontend; pnpm run ci` | package-manager/typecheck/lint/format/size/test/build 全通过 |
| F-AUDIT-1 | 前端依赖 | `cd frontend; pnpm audit --prod --audit-level=high` | 0 high |

### 全量与发布

| Matrix ID | 范围 | 命令 | 通过标准 |
|-----------|------|------|----------|
| R-ALL-1 | 本地全量 | `powershell -ExecutionPolicy Bypass -File ./scripts/check-all.ps1` | 全步骤通过 |
| R-ROOT-1 | 桌面 build tag | `go test -tags dev ./...` | root desktop tests 通过 |
| R-SMOKE-1 | release smoke env | `python scripts/build_release_package.py --skip-build` 或对应 CI job | smoke env 使用 `MEOW_TRAFFIC_RELEASE_SMOKE_CHECK` |

## 4. 重点验收标准

### 4.1 工具链统一策略验收

必须全部满足：

1. `tshark`、`ffmpeg`、`python`、`yara/yara64` 均使用同一个 validator/runtime 语义。
2. 合法绝对路径位于非默认可信目录时：
   - 后端不返回 400。
   - snapshot 中对应工具返回 `path_warning`。
   - 前端展示 warning 和“加入白名单”。
   - 工具运行不被 warning 阻止。
3. 点击“加入白名单”后：
   - 对应 `*AllowedDirs` 字段持久化。
   - 后端重新探测后 warning 消失。
   - 状态中可看到 `extra_allowed_dir` 或 allowed dir 结果。
4. 危险路径仍然硬拒绝：
   - `..\tool.exe`
   - `C:\tmp\evil.bat`
   - `C:\tmp\python.exe` 用作 ffmpeg
   - 目录路径
   - 不可访问文件
   - 符号链接到非法目标

### 4.2 MISC 验收

1. zip 导入和启动加载都验证签名。
2. production build 不允许 unsigned MISC。
3. Python 子进程不继承敏感 env。
4. JS/Python host bridge 均受 permissions 控制。
5. `capture.read` 未声明时，不暴露抓包路径。
6. `host.scan` 未声明时，扫描接口拒绝。

### 4.3 C2/密码学验收

1. AES-CBC 不使用全零 IV 或 key-as-IV。
2. PKCS7 padding 校验固定工作量，不因 padding 长度提前返回。
3. lenient unpad 不接受随机错误密文生成的任意明文。
4. candidate/frame/stream 均有数量与字节上限。
5. dedupe key 不保存原始 payload 大对象。

### 4.4 RuleManager 验收

1. packID 只允许安全字符。
2. cache path 必须位于 cacheDir 内。
3. URL scheme 仅允许 http/https。
4. host 必须在 allowlist 内。
5. checksum 必填且必须匹配。
6. 下载响应大小超过上限必须失败。

### 4.5 Transport 验收

1. HTTP server 设置 read/write/idle timeout。
2. auth token constant-time compare。
3. CORS 同时校验 scheme、host、port。
4. 新 handler 必须调用 `WithContext` 版本。
5. 新错误返回不得泄漏敏感本地路径。

## 5. 评估方案

V2 评分采用 100 分制，作为是否进入 release candidate 的依据：

| 维度 | 权重 | 评价方式 |
|------|------|----------|
| 安全缺陷关闭 | 35 | P1 必须关闭或降级有证据；P2 有计划与门禁 |
| 自动化测试 | 25 | 测试矩阵通过率与新增安全回归覆盖 |
| 架构边界 | 15 | backend architecture test、frontend boundary/lint 不回归 |
| 运行时体验 | 10 | 工具链 warning 不阻断运行，UI 可解释、可恢复 |
| 发布可靠性 | 10 | check-all、audit、govulncheck、release smoke |
| 文档与可追踪性 | 5 | defect register、playbook、阶段报告同步 |

Release candidate 门槛：

- 总分 ≥ 85。
- P1 无 open，P1-12 可作为 “mitigated + accepted residual risk” 但必须有后续沙箱设计 ticket。
- `cd backend; go test ./...` 通过。
- `cd frontend; pnpm run ci` 通过。
- `./scripts/check-all.ps1` 通过。
- `pnpm audit --prod --audit-level=high` 0 high。
- `govulncheck ./...` 通过或有已批准例外。

## 6. 开发规则与门禁

### 6.1 通用规则

- 不回滚未知工作区改动。
- 不把审计项关闭为 resolved，除非有代码证据和测试证据。
- 所有新增 HTTP handler 必须使用 `WithContext`。
- 所有外部二进制路径必须经过统一 validator/runtime。
- 所有用户路径必须 base-dir containment 校验，禁止只查 `..`。
- 所有 `http.Client` 必须有 timeout。
- 密码学实现不得使用硬编码 IV 或 key-as-IV。
- 前端不得新增 EventSource URL token、`useSentinel()` 调用或 clients 层 `any`。

### 6.2 子代理与测试协作规则

- 主代理负责代码审计、方案、风险归因和最终判断。
- 测试可以交给子代理执行，但一次只允许一个子代理。
- 子代理只能执行明确的测试矩阵命令并回传结果，不负责解释安全结论。
- 如果测试失败，主代理必须复核失败栈和相关代码后再给结论。

### 6.3 PR/提交门禁

| Gate | 要求 | 阻断条件 |
|------|------|----------|
| G0 工作区 | `git status` 已检查，未知改动未被回滚 | 覆盖用户改动 |
| G1 格式 | Go `gofmt -l .` 清空，前端 format check 通过 | 格式差异 |
| G2 单测 | 相关模块测试通过 | 目标模块失败 |
| G3 安全 | 对应安全回归测试通过 | P1/P2 修复无测试 |
| G4 架构 | architecture/boundary/lint 通过 | 新增越界 |
| G5 全量 | `check-all.ps1` 通过 | 任一步失败 |
| G6 文档 | playbook、defect register、阶段报告同步 | 状态与代码不一致 |

## 7. 当前执行结论

1. 后端全量已通过：`cd backend; go test ./...`。
2. 前端全量测试已通过：`cd frontend; pnpm run test:run`。
3. 前端 CI bundle 已通过：`cd frontend; pnpm run ci`。
4. 完整本地门禁已通过：`powershell -ExecutionPolicy Bypass -File ./scripts/check-all.ps1`。
5. 依赖安全扫描已完成：
   - `cd backend; govulncheck ./...` 通过；当前代码路径 0 个已调用漏洞，存在 1 个 imported-but-not-called 漏洞提示。
   - `cd frontend; pnpm audit --prod --audit-level=high` 退出码 0；0 high，仍有 1 个 low 漏洞提示。
6. 本轮继续实施项已完成：
   - allowed-dir 匹配语义改为“父级允许目录可解释子目录工具路径”，`extra_allowed_dir` 能返回实际命中的父级 allow-list 项。
   - allowed-dir 归一化拒绝根目录/盘符根目录，避免用户把整盘或系统根直接加白。
   - MCP endpoint fallback 统一到 `frontend/src/app/integrations/backendEndpoint.ts`。
   - `useObjectExport` 与 `useThreatHuntingWorkbench` 已接入 abortable request，取消/替换请求不会悬挂调用方 promise。
7. `docs/governance-defect-register.json` 暂不批量标记 resolved：
   - 当前 schema 的 resolved 证据要求 `closedByCommit`，本轮尚未产生提交，不能伪造 commit hash。
   - P1-7、P1-8、P1-9、P1-10、P1-11、P1-13、P1-14、P2-11 已具备代码和测试关闭条件，等待提交后补真实 `closedByCommit`。
   - P1-12 仍保持 open；当前实现只属于短期缓解，不等价于独立进程/强隔离 sandbox。
8. P2-8、P2-10 继续作为后续阶段任务；P2-12/P2-13 当前批次已有实质收敛，但仍保留搜索/迁移门禁防回归。

## 8. 已知验证记录

本轮已知已通过的定向验证：

- `cd backend; go test ./internal/miscpkg/... -count=1 -v`
- `cd backend; go test ./internal/miscpkg/... ./internal/engine ./internal/transport ./internal/tool/... -count=1`
- `cd backend; go test ./internal/engine -run "TestC2Decrypt|TestStreamDecoder|TestPKCS7|TestDecryptAES|TestToolRuntime|TestSetToolRuntime|TestRule|TestDownloadPack|TestCheckForUpdates|TestReadLimited" -count=1`
- `cd backend; go test ./internal/transport -run "TestRegisteredAPIRoutesHaveContractCases|TestHandleGenericToolAllowedDirs" -count=1 -v`
- `cd backend; go test ./internal/tool/... -count=1`
- `cd backend; go test ./internal/tool/... ./internal/architecture -count=1`
- `cd backend; go test ./internal/engine -run TestTSharkExtraAllowedDirForStatusMatchesAllowedDirScope -count=1`
- `cd backend; go test ./internal/transport -run TestRulesAPIContract -count=1 -v`
- `cd backend; go test ./internal/engine -count=1`
- `cd backend; go test ./internal/transport -count=1`
- `cd frontend; pnpm run lint`
- `cd frontend; pnpm run typecheck`
- `cd frontend; pnpm run test:run -- RuntimeSettings TSharkPathAllowWarning toolRuntimeStorage toolRuntimeClient desktopBridge heavyWarmupPreload`
- `cd frontend; pnpm run test:run -- useObjectExport useThreatHuntingWorkbench MCPSettingsSection toolRuntimeClient huntingClient objectClient`

本轮已完成的全量/门禁验证：

- `cd backend; go test ./...`：通过；最终复跑于 2026-06-23。
- `cd backend; go test ./internal/architecture -run TestBackendArchitectureBoundaries -count=1`：通过。
- `cd backend; govulncheck ./...`：通过；最终复跑于 2026-06-23，当前代码路径 0 个已调用漏洞，1 个 imported-but-not-called 漏洞提示。
- `cd frontend; pnpm run test:run -- useBackendLifecycle`：通过。
- `cd frontend; pnpm run test:run`：通过，282 个测试文件、936 个测试。
- `cd frontend; pnpm run typecheck`：通过。
- `cd frontend; pnpm run ci`：通过；最终复跑包含 282 个测试文件、938 个测试、Vite build。
- `cd frontend; pnpm audit --prod --audit-level=high`：最终复跑于 2026-06-23，退出码 0；0 high，1 low。
- `powershell -ExecutionPolicy Bypass -File ./scripts/check-all.ps1`：通过。
- `cd backend; gofmt -l .`：无输出，格式通过。
- `rg -n "銆|涓|鍔|宸|绛|杩|鍓|鍚|鏂|瀹|璇|�" docs/audit-development-report-archive-2026-06-23 frontend/src/app -g "*.md" -g "*.ts" -g "*.tsx"`：无匹配，未发现明显乱码。

非阻断提示：

- `pnpm` 仍提示 `package.json` 中的 `pnpm` 字段键会被忽略；该提示不影响 CI 结果。
