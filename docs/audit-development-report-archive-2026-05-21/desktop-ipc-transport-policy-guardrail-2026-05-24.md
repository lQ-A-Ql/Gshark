# Desktop IPC Phase 5 transport policy guardrail 报告

## 本轮目标

按上一轮 tracker 的自主建议进入 Phase 5 小切片：新增自动化 guardrail，防止已 typed IPC 覆盖的桌面域在后续迭代中回流到 generic `/api/...` 字符串接线或 `InvokeBackend*` 代理调用。

本轮只做一个主域：

- 主域：generic IPC 收口 guardrail。
- 附带收口：将 guardrail 接入 `pnpm run ci`，让后续 CI 自动阻断回流。

## 阅读与评审输入

本轮先读取并对照：

- `docs/desktop-ipc-migration-plan.md`
- `docs/desktop-ipc-iteration-status.json`
- `frontend/package.json`
- `frontend/scripts/check-wails-bindings.mjs`
- `frontend/src/app/integrations/desktopBridge.ts`
- `frontend/src/app/integrations/ipcBackendTransport.ts`
- `frontend/src/app/integrations/bridgeFactory.test.ts`
- `frontend/src/app/integrations/httpBridgeAggregation.test.ts`

### 文档评审结论

- tracker 上一轮结论正确：typed IPC baseline 已通过机器门禁，但 Phase Audit 手工 smoke 未归档，因此不能关闭 Phase Audit。
- Phase 5 的自动化 guardrail 可以独立推进，因为它不伪造 smoke 结论，只增强后续代码回流防护。
- `desktopBridge.ts` 仍需要保留 generic IPC fallback 组合能力；guardrail 不应误杀该兼容层。
- 真正需要禁止的是 `desktopTypedBridge*` typed override 文件中直接出现 `/api/...` 路径或 `InvokeBackend*` 调用。

## 实际改动

### 1. 新增 desktop transport policy 检查脚本

新增 `frontend/scripts/check-desktop-transport-policy.mjs`，检查内容：

- typed desktop override 文件不得直接写 `/api/...` 或 `127.0.0.1:17891/api/...` 字符串。
- typed desktop override 文件不得直接调用 `InvokeBackendJSON`、`InvokeBackendBlob`、`InvokeBackendText`。
- `desktopTypedBridgeCore.ts` 必须为已迁移 bridge method 提供 `typedBindingRequirements` 映射。
- typed bridge 文件必须实际调用对应 `DesktopApp.<TypedMethod>!`，避免“声明了 typed requirement 但实现仍落在 generic bridge”。

脚本刻意允许：

- `desktopBridge.ts` 继续组合 `createIpcBackendTransport`，作为未迁移域和兼容窗口的 fallback。
- HTTP client 文件继续保留 `/api/...`，用于 browser/dev 和普通 HTTP fallback。
- MISC multipart/import 继续通过 generic IPC compatibility path。

### 2. 新增脚本单测

新增 `frontend/scripts/check-desktop-transport-policy.test.mjs`，覆盖：

- typed DesktopApp 方法调用通过。
- typed override 文件中直接 `/api/...` 失败。
- typed override 文件中 `InvokeBackend*` 失败。
- `desktopBridge.ts` 组合 generic fallback 不失败。
- missing typed requirement / missing typed call 失败。

### 3. 接入前端 CI

更新 `frontend/package.json`：

- 新增 `desktop-transport-policy:check`。
- `pnpm run ci` 在 `wails-binding:check` 之后运行 `desktop-transport-policy:check`。

### 4. 文档与 tracker 同步

- 更新 `docs/desktop-ipc-migration-plan.md`：Phase 5 改为 `machine_validated_audit_pending`，说明 guardrail 已落地。
- 更新 `docs/desktop-ipc-iteration-status.json`：currentRound 改为 2，lastRound 记录 Phase 5 guardrail 评分、验证和下一轮建议。

## 验证结果

Focused tests 已通过：

```powershell
cd frontend; pnpm run desktop-transport-policy:check
cd frontend; pnpm exec vitest run scripts/check-desktop-transport-policy.test.mjs src/app/integrations/desktopBridge.test.ts src/app/integrations/bridgeFactory.test.ts src/app/integrations/ipcBackendTransport.test.ts
```

Focused 结果：

- `desktop-transport-policy:check`：通过。
- Vitest focused：`4` 个测试文件 / `38` 个测试通过。

Full gates 已通过：

```powershell
cd frontend; pnpm run ci
cd frontend; pnpm run build:wails
go test -tags dev ./...
go test -tags production ./...
cd backend; go test ./...
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1
node frontend/scripts/check-wails-bindings.mjs
git diff --check
```

结果摘要：

- Frontend CI：通过，`228` 个测试文件 / `707` 个测试通过；新增 desktop transport policy check 已在 CI 链中执行。
- `build:wails`：通过，桌面后端 exe 已重新嵌入 `frontend/dist`。
- Root Go dev tests：通过。
- Root Go production tests：通过。
- Backend Go tests：通过。
- Desktop asset check：通过。
- Wails binding group check：通过。
- `git diff --check`：通过。

注意事项：

- `pnpm run ci` 的普通 Vite build 会刷新 `frontend/dist`，导致 root `go test -tags dev ./...` 在 `build:wails` 之前缺少 `frontend/dist/sentinel-backend.exe`。本轮按正确顺序在 CI 后执行 `build:wails`，再复跑 root dev/production 测试并通过。

## 评分

本轮评分：`94 / 100`

- Contract Correctness：`23 / 25`。guardrail 能校验 typed requirement 与 typed call 对齐；仍基于静态正则，不能证明运行时真实桌面 DevTools network 行为，扣 2 分。
- Desktop Policy Compliance：`20 / 20`。已阻止 typed override 文件回流 `/api/...` 或 `InvokeBackend*`。
- Regression Safety：`20 / 20`。focused、frontend CI、root dev/production、backend、build:wails、asset、binding、diff check 均通过。
- Diagnostics and Failure Shape：`14 / 15`。违规输出包含文件行号和具体原因；尚未覆盖所有 generic compatibility 路径白名单解释，扣 1 分。
- Docs and Traceability：`10 / 10`。plan、tracker、本地 report 已同步。
- Dev/Browser Compatibility：`7 / 10`。脚本刻意保留 HTTP client 和 `desktopBridge` generic fallback；但 browser-dev 手工 smoke 仍未跑，扣 3 分。

Hard blockers：无。

Audit blocker：Phase Audit 桌面/browser-dev 手工 smoke 仍未归档。

## 自迭代记录

- 机器门禁结论：Phase 5 guardrail 通过，可进入下一 round。
- 自主决策：由于 open blocker 仍是 Phase Audit 手工 smoke，下一轮不得继续扩大新 typed 域，应先补 smoke 证据并关闭 audit pending。
- 误报修正：初版 guardrail 把 `desktopBridge.ts` 的 fallback composition 误判为违规；已调整为只检查 `desktopTypedBridge*` typed override 文件，并新增单测固定该例外。
- 顺序修正：`pnpm run ci` 会覆盖 `frontend/dist`，root build-tag 测试应在 `build:wails` 之后执行。

## 下一轮自动建议

优先级：

1. 执行 Phase Audit 桌面 Wails smoke：打开 PCAP、packet page、HTTP/TCP stream、analysis、evidence filter、object/tooling 页，并观察 migrated domains 不再作为 WebView 直接请求 `/api/...`。
2. 执行 browser-dev smoke：确认 HTTP/SSE 正常，desktop typed IPC policy 未误伤 dev 调试。
3. Smoke 通过后，把 `docs/desktop-ipc-migration-plan.md` 和 `docs/desktop-ipc-iteration-status.json` 中 Phase 1-5 改为 completed。
4. 再进入下一个小切片：收窄 remaining generic IPC compatibility path，仅保留 MISC multipart/import、未迁移边缘接口和旧 binding 兼容。

署名：Codex
时间：2026-05-24 22:34:02 +08:00
