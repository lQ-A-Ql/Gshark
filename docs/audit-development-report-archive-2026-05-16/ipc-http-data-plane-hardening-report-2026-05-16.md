# Wails IPC / HTTP 混合数据面加固报告

- 作者：Codex
- 时间：2026-05-16 19:07:49 +08:00（Asia/Shanghai）
- 工作区：`C:\Users\QAQ\Desktop\gshark`

## 本轮目标

用户反馈“当前所有页面功能都失效”，并要求查明是否是 IPC 和 HTTP 不兼容导致。目标是实现《Wails IPC / HTTP 混合链路失效审计与修补计划》：修复 Wails 桌面环境下“后端 ready / health 成功，但页面 HTTP 数据面因为 token、origin、端口旧实例或请求 pending 而全部卡住”的链路级问题。

## 文档读取与评审

- `README.md`：已包含 Wails dev 缓存清理、runtime fast/full 探测、首屏 active load 和 page/status transport 说明。本轮追加了“Wails 不是全量 IPC、页面数据仍主要走 HTTP、`/health` 不等于页面 API 可用、HTTP token cache 不能缓存空/失败/pending 状态”的规则。
- `docs/README.md`：确认本地逐轮报告应放在 `docs/audit-development-report-archive-*`，当前事实要沉淀到根 README 或接口文档。本轮按规则追加本报告。
- `docs/audit-development-report-archive-2026-05-16/runtime-fast-full-probe-hardening-report-2026-05-16.md`：前序修复已经处理 runtime 探测慢快照和 IPC fallback，但没有覆盖所有页面 HTTP 数据面。
- `docs/audit-development-report-archive-2026-05-16/capture-first-screen-load-chain-hardening-report-2026-05-16.md`：前序修复已经让 capture status/page 数据面更可观测，但 C2、APT、工控、车机、USB、证据、对象、流、MISC 等页面仍大多走 HTTP fallback。

评审结论：前序文档方向正确，但把 runtime/capture 两条高频链路修好了以后，仍然缺少“全局 HTTP 数据面鉴权、超时、ready 门禁”的治理。当前“所有页面都在获取数据”更符合 HTTP token/readiness 失效，而不是 IPC 方法本身全量不兼容。

## 根因结论

这不是纯 IPC/HTTP wire 不兼容。真实断点是混合桥接模型中的 HTTP 数据面没有同等级保护：

- `createDesktopBridge()` 只覆盖少数 Wails IPC 方法，页面分析 API 仍继承 HTTP fallback。
- `/health` 无需鉴权，旧逻辑容易把端口在线误判为所有页面 API 可用。
- 页面 API 需要 bearer token，除非请求来自可信 `wails.localhost` origin。
- `httpBridge` 原先把首次 `GetBackendAuthToken()` 结果缓存为模块级 promise；若第一次读取发生在 binding 未就绪、返回空 token、抛错或长期 pending，后续所有 HTTP 页面请求都会复用坏状态。
- 普通页面请求原先没有统一超时；token promise 或 fetch pending 时，页面 hook 的 loading 可能长期保持 true。
- 本轮审阅还发现一个关键遗漏：`desktopBridge.isAvailable()` 仍直接返回 `IsBackendReady()`，会绕过新增的 HTTP data-plane readiness。这个点已在本轮补上。

## 修改摘要

### HTTP token / request 层

- `frontend/src/app/integrations/httpBridge.ts`
  - 新增 `BackendRequestError` 和错误码：`auth_failed`、`token_unavailable`、`token_timeout`、`backend_unreachable`、`request_timeout`、`backend_error`、`old_or_incompatible_backend`。
  - `getBackendAuthToken()` 不再缓存空 token。
  - `GetBackendAuthToken()` 抛错或超时后清空 token promise，允许后续 Wails binding ready 后恢复。
  - Wails token 读取增加 1500ms 超时，避免页面无限等待 token 初始化。
  - 401 后清空 token cache，并在可刷新 auth 的情况下重试一次，避免无限 retry。
  - HTTP 请求增加统一超时：普通请求 15s，分析/POST/对象/流/证据/统计类 30s，下载/导出/播放/转写类 60s。
  - 保留 caller `AbortSignal` 语义；用户侧取消仍保持 `AbortError`。
  - 成功 JSON 对象附加非枚举 `__backendRequestMeta`，记录 `transport=http-fallback`、endpoint、duration、authState、status。

### 后端可用性门禁

- `frontend/src/app/integrations/clients/desktopClient.ts`
  - `isAvailable()` 从单 `/health` 升级为 data-plane readiness：依次探测 `/health`、`/api/runtime/identity`、`/api/capture/status`。
  - data-plane 失败时记录 `lastBackendReadinessError`，错误文案明确为“后端端口在线，但 HTTP 数据面不可用”。

- `frontend/src/app/integrations/desktopBridge.ts`
  - 修复关键绕过：Wails `IsBackendReady()` 只代表后端进程 ready。现在 `IsBackendReady()` 为 false 时直接不可用；为 true 时还必须调用 HTTP fallback 的 `isAvailable()`，通过 token/identity/status 探针后才认为后端可用。

- `frontend/src/app/state/hooks/backendUnavailableStatus.ts`
  - 优先展示 `lastBackendReadinessError`，让启动页/状态区能看到 token、401、timeout、旧后端等真实 data-plane 错误。

### 测试

- `frontend/src/app/integrations/httpBridge.test.ts`
  - 覆盖空 token 不缓存、rejected promise 不缓存、pending token 1500ms 超时、401 清缓存并重试一次、HTTP pending 请求超时。
- `frontend/src/app/integrations/clients/desktopClient.test.ts`
  - 覆盖 `/health` 成功但 data-plane 探针失败时不可用。
- `frontend/src/app/integrations/desktopBridge.test.ts`
  - 覆盖 Wails `IsBackendReady()` 不能单独放行，必须通过 HTTP data-plane probe。
  - 覆盖 Wails 后端未 ready 时不打 HTTP data-plane 探针。
- `frontend/src/app/features/c2/useC2Analysis.test.tsx`
  - 覆盖页面数据请求超时后 loading 退出并展示错误。

## 验证记录

### Frontend focused

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec vitest run src/app/integrations/httpBridge.test.ts src/app/integrations/clients/desktopClient.test.ts src/app/features/c2/useC2Analysis.test.tsx src/app/integrations/bridgeFactory.test.ts src/app/integrations/desktopBridge.test.ts
```

结果：5 个测试文件 / 30 个测试通过。

### Frontend CI

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec tsc --noEmit --pretty false
pnpm run lint
pnpm run ci
pnpm run build:wails
```

结果：

- TypeScript 通过。
- ESLint 通过。
- `pnpm run ci` 通过：package manager、typecheck、lint、format、size、boundary、client/mapper/wire any、Wails binding、Vitest、Vite build 全部通过。
- CI 中 Vitest 结果：219 个测试文件 / 665 个测试通过。
- `pnpm run build:wails` 通过，并输出 `Desktop asset check: ok`。

### Backend / Root

```powershell
cd C:\Users\QAQ\Desktop\gshark\backend
gofmt -l .
go test ./...

cd C:\Users\QAQ\Desktop\gshark
go test -tags dev ./...
go test -tags production ./...
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1
git diff --check
```

结果：

- `gofmt -l .` 无输出。
- `go test ./...` 通过全部 backend 包。
- root `go test -tags dev ./...` 通过。
- root `go test -tags production ./...` 通过。
- 桌面资产检查通过：`Desktop asset check: ok`。
- `git diff --check` 无输出。

### Wails visual smoke

未在本轮自动化中启动长驻 `start-wails-dev.ps1 -CleanGoCache` GUI smoke。原因：该脚本会进入长驻 `wails dev` 会话并打开桌面窗口，当前交付以 CLI 门禁、Wails build、asset check、bridge/data-plane focused tests 作为证据。后续人工 smoke 建议执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark
powershell -ExecutionPolicy Bypass -File .\scripts\start-wails-dev.ps1 -CleanGoCache
```

人工验收重点：

- 启动页不再只因 `/health` 成功显示假连接。
- 若 token 或 data-plane 探针失败，显示“HTTP 数据面不可用”及具体原因。
- 打开 PCAP 后进入 C2 / 工控 / USB / 证据 / 流量图等页面，请求要么返回数据，要么在超时预算内退出 loading 并显示 endpoint/token/timeout 错误。

## Phase 评分

用户计划里的 phase 分值合计为 110 分。为便于按“总分 100”理解，下面同时给出原始分和折算分。

| Phase | 原始得分 | 说明 |
|---|---:|---|
| Phase 0：复现与链路固定 | 7 / 8 | 完成 git/docs/代码链路审计；未做 live Wails GUI endpoint 复现 |
| Phase 1：HTTP token 缓存语义 | 24 / 24 | 空 token、rejected、pending、401 retry、late binding 恢复均有测试 |
| Phase 2：HTTP 超时与错误分类 | 20 / 20 | requestJSON/requestBlob 统一超时，错误分类可见，caller abort 保留 |
| Phase 3：IPC / HTTP 诊断 | 12 / 16 | 成功 payload 有 metadata，readiness 错误可见；尚未做完整全局 UI 诊断面板 |
| Phase 4：data-plane readiness | 14 / 14 | `/health` 不再单独放行；Wails `IsBackendReady()` 也必须通过 HTTP probe |
| Phase 5：页面 loading 硬化 | 12 / 14 | 全局 bridge 超时覆盖所有页面；C2 hook focused test 覆盖 loading 退出，未逐页新增 hook 测试 |
| Phase 6：测试、smoke 与报告 | 12 / 14 | CI/backend/root/build:wails/report 完成；未执行长驻 GUI smoke |

原始总分：101 / 110。折算百分制：91.8 / 100，接近 Gold；若人工 Wails GUI smoke 通过，可视为 Gold 交付。严格按“92 以上 Gold”门槛，本轮处于高 Silver / 准 Gold。

## 自迭代记录

1. 现象：所有页面卡在获取数据，但 runtime/capture 高优先级 IPC 链路已有前序修复。
2. 分类：混合桥接中 HTTP data-plane auth/readiness/timeout 失效。
3. Patch 1：修 `httpBridge` token cache、token timeout、401 retry、request timeout。
4. Verify 1：focused tests 初步通过。
5. 再审计发现：`desktopBridge.isAvailable()` 仍绕过 HTTP readiness，只信 `IsBackendReady()`。
6. Patch 2：Wails ready 后继续调用 fallbackBridge.isAvailable()；Wails not ready 时跳过 HTTP probe。
7. Verify 2：focused tests、typecheck、lint、frontend CI、backend tests、root tags、build:wails、asset check 全部通过。

## 剩余风险

- 还没有完整的全局 UI 诊断面板来展示每个页面最近一次 endpoint、duration、authState、status。当前页面会显示错误消息，成功对象带非枚举 metadata，但 UI 尚未集中呈现。
- `EventSource` 仍使用 query token 连接 SSE；本轮没有重构 SSE 诊断，只通过 token read timeout 避免初始化永久 pending。
- 未自动执行 Wails GUI smoke，仍建议用户用 `start-wails-dev.ps1 -CleanGoCache` 做真实窗口验收。
- 如果某个后端分析 handler 本身长时间计算超过 30s，页面会明确 timeout 而不是无限 loading；后续可按具体 endpoint 调整长任务模型或进度 API。

