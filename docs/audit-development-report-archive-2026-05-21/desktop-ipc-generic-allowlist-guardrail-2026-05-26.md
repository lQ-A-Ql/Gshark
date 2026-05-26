# Desktop IPC generic allowlist guardrail round

- Author: Codex
- Time: 2026-05-26 01:53:12 +08:00
- Round: 10
- Primary domain: generic IPC allowlist guardrail

## 迁移域与目标

本轮不新增 typed 业务绑定，目标是收紧 post-phase generic IPC 兼容窗口：前端 client 层新增 `/api/...` 字符串接线时，必须被归类为已迁移 typed 路由或显式兼容路由。MISC multipart/import/invoke/delete/list 保持兼容，不在本轮强行改成 typed JSON。

## 修改面清单

- 新增 `frontend/scripts/check-desktop-generic-ipc-allowlist.mjs`。
- 新增 `frontend/scripts/check-desktop-generic-ipc-allowlist.test.mjs`。
- `frontend/package.json` 新增 `desktop-generic-ipc:check` 并接入 `pnpm run ci`。
- `docs/desktop-ipc-iteration-status.json`、`docs/desktop-ipc-migration-plan.md` 在后续 Round 11 文档闭环中同步更新。

## Focused test 结果

- `node frontend/scripts/check-desktop-generic-ipc-allowlist.mjs`: passed.
- `cd frontend && pnpm exec vitest run scripts/check-desktop-generic-ipc-allowlist.test.mjs src/app/integrations/ipcBackendTransport.test.ts src/app/integrations/desktopBridge.test.ts`: passed, 3 files / 41 tests.

## Full gate 结果

- `go test -tags dev ./...`: passed.
- `go test -tags production ./...`: passed.
- `cd backend && go test ./...`: passed.
- `cd frontend && pnpm run ci`: passed, 229 files / 720 tests.
- `cd frontend && pnpm run build:wails`: passed.
- `powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1`: passed.
- `node frontend/scripts/check-wails-bindings.mjs`: passed.
- `node frontend/scripts/check-desktop-transport-policy.mjs`: passed.
- `node frontend/scripts/check-desktop-generic-ipc-allowlist.mjs`: passed.
- `powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1`: passed.
- `git diff --check`: passed.

## 桌面/浏览器行为差异说明

- Desktop release: 已迁移 typed 路由不能通过 generic IPC 静默扩散；新增 client 路由字面量必须先分类。
- Desktop dev: 保留 MISC multipart/import/invoke/delete/list 的 generic IPC 兼容。
- Browser dev: HTTP/SSE 继续可用，本轮未改变 browser HTTP transport。

## 评分

- Contract Correctness: 24/25。allowlist 覆盖当前 typed 路由与显式兼容路由，但仍不是 typed DTO 合约迁移。
- Desktop Policy Compliance: 20/20。新增静态 gate 阻止非 MISC generic IPC 扩散。
- Regression Safety: 20/20。focused tests、full CI、root/backend tests、build:wails、smoke 均通过。
- Diagnostics and Failure Shape: 14/15。脚本错误明确要求新增 typed binding 或显式兼容；运行期错误形态未变。
- Docs and Traceability: 10/10。tracker、计划、归档报告同步。
- Dev/Browser Compatibility: 8/10。browser-dev smoke 通过；本轮未覆盖全部手工 UI 路径。
- Total: 96/100。

## Open blockers

- 无硬阻塞。
- MISC multipart/import/invoke/delete/list 仍是显式 compatibility，不应在没有 native upload/invoke 设计前强行迁移。

## 自迭代记录

本轮得分 `>= 90` 且无硬阻塞，按规则可以进入下一轮。自动决策为继续 generic IPC 收口，但不跨到多域迁移；下一轮优先处理 old generated binding compatibility 窗口，避免新代码直接读取旧 DesktopApp binding。

## 下一轮自动建议

进入 `old generated binding compatibility guardrail`：梳理允许直接访问旧 DesktopApp binding 的文件和方法，新增 CI 检查，禁止生产 integration client 直接新增 data-plane 旧 binding 入口。

## 预期结果

- 每个 client `/api` route literal 都能被机器判定为 typed migrated 或 explicit compatibility。
- generic IPC 从默认路径进一步降级为显式例外。
- 桌面 WebView typed smoke 继续保持 `directBackendApiRequestCount = 0`。
