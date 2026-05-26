# Desktop IPC old generated binding compatibility guardrail round

- Author: Codex
- Time: 2026-05-26 02:01:20 +08:00
- Round: 11
- Primary domain: old generated binding compatibility guardrail

## 迁移域与目标

本轮不删除旧 generated binding，也不迁移 MISC multipart。目标是把旧 DesktopApp binding 的直接使用范围收缩为机器可检查的 compatibility allowlist，防止新增桌面数据面功能绕过 `desktopBridge` / `desktopTypedBridge*`。

## 修改面清单

- 新增 `frontend/scripts/check-desktop-old-binding-compat.mjs`。
- 新增 `frontend/scripts/check-desktop-old-binding-compat.test.mjs`。
- `frontend/package.json` 新增 `desktop-old-binding:check` 并接入 `pnpm run ci`。
- 更新 `docs/desktop-ipc-iteration-status.json`，新增 `oldGeneratedBindings` guarded 状态、allowlist、exit criteria、Round 11 score。
- 更新 `docs/desktop-ipc-migration-plan.md`，追加 Round 10 / Round 11 状态和开发记录。

## Focused test 结果

- `node frontend/scripts/check-desktop-old-binding-compat.mjs`: passed.
- `cd frontend && pnpm exec vitest run scripts/check-desktop-old-binding-compat.test.mjs scripts/check-desktop-generic-ipc-allowlist.test.mjs src/app/integrations/desktopBridge.test.ts src/app/integrations/ipcBackendTransport.test.ts`: passed, 4 files / 44 tests.

## Full gate 结果

- `go test -tags dev ./...`: passed.
- `go test -tags production ./...`: passed.
- `cd backend && go test ./...`: passed.
- `cd frontend && pnpm run ci`: passed, 230 files / 723 tests.
- `cd frontend && pnpm run build:wails`: passed.
- `powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1`: passed.
- `node frontend/scripts/check-wails-bindings.mjs`: passed.
- `node frontend/scripts/check-desktop-transport-policy.mjs`: passed.
- `node frontend/scripts/check-desktop-generic-ipc-allowlist.mjs`: passed.
- `node frontend/scripts/check-desktop-old-binding-compat.mjs`: passed.
- `powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1`: passed.
- `git diff --check`: passed.

## 桌面/浏览器行为差异说明

- Desktop release: typed data-plane remains owned by `desktopBridge.ts` and `desktopTypedBridge*.ts`; old generated binding direct use is limited to shell/auth/dialog/generic-adapter compatibility.
- Desktop dev: generic IPC adapter remains available only through `ipcBackendTransport.ts` and existing route allowlists.
- Browser dev: HTTP/SSE remains unchanged and passed smoke.

## 评分

- Contract Correctness: 24/25。compat allowlist 定义清晰，但本轮不新增 typed DTO。
- Desktop Policy Compliance: 20/20。生产 integration client 不能新增未批准的旧 DesktopApp data-plane binding。
- Regression Safety: 20/20。focused tests、full CI、root/backend tests、build:wails、smoke 均通过。
- Diagnostics and Failure Shape: 14/15。脚本错误能直接指出未批准旧 binding 与修复方向。
- Docs and Traceability: 10/10。tracker、计划、归档报告同步。
- Dev/Browser Compatibility: 8/10。browser-dev smoke 通过；未覆盖完整人工 UI 操作。
- Total: 96/100。

## Open blockers

- 无硬阻塞。
- MISC multipart/import/invoke/delete/list 仍待 native binding 设计，不建议直接删除 generic IPC 兼容。

## 自迭代记录

本轮初次脚本运行发现 `ipcBackendTransport.ts` 作为 generic IPC adapter 被过度拦截。修正策略为只允许 `InvokeBackendJSON/Blob/Text` 出现在这个单一 adapter 文件，避免误伤兼容路径，同时仍禁止其它 client 直接新增旧 binding data-plane 调用。修正后 focused tests、CI 和 smoke 全部通过。

本轮得分 `>= 90` 且无硬阻塞，按规则可以进入下一轮。自动决策为继续 MISC multipart native-binding design spike；在设计未完成前，MISC 保持 explicit compatibility。

## 下一轮自动建议

进入 `MISC multipart native-binding design spike`：先做接口设计和合约边界，不直接改运行时 transport。需要明确文件上传、动态 package id 路由、invoke JSON payload、delete、返回 blob/text 的 typed DesktopApp 方法形态，并给出是否值得迁移的判定标准。

## 预期结果

- 旧 generated binding 兼容窗口不再依赖人工约定。
- 新数据面功能必须走 `desktopBridge` / typed override / 明确 generic compatibility。
- 桌面 WebView typed smoke 继续保持 `directBackendApiRequestCount = 0`。
