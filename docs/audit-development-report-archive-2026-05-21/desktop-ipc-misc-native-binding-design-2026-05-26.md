# Desktop IPC MISC native binding design round

- Author: Codex
- Time: 2026-05-26 02:08:54 +08:00
- Round: 12
- Primary domain: MISC multipart native binding design

## 迁移域与目标

本轮只做设计与库存 guardrail，不改变 runtime transport。目标是明确 MISC package 剩余 generic IPC 兼容面的真实边界，设计后续 typed DesktopApp 方法形态，并防止新 MISC generic route 静默扩散。

## 修改面清单

- 新增 `docs/desktop-ipc-misc-native-binding-design.md`。
- 新增 `frontend/scripts/check-desktop-misc-compat-inventory.mjs`。
- 新增 `frontend/scripts/check-desktop-misc-compat-inventory.test.mjs`。
- `frontend/package.json` 新增 `desktop-misc-compat:check` 并接入 `pnpm run ci`。
- 更新 `docs/desktop-ipc-iteration-status.json`，新增 `miscMultipartCompatibility` 设计状态、当前路由、建议 typed 方法和 Round 12 score。
- 更新 `docs/desktop-ipc-migration-plan.md`，追加 Round 12 状态和开发记录。

## Focused test 结果

- `node frontend/scripts/check-desktop-misc-compat-inventory.mjs`: passed.
- `cd frontend && pnpm exec vitest run scripts/check-desktop-misc-compat-inventory.test.mjs scripts/check-desktop-generic-ipc-allowlist.test.mjs scripts/check-desktop-old-binding-compat.test.mjs src/app/integrations/clients/toolClient.test.ts src/app/integrations/ipcBackendTransport.test.ts`: passed, 5 files / 33 tests.

## Full gate 结果

- `go test -tags dev ./...`: passed.
- `go test -tags production ./...`: passed.
- `cd backend && go test ./...`: passed.
- `cd frontend && pnpm run ci`: passed, 231 files / 726 tests.
- `cd frontend && pnpm run build:wails`: passed.
- `powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1`: passed.
- `node frontend/scripts/check-wails-bindings.mjs`: passed.
- `node frontend/scripts/check-desktop-transport-policy.mjs`: passed.
- `node frontend/scripts/check-desktop-generic-ipc-allowlist.mjs`: passed.
- `node frontend/scripts/check-desktop-old-binding-compat.mjs`: passed.
- `node frontend/scripts/check-desktop-misc-compat-inventory.mjs`: passed.
- `powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1`: passed.
- `git diff --check`: passed.

## 桌面/浏览器行为差异说明

- Desktop release: MISC import/delete/invoke 仍是 explicit generic IPC compatibility；本轮仅新增设计与库存检查。
- Desktop dev: 保留当前 MISC generic IPC 行为，便于调试动态 module packages。
- Browser dev: HTTP multipart/SSE 不变，smoke 通过。

## 评分

- Contract Correctness: 24/25。设计明确 typed method shape 与错误分层，但本轮不实现 runtime typed DTO。
- Desktop Policy Compliance: 20/20。新增 MISC inventory guardrail 防止 generic MISC route 扩散。
- Regression Safety: 20/20。focused tests、full CI、root/backend tests、build:wails、smoke 均通过。
- Diagnostics and Failure Shape: 14/15。文档定义 business error、IPC transport error、compat fallback；runtime 错误形态未改变。
- Docs and Traceability: 10/10。tracker、计划、设计文档、归档报告同步。
- Dev/Browser Compatibility: 8/10。browser-dev smoke 通过；未做完整人工 UI 操作。
- Total: 96/100。

## Open blockers

- 无硬阻塞。
- import/delete/invoke 的 runtime typed 迁移需要隔离临时 MISC package dir，避免 smoke 或测试污染用户本地插件状态。

## 自迭代记录

本轮根据 Round 11 自动建议推进 MISC 设计切片。实现时没有直接新增 typed runtime binding，因为 zip upload 与动态 package route 如果直接映射到 JSON/base64，会放大 Wails IPC payload 和错误诊断风险。当前更安全的下一步是先迁移非变更性 `ListMiscModules`，再单独处理 import/delete/invoke。

本轮得分 `>= 90` 且无硬阻塞，按规则可以进入下一轮。

## 下一轮自动建议

进入 `MISC ListMiscModules typed IPC`：新增 root DesktopApp typed method、frontend typed override、binding check、transport policy mapping 和 contract tests。保持 import/delete/invoke explicit compatibility。

## 预期结果

- MISC generic IPC 兼容库存变成机器可检查事实。
- MISC runtime 迁移有明确 typed method shape 和错误分层。
- 下一轮可以从非 mutating list 接口安全切入，不污染用户本地插件状态。
