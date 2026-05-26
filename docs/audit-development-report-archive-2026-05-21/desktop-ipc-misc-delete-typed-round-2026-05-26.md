# Desktop IPC Round 15 - MISC DeleteMiscModulePackage typed IPC

- Author: Codex
- Time: 2026-05-26 03:06:32 +08:00
- Phase: post-phase-5
- Primary slice: `DeleteMiscModulePackage` typed IPC

## 迁移域与目标

本轮只迁移一个主域切片：MISC package delete。

目标：

- 新增 `DesktopApp.DeleteMiscModulePackage(id string)` typed binding。
- 桌面路径优先走 typed IPC。
- 当 typed binding 已存在时，`DELETE /api/tools/misc/packages/{id}` generic IPC 被 runtime guard 拒绝。
- browser-dev 继续保留 HTTP 调试路径。
- smoke 只验证 binding 可用，不执行破坏性删除。

未纳入本轮：

- 不迁移 `RunMiscModulePackage`。
- 不迁移 multipart import。
- 不改变 MISC package zip 上传策略。

## 修改面清单

- `desktop_backend_proxy.go`: 新增 `DeleteMiscModulePackage` typed DesktopApp method，经 backend proxy 执行现有 delete route。
- `desktop_typed_bindings_test.go`: 覆盖 `DELETE /api/tools/misc/packages/demo.module` 合约路由。
- `frontend/src/app/integrations/desktopTypedBridgeMisc.ts`: `deleteMiscModule` 走 `DesktopApp.DeleteMiscModulePackage`。
- `frontend/src/app/integrations/ipcBackendTransport.ts`: typed binding 存在时拦截 delete route 的 generic IPC。
- `frontend/src/app/integrations/desktopTransportBinding*.ts`: 将 Wails binding 类型面拆成 shell/control/stream/tooling/analysis 分片，避免单文件继续膨胀。
- `frontend/src/app/integrations/desktopTypedBridgeRequirements.ts`: 将 bridge method -> Wails binding requirement 从 core 中拆出。
- `frontend/scripts/check-wails-bindings.mjs`: 支持拆分后的 binding type 文件，同时保持分组完整性检查。
- `frontend/scripts/check-desktop-generic-ipc-allowlist.mjs`: 将 package delete route 标为 migrated typed route。
- `frontend/scripts/check-desktop-misc-compat-inventory.mjs`: MISC inventory 更新为 list/delete typed，import/invoke compatibility。
- `frontend/src/app/desktopWebviewSmoke.ts` 与 `scripts/check-desktop-ipc-smoke.ps1`: 验证 `DeleteMiscModulePackage` binding 可用，保持非破坏性 smoke。
- `frontend/wailsjs/go/main/DesktopApp.d.ts` 与 `DesktopApp.js`: 更新 generated binding stub。

## focused test 结果

通过：

- `go test -tags dev ./...`
- `cd frontend && pnpm run typecheck`
- `cd frontend && pnpm run size:check`
- `cd frontend && pnpm exec vitest run src/app/integrations/desktopBridge.test.ts src/app/integrations/ipcBackendTransport.test.ts src/app/integrations/clients/toolClient.test.ts scripts/check-desktop-misc-compat-inventory.test.mjs scripts/check-desktop-generic-ipc-allowlist.test.mjs scripts/check-desktop-transport-policy.test.mjs`
- `node frontend/scripts/check-wails-bindings.mjs`
- `node frontend/scripts/check-desktop-transport-policy.mjs`
- `node frontend/scripts/check-desktop-generic-ipc-allowlist.mjs`
- `node frontend/scripts/check-desktop-old-binding-compat.mjs`
- `node frontend/scripts/check-desktop-misc-compat-inventory.mjs`
- `git diff --check`

Focused Vitest result: 6 files / 60 tests passed.

## full gate 结果

通过：

- `go test -tags dev ./...`
- `go test -tags production ./...`
- `cd backend && go test ./...`
- `cd frontend && pnpm run ci`
- `cd frontend && pnpm run build:wails`
- `powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1`
- `node frontend/scripts/check-wails-bindings.mjs`
- `node frontend/scripts/check-desktop-transport-policy.mjs`
- `node frontend/scripts/check-desktop-generic-ipc-allowlist.mjs`
- `node frontend/scripts/check-desktop-old-binding-compat.mjs`
- `node frontend/scripts/check-desktop-misc-compat-inventory.mjs`
- `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1 -TimeoutSeconds 180`
- `git diff --check`

Frontend CI result: 231 test files / 728 tests passed.

备注：有一次并行执行中的 `check-desktop-assets.ps1` 早于 `build:wails` 完成而失败；`build:wails` 自带资产检查通过，随后顺序重跑 `check-desktop-assets.ps1` 通过。该失败是验证调度竞态，不是产品 gate 失败。

## 桌面/浏览器行为差异说明

- Desktop release: `DeleteMiscModulePackage` typed IPC binding 可用；typed route 已进入 generic IPC runtime block。
- Desktop WebView typed smoke: 不执行删除，只验证 `miscDeleteBindingAvailable = true`，避免破坏本地可信 package 状态。
- Browser-dev: HTTP/SSE 继续通过，MISC package dir 仍由 smoke 单独隔离。
- Direct backend API: WebView typed smoke 记录 `directBackendApiRequestCount = 0`。

Smoke evidence from `output/desktop-ipc-smoke/desktop-ipc-smoke-summary.json`:

- `desktopRelease.ok = true`
- `desktopWebviewTyped.ok = true`
- `browserDev.ok = true`
- `desktopWebviewTyped.miscDeleteBindingAvailable = true`
- `desktopWebviewTyped.miscModuleCount = 8`
- `desktopWebviewTyped.capturePackets = 7074`
- `desktopWebviewTyped.threatHitCount = 721`
- `desktopWebviewTyped.objectCount = 205`
- `desktopWebviewTyped.directBackendApiRequestCount = 0`
- `desktopWebviewTyped.miscPackageDir == desktopWebviewTyped.backendMiscPackageDir`

## 评分

Total: 98/100

- Contract Correctness: 25/25. Go contract, frontend bridge test, IPC transport guard, Wails binding check, and MISC inventory all cover delete route semantics.
- Desktop Policy Compliance: 20/20. Typed binding 存在时 delete route 不再允许 generic IPC silent fallback。
- Regression Safety: 20/20. Focused gate、frontend CI、root/backend Go、build:wails、desktop assets、smoke 全部通过。
- Diagnostics and Failure Shape: 15/15. typed IPC transport error、compat fallback 和 smoke-safe non-destructive assertion 边界清晰。
- Docs and Traceability: 10/10. tracker、migration plan、MISC design 和 round report 已同步。
- Dev/Browser Compatibility: 8/10. browser-dev HTTP/SSE 通过；扣分点是 smoke 为避免破坏性副作用只断言 delete binding 可用，未执行真实删除。

## 自迭代记录

- 上轮建议：迁移 `DeleteMiscModulePackage` typed IPC，保留 `RunMiscModulePackage` 和 multipart import。
- 本轮执行：完全符合一轮一个主切片规则。
- 中途发现：`desktopTransportBinding.ts` 和 `desktopTypedBridgeCore.ts` 超过 size budget。处理方式是拆分类型面和 requirements，不放宽预算。
- 中途发现：binding check 原本只扫描单文件 `DesktopTransportBinding`。处理方式是让脚本扫描拆分后的类型文件集合，保留分组完整性检查。
- 硬阻塞：无。

## open blockers

无。

## 下一轮自动建议

根据评分阈值，98 >= 90 且无硬阻塞，可以进入下一轮。

recommendedNextSlice: `RunMiscModulePackage typed IPC`

约束：

- 下一轮只迁移 `RunMiscModulePackage`。
- 不同时迁移 multipart import。
- 运行错误需要保持为业务错误，不应误报为 desktop IPC transport error。
- smoke 若执行 invoke，必须使用 isolated MISC package dir，并优先选择内置或临时可控模块，避免污染用户 package 状态。
