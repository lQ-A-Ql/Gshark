# Desktop IPC MISC ImportMiscModulePackageFromPath typed round

- Author: Codex
- Time: 2026-05-26 03:45:51 +08:00
- Round: 17
- Phase: post-phase-5

## 迁移域与目标

本轮只迁移一个主切片：MISC package import typed IPC。

目标：

- 桌面发行版不再通过 generic IPC multipart blob 导入 MISC zip。
- 桌面使用 `SelectMiscModulePackage()` 选择本地 zip，并通过 `ImportMiscModulePackageFromPath(path string)` 导入。
- Browser-dev 继续保留原有 multipart HTTP 上传。
- 继续复用现有后端 `/api/tools/misc/import` 处理链路，确保 `miscpkg.Manager.ImportZipBytes` 的 zip 数量、大小、路径穿越、manifest 校验不被绕过。

## 修改面清单

- `app.go`
  - 新增 `SelectMiscModulePackage()` Wails 原生 zip 选择对话框。
- `desktop_backend_proxy.go`
  - 新增 `ImportMiscModulePackageFromPath(path string)`。
  - 新增 `postMultipartFile` / `desktopPostMultipartFile`，从本地路径读取 zip 并以 multipart/form-data 转发到现有后端 import route。
- `desktop_typed_bindings_test.go`
  - 覆盖 import route、HTTP method、multipart field、filename、file body。
- `frontend/src/app/integrations/desktopTransportBindingShell.ts`
  - 声明 `SelectMiscModulePackage`。
- `frontend/src/app/integrations/desktopTransportBindingTooling.ts`
  - 声明 `ImportMiscModulePackageFromPath`。
- `frontend/src/app/integrations/desktopTypedBridgeRequirements.ts`
  - 新增 `selectMiscModulePackage` 与 `importMiscModulePackageFromPath` typed requirements。
- `frontend/src/app/integrations/desktopTypedBridgeMisc.ts`
  - 新增 typed picker/import overrides，并复用 `asMiscModuleImportResult`。
- `frontend/src/app/integrations/ipcBackendTransport.ts`
  - typed import binding 存在时阻断 `POST /api/tools/misc/import` generic IPC。
- `frontend/src/app/integrations/miscModuleClientTypes.ts`
  - 拆出 MISC client 类型，保持 `bridgeTypes.ts` size budget。
- `frontend/src/app/misc/useMiscToolsCatalog.ts`
  - 新增 `importModuleFromNativeDialog`，仅在 client 同时具备 picker/importFromPath 时暴露。
- `frontend/src/app/misc/MiscToolsHero.tsx`
  - 接入可选 native import 入口。
- `frontend/src/app/misc/MiscImportButtons.tsx`
  - 拆出导入按钮区域，保持 MISC hero size budget。
- `frontend/wailsjs/go/main/DesktopApp.d.ts`
  - 新增 generated declarations。
- `frontend/wailsjs/go/main/DesktopApp.js`
  - 新增 generated wrappers。
- `frontend/scripts/check-wails-bindings.mjs`
  - shell 组新增 `SelectMiscModulePackage`，typed-misc 组新增 `ImportMiscModulePackageFromPath`。
- `frontend/scripts/check-desktop-transport-policy.mjs`
  - 新增 typed import requirements。
- `frontend/scripts/check-desktop-generic-ipc-allowlist.mjs`
  - 将 MISC import route 归类为 migrated typed route。
- `frontend/scripts/check-desktop-misc-compat-inventory.mjs`
  - MISC compatibility route 清零，要求 `runtime-complete; list-import-delete-run-typed`。
- `frontend/src/app/desktopWebviewSmoke.ts`
  - 校验 `SelectMiscModulePackage` 和 `ImportMiscModulePackageFromPath` binding 可用。
- `scripts/check-desktop-ipc-smoke.ps1`
  - 输出并断言 `miscImportBindingAvailable = true`。
- `docs/desktop-ipc-iteration-status.json`
  - 更新 Round 17 状态、自评分、下一轮建议。
- `docs/desktop-ipc-migration-plan.md`
  - 追加 Round 17 完成记录。
- `docs/desktop-ipc-misc-native-binding-design.md`
  - 更新到 `runtime-complete; list-import-delete-run-typed`。

## Focused test 结果

- `go test -tags dev ./...`：passed
- `cd frontend && pnpm run typecheck`：passed
- `cd frontend && pnpm exec vitest run src/app/integrations/desktopBridge.test.ts src/app/integrations/ipcBackendTransport.test.ts src/app/integrations/clients/toolClient.test.ts src/app/misc/useMiscToolsCatalog.test.tsx src/app/pages/MiscTools.customModules.test.tsx scripts/check-desktop-misc-compat-inventory.test.mjs scripts/check-desktop-generic-ipc-allowlist.test.mjs scripts/check-desktop-transport-policy.test.mjs`：8 files / 71 tests passed
- `node frontend/scripts/check-wails-bindings.mjs`：passed
- `node frontend/scripts/check-desktop-transport-policy.mjs`：passed
- `node frontend/scripts/check-desktop-generic-ipc-allowlist.mjs`：passed
- `node frontend/scripts/check-desktop-misc-compat-inventory.mjs`：passed
- `cd frontend && pnpm run size:check`：passed

## Full gate 结果

- `go test -tags dev ./...`：passed
- `go test -tags production ./...`：passed
- `cd backend && go test ./...`：passed
- `cd frontend && pnpm run ci`：passed，231 test files / 731 tests
- `cd frontend && pnpm run build:wails`：passed
- `powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1`：passed
- `node frontend/scripts/check-wails-bindings.mjs`：passed
- `node frontend/scripts/check-desktop-transport-policy.mjs`：passed
- `node frontend/scripts/check-desktop-generic-ipc-allowlist.mjs`：passed
- `node frontend/scripts/check-desktop-old-binding-compat.mjs`：passed
- `node frontend/scripts/check-desktop-misc-compat-inventory.mjs`：passed
- `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1 -TimeoutSeconds 180`：passed
- `git diff --check`：passed

## 桌面/浏览器行为差异说明

- Desktop release / desktop WebView：MISC import 走 native file picker + typed `ImportMiscModulePackageFromPath`。
- Desktop generic IPC：当 typed import binding 存在时，`POST /api/tools/misc/import` generic IPC 被拒绝，避免大 zip blob 继续走 generic IPC。
- Browser-dev：继续使用原有 multipart HTTP upload，保留调试体验。
- 后端校验：typed import 仍进入现有 backend import handler；业务错误保持原后端错误形态，不包装为 IPC transport error。

## Smoke 证据

Summary: `output/desktop-ipc-smoke/desktop-ipc-smoke-summary.json`

- `desktopRelease.ok = true`
- `desktopWebviewTyped.ok = true`
- `browserDev.ok = true`
- `desktopWebviewTyped.capturePackets = 7074`
- `desktopWebviewTyped.threatHitCount = 721`
- `desktopWebviewTyped.objectCount = 205`
- `desktopWebviewTyped.miscModuleCount = 8`
- `desktopWebviewTyped.miscImportBindingAvailable = true`
- `desktopWebviewTyped.miscDeleteBindingAvailable = true`
- `desktopWebviewTyped.miscRunBindingAvailable = true`
- `desktopWebviewTyped.directBackendApiRequestCount = 0`
- `desktopWebviewTyped.miscPackageDir == desktopWebviewTyped.backendMiscPackageDir`

## 评分

Total: 97 / 100

- Contract Correctness: 25 / 25
  - Go contract 覆盖 multipart import 的 route、method、field、filename、body；frontend typed override 复用 import mapper。
- Desktop Policy Compliance: 20 / 20
  - typed binding 存在时 generic import route 被 runtime guard 阻断；桌面不再通过 Wails JSON/base64 传 zip。
- Regression Safety: 20 / 20
  - focused tests、full gate、Wails build、smoke 全部通过。
- Diagnostics and Failure Shape: 15 / 15
  - 本地文件读取错误、backend business validation error、IPC transport error 仍可区分。
- Docs and Traceability: 10 / 10
  - tracker、plan、design、round report、开发记录同步。
- Dev/Browser Compatibility: 7 / 10
  - browser-dev HTTP/SSE green，multipart upload 保留。扣 3 分原因：WebView smoke 只校验 import binding 可用，没有执行真实 zip 安装，避免自动 smoke 留下自定义模块状态。

## 自迭代记录

- 硬阻塞：无。
- 自动决策：分数 >= 90，允许进入下一 round。
- MISC runtime route 已完成桌面 typed IPC 化，MISC compatibility route 清零。
- 剩余 generic IPC 不应再推进新业务域，而应进入最终兼容窗口审计。

## 下一轮自动建议

Recommended next slice: `Generic IPC final compatibility audit`。

边界：

- 不新增业务 typed binding。
- 审计剩余 generic IPC allowlist 和 old generated binding allowlist 是否只包含 browser-dev upload/events/runtime identity/health 与 shell/update/dialog 例外。
- 收紧 stale 文档措辞，把 MISC multipart compatibility 从“桌面例外”改为“browser-dev 兼容”。
- 若发现桌面 business route 仍能 generic IPC，下一轮只修该 blocker。
