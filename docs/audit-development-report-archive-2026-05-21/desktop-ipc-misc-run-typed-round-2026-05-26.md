# Desktop IPC MISC RunMiscModulePackage typed round

- Author: Codex
- Time: 2026-05-26 03:22:28 +08:00
- Round: 16
- Phase: post-phase-5

## 迁移域与目标

本轮只迁移一个主切片：`RunMiscModulePackage` typed IPC。

目标：

- 桌面 MISC package invoke 从 `POST /api/tools/misc/packages/{id}/invoke` generic IPC 迁移到 `DesktopApp.RunMiscModulePackage(id, values)` typed binding。
- 保留 browser-dev HTTP 路径。
- 保留 multipart import 为唯一 MISC generic IPC compatibility 路径。
- 不在 WebView smoke 中执行任意用户 MISC 包代码；运行结果语义由 Go contract 和 frontend mapper/integration tests 覆盖。

## 修改面清单

- `desktop_backend_proxy.go`
  - 新增 `RunMiscModulePackage(id string, values map[string]string) (any, error)`。
  - typed binding 复用现有 backend route：`POST /api/tools/misc/packages/{id}/invoke`，timeout 为 120s。
- `desktop_typed_bindings_test.go`
  - 覆盖 invoke route、HTTP method、URL path、JSON body `values.keyword`。
- `frontend/src/app/integrations/desktopTransportBindingTooling.ts`
  - 声明 `RunMiscModulePackage` typed binding。
- `frontend/src/app/integrations/desktopTypedBridgeRequirements.ts`
  - 将 `runMiscModule` 绑定到 `RunMiscModulePackage`。
- `frontend/src/app/integrations/desktopTypedBridgeMisc.ts`
  - 新增桌面 typed override，并通过 `asMiscModuleRunResult` 保持 DTO 语义。
- `frontend/src/app/integrations/ipcBackendTransport.ts`
  - 当 typed binding 存在时，阻止 `POST /api/tools/misc/packages/{id}/invoke` generic IPC。
- `frontend/wailsjs/go/main/DesktopApp.d.ts`
  - 新增 Wails generated declaration。
- `frontend/wailsjs/go/main/DesktopApp.js`
  - 新增 Wails generated wrapper。
- `frontend/scripts/check-wails-bindings.mjs`
  - `typed-misc` 组新增 `RunMiscModulePackage`。
- `frontend/scripts/check-desktop-transport-policy.mjs`
  - transport policy 要求 `runMiscModule -> RunMiscModulePackage`。
- `frontend/scripts/check-desktop-generic-ipc-allowlist.mjs`
  - 将 MISC invoke route 从 explicit compatibility 移入 migrated typed route。
- `frontend/scripts/check-desktop-misc-compat-inventory.mjs`
  - MISC compatibility 收窄到仅 `POST /api/tools/misc/import`。
- `frontend/src/app/desktopWebviewSmoke.ts`
  - 校验 `RunMiscModulePackage` binding 可用。
- `scripts/check-desktop-ipc-smoke.ps1`
  - 输出并断言 `miscRunBindingAvailable = true`。
- `docs/desktop-ipc-iteration-status.json`
  - 更新 Round 16 状态、自评分、下一轮建议。
- `docs/desktop-ipc-migration-plan.md`
  - 追加 Round 16 完成记录。
- `docs/desktop-ipc-misc-native-binding-design.md`
  - 更新 MISC import-only compatibility 状态。

## Focused test 结果

- `go test -tags dev ./...`：passed
- `cd frontend && pnpm run typecheck`：passed
- `cd frontend && pnpm exec vitest run src/app/integrations/desktopBridge.test.ts src/app/integrations/ipcBackendTransport.test.ts src/app/integrations/clients/toolClient.test.ts scripts/check-desktop-misc-compat-inventory.test.mjs scripts/check-desktop-generic-ipc-allowlist.test.mjs scripts/check-desktop-transport-policy.test.mjs`：6 files / 61 tests passed
- `node frontend/scripts/check-wails-bindings.mjs`：passed
- `node frontend/scripts/check-desktop-transport-policy.mjs`：passed
- `node frontend/scripts/check-desktop-generic-ipc-allowlist.mjs`：passed
- `node frontend/scripts/check-desktop-misc-compat-inventory.mjs`：passed
- `cd frontend && pnpm run size:check`：passed
- `git diff --check`：passed

## Full gate 结果

- `go test -tags dev ./...`：passed
- `go test -tags production ./...`：passed
- `cd backend && go test ./...`：passed
- `cd frontend && pnpm run ci`：passed，231 test files / 729 tests
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

- Desktop release / desktop WebView：`runMiscModule` 优先使用 typed `DesktopApp.RunMiscModulePackage`。
- Desktop generic IPC：当 `RunMiscModulePackage` binding 存在时，`POST /api/tools/misc/packages/{id}/invoke` generic IPC 被拒绝，避免 typed 覆盖域静默回退。
- Browser-dev：继续使用 HTTP `POST /api/tools/misc/packages/{id}/invoke`，不强制走 Wails binding。
- Multipart import：仍保留 browser-dev/compat HTTP multipart 路径，本轮不改变文件上传语义。

## Smoke 证据

Summary: `output/desktop-ipc-smoke/desktop-ipc-smoke-summary.json`

- `desktopRelease.ok = true`
- `desktopWebviewTyped.ok = true`
- `browserDev.ok = true`
- `desktopWebviewTyped.capturePackets = 7074`
- `desktopWebviewTyped.threatHitCount = 721`
- `desktopWebviewTyped.objectCount = 205`
- `desktopWebviewTyped.miscModuleCount = 8`
- `desktopWebviewTyped.miscDeleteBindingAvailable = true`
- `desktopWebviewTyped.miscRunBindingAvailable = true`
- `desktopWebviewTyped.directBackendApiRequestCount = 0`
- `desktopWebviewTyped.miscPackageDir == desktopWebviewTyped.backendMiscPackageDir`

## 评分

Total: 98 / 100

- Contract Correctness: 25 / 25
  - Go contract 覆盖 route/method/body；frontend typed override 复用 mapper 保持返回语义。
- Desktop Policy Compliance: 20 / 20
  - typed binding 存在时 generic invoke route 被 runtime guard 阻断。
- Regression Safety: 20 / 20
  - focused tests、full gate、Wails build、smoke 全部通过。
- Diagnostics and Failure Shape: 15 / 15
  - typed IPC transport error 与 MISC runtime business error 保持分层；执行 sandbox 错误仍由 backend route 语义表达。
- Docs and Traceability: 10 / 10
  - tracker、plan、design、round report 均同步。
- Dev/Browser Compatibility: 8 / 10
  - browser-dev HTTP/SSE green。扣 2 分原因：WebView smoke 只校验 invoke binding 可用，不执行真实自定义 MISC 包，避免任意代码执行风险。

## 自迭代记录

- 硬阻塞：无。
- 自动决策：分数 >= 90，允许进入下一 round。
- 当前 MISC generic compatibility 已收窄到唯一剩余 route：`POST /api/tools/misc/import`。
- 不应把 zip 文件强行转为 typed JSON/base64；桌面发行版更合适的 typed 形态是 native file-path import。

## 下一轮自动建议

Recommended next slice: `ImportMiscModulePackageFromPath typed IPC`。

边界：

- 只迁移 MISC import，不同时处理其他 generic IPC 收口。
- Browser-dev 继续保留 HTTP multipart。
- Desktop typed route 优先使用本地文件路径，避免 Wails JSON 大 blob。
- 如果当前 UI 只能提供浏览器 `File` 而不能提供本地 path，下一轮应先新增 native picker/import entry，而不是破坏现有 browser upload。
