# Desktop IPC Round 13: MISC ListMiscModules typed IPC

- Author: Codex
- Time: 2026-05-26 02:24:08 +08:00

## 迁移域与目标

本轮只迁移一个主域切片：MISC module listing 的非破坏性读取路径。

目标：

- 新增 `DesktopApp.ListMiscModules` typed IPC binding。
- 桌面路径优先使用 typed IPC。
- 当 `ListMiscModules` binding 存在时，禁止 `/api/tools/misc/modules` 继续走 generic IPC。
- 保留 browser-dev HTTP 路径。
- 保留 MISC import/delete/invoke 为显式 generic IPC compatibility。

## 修改面

- Root desktop binding:
  - `desktop_backend_proxy.go`
  - `desktop_typed_bindings_test.go`
- Frontend typed bridge:
  - `frontend/src/app/integrations/desktopTypedBridgeMisc.ts`
  - `frontend/src/app/integrations/desktopTypedBridge.ts`
  - `frontend/src/app/integrations/desktopTypedBridgeCore.ts`
  - `frontend/src/app/integrations/desktopTransportBinding.ts`
- Frontend generated binding stubs:
  - `frontend/wailsjs/go/main/DesktopApp.d.ts`
  - `frontend/wailsjs/go/main/DesktopApp.js`
- Transport policy and guardrails:
  - `frontend/src/app/integrations/ipcBackendTransport.ts`
  - `frontend/scripts/check-wails-bindings.mjs`
  - `frontend/scripts/check-desktop-transport-policy.mjs`
  - `frontend/scripts/check-desktop-generic-ipc-allowlist.mjs`
  - `frontend/scripts/check-desktop-misc-compat-inventory.mjs`
- Tests:
  - `frontend/src/app/integrations/desktopBridge.test.ts`
  - `frontend/src/app/integrations/ipcBackendTransport.test.ts`
  - `frontend/scripts/check-desktop-transport-policy.test.mjs`
  - `frontend/scripts/check-desktop-generic-ipc-allowlist.test.mjs`
  - `frontend/scripts/check-desktop-misc-compat-inventory.test.mjs`
- Smoke:
  - `frontend/src/app/desktopWebviewSmoke.ts`
  - `scripts/check-desktop-ipc-smoke.ps1`
- Docs:
  - `docs/desktop-ipc-iteration-status.json`
  - `docs/desktop-ipc-migration-plan.md`
  - `docs/desktop-ipc-misc-native-binding-design.md`

## Focused test 结果

Passed:

- `go test -tags dev ./...`
- `cd frontend && pnpm exec vitest run src/app/integrations/desktopBridge.test.ts src/app/integrations/ipcBackendTransport.test.ts src/app/integrations/clients/toolClient.test.ts scripts/check-desktop-misc-compat-inventory.test.mjs scripts/check-desktop-generic-ipc-allowlist.test.mjs scripts/check-desktop-transport-policy.test.mjs`
- Focused frontend: 6 files / 59 tests passed.

## Full gate 结果

Passed:

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
- `powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1`
- `git diff --check`

Frontend CI evidence:

- 231 test files passed.
- 727 tests passed.

Desktop smoke evidence:

- `desktopRelease.ok = true`
- `desktopWebviewTyped.ok = true`
- `browserDev.ok = true`
- `capturePackets = 7074`
- `packetPageTotal = 7074`
- `sampledPacketId = 1`
- `locatedPacketFound = true`
- `packetDetailProtocol = IGMPv3`
- `threatHitCount = 721`
- `huntingPrefixCount = 2`
- `vehicleDBCProfileCount = 0`
- `pluginCount = 0`
- `miscModuleCount = 8`
- `httpStreams = 119`
- `tcpStreams = 177`
- `udpStreams = 54`
- `objectCount = 205`
- `objectEvidenceCount = 205`
- `directBackendApiRequestCount = 0`

## 桌面/浏览器行为差异

- Desktop release: `listMiscModules` 优先走 `DesktopApp.ListMiscModules` typed IPC。
- Desktop release: 当 typed binding 存在时，`/api/tools/misc/modules` generic IPC 会触发 `typed_binding_required`，不静默回退 HTTP。
- Desktop dev: typed binding 缺失时仍可走 generic IPC 兼容路径，便于过渡调试。
- Browser dev: 保留 `toolClient` 的 HTTP `/api/tools/misc/modules` 路径，不受 Wails typed IPC 约束影响。
- MISC import/delete/invoke: 继续作为显式 generic IPC compatibility，不在本轮迁移。

## 评分

总分：98 / 100

- Contract Correctness: 25 / 25
  - `ListMiscModules` binding、frontend mapper、typed override、Go route contract 和 generated stubs 已同步。
- Desktop Policy Compliance: 20 / 20
  - typed binding 存在时 generic IPC 对 `/api/tools/misc/modules` 被 runtime block。
  - WebView smoke 仍保持 `directBackendApiRequestCount = 0`。
- Regression Safety: 20 / 20
  - Focused tests、root dev/production Go、backend Go、frontend CI、build:wails、desktop smoke 均通过。
- Diagnostics and Failure Shape: 14 / 15
  - generic IPC 被阻断时保持 `typed_binding_required` 结构化错误。
  - 剩余扣分原因：MISC mutating routes 尚未建立隔离 smoke，错误分层仍待下一轮覆盖。
- Docs and Traceability: 10 / 10
  - tracker、migration plan、MISC design 和本报告已同步。
- Dev/Browser Compatibility: 9 / 10
  - Browser-dev HTTP/SSE smoke 通过。
  - 剩余扣分原因：browser-dev 对 MISC module listing 的专门断言仍依赖整体 HTTP smoke 与 client tests。

## Open blockers

无硬阻塞。

非阻塞后续项：

- MISC delete/run 是 mutating route，迁移前需要临时 package-state 隔离，避免 smoke 改动用户真实 MISC 包目录。
- MISC zip import 仍建议走 native file-path import，不建议把 zip base64 JSON 作为发行版桌面的默认 typed 形态。

## 自迭代记录

本轮得分 98，且无硬阻塞，符合 `>= 90` 自动推进阈值。

按自主选题规则，下一轮不应继续扩散到其他主域；应优先补齐当前 MISC compatibility window 的 mutating route 隔离基础，再考虑迁移 `DeleteMiscModulePackage` 或 `RunMiscModulePackage`。

本轮中途发现两个可修复问题并已收口：

- `pnpm run ci` 首次在 `format:check` 发现 `check-desktop-misc-compat-inventory.mjs` 格式问题，已用 Prettier 修复。
- `pnpm run ci` 第二次在 `size:check` 发现 `desktopTransportBinding.ts` 超出 1 行预算，已压缩相邻声明，不改变类型语义。

## 下一轮自动建议

Recommended next slice:

`MISC mutating typed IPC isolation boundary`

具体建议：

- 先定义临时 MISC package state 的测试/桌面 smoke 隔离边界。
- 在不触碰用户真实 MISC 包目录的前提下，准备 `DeleteMiscModulePackage` 或 `RunMiscModulePackage` typed IPC。
- 暂不迁移 multipart import，直到 native file-path import binding 与隔离策略完成。
