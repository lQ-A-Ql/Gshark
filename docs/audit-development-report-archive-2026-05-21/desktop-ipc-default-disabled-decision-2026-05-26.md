# Desktop IPC Round 24 - default-disabled release-candidate decision

Author: Codex  
Time: 2026-05-26 19:51:44 +08:00

## 迁移域与目标

本轮主域：generic IPC adapter release-candidate policy。

目标：

- 将桌面发行版 generic IPC adapter 默认策略从 `compat` 切到 `disabled`。
- 保留 adapter code，不删除 `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`。
- 保留 `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` 作为 adapter-enabled rollback/override 路径。
- 保留 browser-dev HTTP/SSE 调试链路。
- 更新 readiness guardrail，使其验证 default-disabled release candidate，而不是继续禁止 default-disabled。

## 修改面清单

- `frontend/src/app/integrations/desktopGenericIpcPolicy.ts`
  - 无显式 `VITE_DESKTOP_GENERIC_IPC_POLICY` 时默认返回 `disabled`。
  - 显式 `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` 仍优先返回 `compat`。
- `frontend/src/app/integrations/desktopGenericIpcPolicy.test.ts`
  - 默认策略断言改为 release-candidate default disabled。
  - 保留 explicit disabled、legacy alias、explicit compat override 覆盖。
- `frontend/src/app/integrations/desktopBridge.test.ts`
  - 兼容场景中需要 generic IPC/HTTP fallback 的测试显式 `vi.stubEnv("VITE_DESKTOP_GENERIC_IPC_POLICY", "compat")`。
  - 默认 disabled 的 fail-fast 行为继续由 disabled-policy tests 覆盖。
- `frontend/src/app/integrations/ipcBackendTransport.ts`
  - `generic_ipc_disabled` 错误文案改为策略禁用，并提示 `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` 回滚路径。
- `frontend/scripts/check-desktop-generic-ipc-retirement-readiness.mjs`
  - 从 “experiment default-off readiness” 升级为 “release-candidate default-disabled readiness”。
  - 仍拒绝把 legacy `VITE_DESKTOP_DISABLE_GENERIC_IPC` alias 作为默认控制路径。
  - 要求 tracker 记录 `genericIpcAdapterDefaultDisabledReleaseCandidate.rollbackPolicy = VITE_DESKTOP_GENERIC_IPC_POLICY=compat`。
- `docs/desktop-ipc-iteration-status.json`
  - `currentRound = 24`。
  - `genericIpcAdapterDisableExperiment.status = release-candidate-default-disabled`。
  - 新增 `genericIpcAdapterDefaultDisabledReleaseCandidate` 域。
- `docs/desktop-ipc-old-binding-exit-plan.md`
  - Removal sequence 记录 Round 24 默认禁用决策与 compat rollback。
- `docs/desktop-ipc-migration-plan.md`
  - post-phase typed cycles 增加 Round 24。

## Focused test 结果

已执行：

```powershell
cd frontend
pnpm exec vitest run src/app/integrations/desktopGenericIpcPolicy.test.ts src/app/integrations/desktopBridge.test.ts scripts/check-desktop-generic-ipc-retirement-readiness.test.mjs scripts/check-desktop-generic-ipc-rollback-guard.test.mjs
```

结果：

- Passed: 4 files / 42 tests

## Full gate 结果

已执行并通过：

- `go test -tags dev ./...`
- `go test -tags production ./...`
- `cd backend && go test ./...`
- `cd frontend && pnpm run ci`
  - Passed: 234 files / 753 tests
- `cd frontend && pnpm run build:wails`
- desktop assets / Wails binding / transport policy / generic allowlist / retirement readiness / rollback guard / old-binding / MISC inventory checks

Default-disabled Wails smoke：

- Command: `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1 -TimeoutSeconds 180`
- Summary: `output/desktop-ipc-smoke/desktop-ipc-smoke-summary.json`
- Result:
  - `desktopRelease.ok = true`
  - `desktopWebviewTyped.ok = true`
  - `browserDev.ok = true`
  - `genericIpcPolicy = disabled`
  - `genericIpcDisableExperimentBuildFlag = true`
  - `directBackendApiRequestCount = 0`
  - `capturePackets = 7074`
  - `httpStreams = 119`
  - `objectCount = 205`

Compat rollback Wails smoke：

- Build env: `VITE_DESKTOP_GENERIC_IPC_POLICY=compat`
- Command: `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1 -TimeoutSeconds 180 -OutputDir .\output\desktop-ipc-smoke-compat-rollback`
- Summary: `output/desktop-ipc-smoke-compat-rollback/desktop-ipc-smoke-summary.json`
- Result:
  - `desktopRelease.ok = true`
  - `desktopWebviewTyped.ok = true`
  - `browserDev.ok = true`
  - `genericIpcPolicy = compat`
  - `genericIpcDisableExperimentBuildFlag = false`
  - `directBackendApiRequestCount = 0`
  - `capturePackets = 7074`
  - `httpStreams = 119`
  - `objectCount = 205`

Final asset state：

- 已重新执行无 env 的 `cd frontend && pnpm run build:wails`。
- 最终 `frontend/dist` 为 default-disabled release-candidate 资产。

## 桌面/浏览器行为差异说明

- Desktop release：默认 `genericIpcPolicy = disabled`。缺 typed IPC 覆盖的数据面 route 直接抛 `generic_ipc_disabled`，不 silent fallback 到 generic IPC 或 browser HTTP。
- Desktop rollback：显式 `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` 恢复 adapter-enabled 行为，用于 release-candidate 回滚。
- Browser dev：继续 HTTP/SSE，不受桌面 typed IPC 策略阻断。

## 评分

本轮最终评分：`99/100`。

- Contract Correctness：25/25
- Desktop Policy Compliance：20/20
- Regression Safety：20/20
- Diagnostics and Failure Shape：15/15
- Docs and Traceability：10/10
- Dev/Browser Compatibility：9/10

扣分说明：

- Dev/Browser Compatibility 扣 1 分：browser-dev smoke 已通过，但 default-disabled release candidate 仍需连续观察多轮再进入 adapter removal。

## 自迭代记录

- Round 23 score `98 >= 90` 且无硬阻塞，按 tracker 推荐进入 Round 24。
- 本轮只做一个主域切片：generic IPC adapter 默认禁用 release-candidate decision。
- 发现默认 disabled 后旧测试隐式依赖 generic/HTTP fallback，已把这些测试显式标注为 `compat` 场景，避免测试语义混淆。
- readiness guardrail 已从禁止 default-disabled 改为要求 default-disabled + compat rollback。

## Open blockers

无。

## 下一轮自动建议

`default-disabled observation round 1`

目标：不移除 adapter code，连续观察 default-disabled 资产下 real WebView smoke、browser-dev HTTP/SSE、rollback guard、old-binding guard 是否稳定。

自动决策：本轮 `99 >= 90` 且无硬阻塞，可进入下一轮。但下一轮仍不删除 adapter code，只做默认禁用观察轮。
