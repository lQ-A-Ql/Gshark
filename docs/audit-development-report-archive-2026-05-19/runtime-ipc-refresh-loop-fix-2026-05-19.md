# Runtime IPC 刷新循环修复报告

署名：Codex

时间：2026-05-19 19:21:51 +08:00（Asia/Shanghai）

## 问题

前端在“后端已连接”和“运行时组件检测失败：Wails IPC 数据面不可用”之间反复刷新。

根因是 `SentinelContext` 传入 `useBackendLifecycle` 的 `setSelectedPacketId` 为内联函数，状态变化后引用随渲染改变，触发 `useBackendLifecycleStartupEffect` 重新执行启动探测。Typed Wails runtime snapshot 失败后，该循环会不断重复。

## 修改摘要

- `frontend/src/app/state/SentinelContext.tsx`
  - 使用 `useCallback` 固定 `setSelectedPacketId` 代理函数引用，避免启动生命周期 effect 因渲染产生的新函数重复执行。

- `frontend/src/app/integrations/desktopBridge.ts`
  - `GetToolRuntimeSnapshotFast/Full` typed IPC 失败后，改为通过当前数据面 bridge 读取 `/api/tools/runtime-config`。
  - fallback 成功时保留 `transportError`，设置 transport 为 `http-fallback`，供设置侧栏诊断。

- `frontend/src/app/integrations/ipcBackendTransport.ts`
  - 保留 string/object rejection 中的真实错误内容，不再统一退化为 `Wails IPC 数据面请求失败`。

- `frontend/src/app/integrations/desktopBridge.test.ts`
  - 增加 typed runtime snapshot 失败后走 generic desktop IPC fallback 的覆盖。
  - 增加字符串 IPC 错误保真的覆盖。

- `frontend/src/app/state/hooks/useBackendLifecycle.test.tsx`
  - 增加 runtime 探测失败后 rerender 不会重启 startup probe 的回归覆盖。

## 验证记录

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm test:run -- src/app/integrations/desktopBridge.test.ts src/app/state/hooks/useBackendLifecycle.test.tsx
pnpm run typecheck
pnpm run lint
pnpm run format:check
pnpm run boundary:check
pnpm run ci

cd C:\Users\QAQ\Desktop\gshark
git diff --check
```

结果：全部通过。前端完整 CI 通过，测试结果为 `221` 个测试文件、`683` 个测试全部通过。

## 预期结果

- 后端连接成功后，启动 runtime 探测失败不会再触发启动 effect 循环。
- typed Wails runtime snapshot 不可用时，会降级到数据面 bridge 获取 runtime snapshot。
- 用户仍可进入主界面，并在设置侧栏看到保留的 IPC 错误详情。

## 剩余风险

- 本轮修复解决前端循环和错误降级；如果 typed Wails binding 本身仍不可用，设置侧栏仍会显示降级诊断，需要继续从 Wails 绑定生成或桌面代理日志排查。
