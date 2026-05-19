# CI 与测试覆盖修补报告

署名：Codex

时间：2026-05-19 21:36:00 +08:00（Asia/Shanghai）

## 本轮目标

修补 CI 与测试门禁缺口，确保 Wails 桌面嵌入资产、`dev` 构建标签测试、`production` 构建标签测试都能在 fresh CI runner 中被验证。

## 文档评审

- `docs/audit-development-report-archive-2026-05-19/backend-hardening-report-2026-05-19.md`：后端安全加固已有 focused/backend 测试记录，本轮保持 Ubuntu backend job 覆盖这些检查。
- `docs/audit-development-report-archive-2026-05-19/security-hardening-four-defects-report-2026-05-19.md`：记录了 `pnpm run build:wails` 与 root build-tag 测试的本地验证，本轮把这条链路纳入 CI。
- `docs/audit-development-report-archive-2026-05-19/runtime-ipc-refresh-loop-fix-2026-05-19.md`：前端完整 CI 已覆盖 IPC 刷新循环回归测试，本轮保留 frontend job 的 `pnpm run ci`。

## 修改摘要

- `.github/workflows/ci.yml`
  - 从 Ubuntu backend job 移除直接执行的 root `go test -tags dev ./...`，避免 fresh runner 缺少 `frontend/dist/sentinel-backend.exe` 时失败。
  - 新增 Windows desktop job：安装 Go、Node、pnpm，执行 `pnpm run build:wails` 生成 Wails 桌面资产。
  - 在 desktop job 中显式运行 `scripts/check-desktop-assets.ps1`。
  - 在桌面资产生成后执行 root `go test -tags dev ./...` 与 `go test -tags production ./...`。

- `.gitignore`
  - 移除 `.github/` 忽略规则，避免后续新增 workflow 被静默忽略。
  - 移除 `/docs/audit*` 忽略规则，保证开发归档报告可以正常进入版本控制。
  - 保留 `frontend/dist/` 与 `build/` 忽略规则，桌面构建产物仍不提交。

## 验证记录

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run ci
pnpm run build:wails

cd C:\Users\QAQ\Desktop\gshark
go test -tags dev ./...
go test -tags production ./...

cd C:\Users\QAQ\Desktop\gshark\backend
go test ./...

cd C:\Users\QAQ\Desktop\gshark
git diff --check
```

结果：全部通过。`pnpm run ci` 覆盖 221 个测试文件、683 个测试；`pnpm run build:wails` 完成 Vite 构建、后端二进制复制和桌面资产校验。

## 预期结果

- Ubuntu backend job 专注后端格式、契约、治理与 backend package 测试。
- Ubuntu frontend job 保持 pnpm-only、typecheck、lint、format、Vitest、Vite build 等完整前端门禁。
- Windows desktop job 在 fresh runner 中先生成 Wails 嵌入资产，再验证 `dev` 与 `production` 构建标签。
- 后续新增 CI workflow 与开发归档报告不会再被 `.gitignore` 静默屏蔽。
