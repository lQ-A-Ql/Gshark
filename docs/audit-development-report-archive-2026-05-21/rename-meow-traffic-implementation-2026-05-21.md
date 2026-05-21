# meow~traffic 改名实施报告

## 本轮目标

在不修改业务逻辑、不迁移内部接口标识的前提下，将项目的用户可见品牌统一改为 `meow~traffic`，并将桌面产物与发布资产默认文件名统一改为 `meow-traffic`。

## 实际改动摘要

1. 品牌显示面改名
   - 桌面窗口标题改为 `meow~traffic`
   - `wails.json` 中应用名改为 `meow~traffic`
   - 前端页面标题、启动页、欢迎页、mock 文案、指南文案同步改名
   - README、CLAUDE、AGENTS、版本化文档中的产品层描述同步改名

2. 构建与发布产物改名
   - Wails 输出文件名改为 `meow-traffic`
   - 发布脚本默认资产文件名由 `gshark.<version>.exe` 改为 `meow-traffic.<version>.exe`
   - 当前 `release/version.json` 展示名改为 `meow~traffic v1.0.3`
   - 当前 `release/version.json` 资产名与默认下载文件名改为 `meow-traffic.v1.0.3.exe`

3. 校验与测试同步
   - 更新桌面更新测试中的 Windows 资产样例文件名
   - 保持语义版本提取逻辑不变，仅验证新文件名前缀也能通过
   - 前后端及前端测试均完成回归

## 保留的兼容标识

本轮明确保留以下旧名，以避免把“品牌改名”扩大成“接口/运行时迁移”：

- Go module path：`github.com/gshark/sentinel/...`
- 环境变量：`GSHARK_*`
- 配置 / 临时目录根：`gshark-sentinel`
- 内嵌后端二进制名：`sentinel-backend.exe`
- 前端状态/类型名：`SentinelContext`
- 桌面事件名前缀：`gshark:backend:*`
- CSS 类名与主题变量前缀：`gshark-*`
- GitHub 仓库与更新源：`lQ-A-Ql/Gshark`

## 最新文档评审结论

本轮按约定先复查了最新版本化文档，重点包括：

- `docs/README.md`
- `docs/misc-module-interface.md`
- `docs/plugin-interface.md`
- `docs/backend-engineering-audit-spec-2026-05-14.md`
- `docs/frontend-engineering-audit-spec-2026-05-15.md`

评审结论：

1. 这些文档没有新增会阻塞本轮改名的架构性变化。
2. 文档中存在大量品牌文案与真实内部标识混写的情况。
3. 因本轮只做品牌与产物层改名，不能把文档写成“内部标识也已迁移”。
4. 因此已在关键入口文档中补充兼容说明，明确 `meow~traffic` 是品牌名，而 `GSHARK_*`、`gshark-sentinel`、`sentinel-backend.exe` 等仍是当前真实运行标识。

## 验证结果

已执行：

```powershell
go test -tags dev ./...
cd backend && go test ./...
cd frontend && pnpm run typecheck
cd frontend && pnpm run test:run
```

结果：

- Root Go tests：通过
- Backend Go tests：通过
- Frontend typecheck：通过
- Frontend Vitest：首次全量运行出现 1 个既有时序性失败，单测单跑通过；再次全量运行 225/225 文件、693/693 测试全部通过

## 备注

- 历史发布目录 `release/out/v*/version.json` 未回写，保持历史事实不变。
- 本轮没有迁移 `frontend/package.json` 的包名；它仍保留旧内部命名以避免波及包管理与工具链约束。
- 桌面请求头中的 user-agent 文本已同步为 `meow-traffic-*`，属于品牌显示层调整，不影响接口协议。

署名：Codex
时间：2026-05-21 16:04:06 +08:00
