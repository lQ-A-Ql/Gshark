# meow~traffic 项目开发指南

本文是当前仓库的权威开发入口。产品品牌名是 `meow~traffic`；为了兼容历史版本，`sentinel`、`meow-traffic`、`github.com/gshark/sentinel/...`、`sentinel-backend.exe` 和 `MEOW_TRAFFIC_*` 等内部标识仍然有效，除非后续有明确迁移方案。

## 仓库结构

项目由两个 Go module 组成，并通过根目录 `go.work` 统一到一个工作区。

| 路径 | Module | Go 版本 | 职责 |
| --- | --- | --- | --- |
| `.` | `github.com/gshark/sentinel/desktop` | Go 1.22 | Wails 桌面壳、前端嵌入、桌面 binding |
| `backend/` | `github.com/gshark/sentinel/backend` | Go 1.25 | HTTP 后端、tshark 集成、分析逻辑、MISC 运行时 |

根模块只承载桌面壳，真实业务逻辑集中在 `backend/`。运行后端命令时先 `cd backend`；运行前端命令时先 `cd frontend`。

## 构建标签

桌面应用入口受 `dev` 或 `production` build tag 保护。根目录 `main.go`、`app.go`、`build_mode_*.go` 都要求 `//go:build dev || production`。不带 tag 时，根模块只会编译 `main_nondesktop.go`，它只打印提示并退出。

```powershell
# 桌面壳测试
go test -tags dev ./...
go test -tags production ./...

# 后端测试不需要桌面 build tag
cd backend
go test ./...
```

## 前端包管理

前端只使用 `pnpm`。`frontend/pnpm-lock.yaml` 是唯一维护的锁文件，不要重新引入 `package-lock.json`。

```powershell
cd frontend
corepack enable
corepack prepare pnpm@10.31.0 --activate
pnpm install --frozen-lockfile
```

常用前端脚本：

| 命令 | 含义 |
| --- | --- |
| `pnpm run dev` | 启动 Vite 开发服务 |
| `pnpm run build` | 仅执行 Vite 生产构建 |
| `pnpm run build:wails` | Vite 构建、复制后端二进制、检查桌面资源 |
| `pnpm run ci` | 包管理、类型、lint、格式、体积、边界、IPC、Vitest、Vite 构建全套检查 |
| `pnpm run ci:quality` | 包管理、typecheck、lint、format、size 检查 |
| `pnpm run ci:boundaries` | 前端架构、preload、client/mapper/wire 边界检查 |
| `pnpm run ci:desktop` | Wails binding、desktop transport、generic IPC、old binding、MISC compat 检查 |
| `pnpm run ci:test-build` | Vitest 全量测试与 Vite 生产构建 |
| `pnpm run boundary:check` | 前端架构边界检查 |
| `pnpm run type-governance:check` | 阻止新增裸 `as any`、开放核心 `| string` union、未登记宽 wire DTO |

## 本地开发

固定端口约定：

| 组件 | 端口 |
| --- | --- |
| 后端 HTTP/SSE | `17891` |
| Wails dev server | `34115` |

桌面优先开发启动：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start-dev.ps1
```

直接启动 Wails 开发模式：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start-wails-dev.ps1
```

后端单独开发：

```powershell
cd backend
go test ./...
```

普通浏览器开发模式继续通过 `httpBridge` 使用 HTTP/SSE fallback。桌面模式的数据面调用应走 typed Wails IPC。

## 运行时配置

常用环境变量：

| 变量 | 用途 |
| --- | --- |
| `MEOW_TRAFFIC_BACKEND_TOKEN` | 后端 bearer token；未设置时自动生成 |
| `MEOW_TRAFFIC_ALLOW_EXISTING_BACKEND=1` | 复用已经运行的后端 |
| `VITE_BACKEND_URL` | 前端 API override，默认 `http://127.0.0.1:17891` |
| `MEOW_TRAFFIC_FFMPEG` | 显式 FFmpeg 路径 |
| `MEOW_TRAFFIC_PYTHON` | 显式 Python 路径 |
| `MEOW_TRAFFIC_VOSK_MODEL` | 显式 Vosk 模型目录 |
| `MEOW_TRAFFIC_MISC_PACKAGE_DIR` | MISC zip 模块安装目录 |

运行时探测规则：

- `probe=fast` 面向启动和手动刷新预算。
- 完整探测会补齐 tshark 字段、Python `vosk`、YARA 规则等慢信息。
- 缺少 tshark 可选字段表示能力降级，不代表 tshark 完全不可用。

## Wails 后端二进制缓存

`main.go` 会在桌面构建时嵌入 `frontend/dist/sentinel-backend.exe`。修改后端代码后，旧二进制可能从以下位置被复用：

- `frontend/dist/sentinel-backend.exe`
- `build/bin/sentinel-backend.exe`
- `%TEMP%\meow-traffic\backend\sentinel-backend.exe`

`scripts/start-wails-dev.ps1` 通常会清理这些位置。如果仍然看到旧后端行为，删除这些文件并清理 Go build cache。

## 检查命令

快速聚焦检查：

```powershell
cd backend
gofmt -l .
go test ./internal/architecture -run TestBackendArchitectureBoundaries -count=1 -v
go test ./...

cd ..\frontend
pnpm run type-governance:check
pnpm run boundary:check
pnpm run test:run
pnpm run typecheck
pnpm run lint
```

完整本地检查：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check-all.ps1
```

`check-all.ps1` 会构建桌面资源，分别用 `dev` 和 `production` tag 跑桌面壳测试，检查后端格式和架构边界，运行后端测试与覆盖率报告，并执行前端 quality、boundaries、desktop IPC、test-build 四组 CI、Wails 资源检查和 ignored tracked files 检查。

忽略文件不允许继续被 Git 跟踪。若误提交了 `.gitignore` 覆盖的文件，使用 `git rm --cached <path>` 从索引移除，并运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check-ignored-tracked-files.ps1
```

## 文档维护规则

变更以下工程表面时，必须同步更新对应权威文档：

| 变更 | 必须更新 |
| --- | --- |
| 新增或调整 HTTP route | `docs/api/openapi.yaml` |
| 新增 typed Wails 数据面 binding | `docs/project-design-and-constraints.md`、`docs/project-model.md` 和相关架构图 |
| 新增核心前端类型或 wire DTO 家族 | `docs/project-model.md` 或架构文档；如对外公开则同步 OpenAPI |
| 新增 MISC 包交付形态 | `docs/misc-module-interface.md` |
| 新增威胁狩猎规则、YARA 或 playbook 契约 | `docs/api/openapi.yaml`、架构文档或约束文档 |
| 新增 CI、构建、包管理约束 | 本文档；如影响阅读入口或门禁矩阵则同步 `docs/README.md`、`docs/project-model.md` |
| 新增全局工程治理规则或阶段性整改状态 | `docs/full-governance-phase1-register.md` 或 `docs/governance-defect-register.json` |
