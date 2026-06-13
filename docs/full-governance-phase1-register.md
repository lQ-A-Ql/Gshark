# 全量一期治理登记表

本文记录本轮“全量一期治理”13 项问题的处理状态、落地位置和验收命令。外部 HTTP route、Wails binding、OpenAPI wire shape、核心算法输出语义保持不变。

## 状态总览

| 严重度 | 问题 | 本轮状态 | 落地位置 | 验收 |
| --- | --- | --- | --- | --- |
| 高 | `engine.Service` God Object | 已完成一期解耦 | `backend/internal/engine/service.go`、`service_types.go` | backend architecture + `go test ./...` |
| 高 | `engine` 大包 | 已建立门禁并完成首个纯逻辑抽离 | `backend/internal/engine/payloadinspect/`、`backend/internal/architecture/boundary_test.go` | backend architecture |
| 中 | `tool_*.go` 模板复制 | 已抽公共 precondition helper | `backend/internal/engine/shared_helpers.go`、`tool_*.go` | engine focused tests |
| 中 | 错误处理无 `%w` | 已修 YARA 高频取消/超时/执行错误路径 | `backend/internal/engine/yara_batch.go` | YARA tests |
| 中 | YARA done signal | 已修为真实 completion signal | `service_tools.go`、`service_types.go` | `TestCachedYaraHitsWaitsForScanCompletionSignal` |
| 中 | 前端 God Context | 已拆出 context value assembly，legacy shape 不变 | `frontend/src/app/state/hooks/useSentinelDomainValues.ts`、`useSentinelContextValues.ts` | provider focused tests + typecheck |
| 中 | 分析 hook 缓存策略不一致 | 已引入公共 cache helper并迁移主要分析 hook | `frontend/src/app/core/analysisResourceCache.ts` | cache tests |
| 中 | Wire DTO 宽类型 | 已建治理门禁与例外清单 | `frontend/scripts/check-type-governance.mjs` | `pnpm run type-governance:check` |
| 中 | 核心类型 `| string` 泄漏 | 已引入 `KnownOrUnknown<T>` 并阻止新增开放 union | `frontend/src/app/core/types/unknownEnum.ts` | type governance |
| 中 | `desktopTypedBridgeRules.ts as any` | 已改为 typed normalizer 并补测试 | `frontend/src/app/integrations/desktopTypedBridgeRules.ts` | bridge rules tests |
| 低 | 二进制/忽略文件残留 | 已加入 ignored tracked file gate | `.gitignore`、`scripts/check-ignored-tracked-files.ps1` | ignored tracked check |
| 低 | 前端缺 filePath 守卫 | 已统一主要分析入口 guard | `frontend/src/app/core/usableCapture.ts` | hook tests/typecheck |
| 低 | 缺 CONTRIBUTING/CHANGELOG | 已新增 | `CONTRIBUTING.md`、`CHANGELOG.md` | 文档链接/存在性 |

## 后端治理规则

- `engine.Service` 继续作为 transport/Wails 唯一 facade。
- Service 不再匿名嵌入状态结构；状态按 capture、filter、stream、analysis、object、media、YARA/hunting、runtime、MCP、playbook、saved-search、hypothesis 分组。
- 新增 engine 根包生产文件必须进入 ownership map。
- 新增超过大文件阈值的 engine 根文件必须拆分或明确进入 grandfather 例外。
- 纯逻辑子包不得依赖根 `engine`、`transport`、`tshark`、HTTP、MISC/plugin 或 `os/exec`。
- controller 只拥有自己的 state group，不嵌入其他 controller 或 `Service`。

## 前端治理规则

- `SentinelProvider` 保持旧 context 输出兼容，但新页面应优先使用已有领域 context：backend、capture、packet、stream、filter、analysis。
- 分析 hook 应使用公共 cache/guard 语义：same key inflight dedupe、force refresh、capture revision/filePath/totalPackets 变化刷新、空样本不请求。
- 桌面主线是 typed Wails IPC；已迁移数据面缺 binding 时不新增 generic IPC 回退。
- 新 wire DTO 默认声明明确字段；真实动态结构必须登记在 type governance 例外清单中。
- 新核心 enum 兼容未知值时使用 `KnownOrUnknown<T>` 或领域等价类型，不直接新增开放 `| string`。

## 验收命令

```powershell
cd backend
gofmt -l .
go test ./internal/architecture -run TestBackendArchitectureBoundaries -count=1 -v
go test ./...

cd ..\frontend
pnpm run type-governance:check
pnpm run typecheck
pnpm run size:check
pnpm exec vitest run src/app/state/useSentinelProviderBody.test.ts src/app/core/analysisResourceCache.test.ts src/app/integrations/desktopTypedBridgeRules.test.ts scripts/check-type-governance.test.mjs scripts/ci-script-coverage.test.mjs --reporter=verbose

cd ..
powershell -ExecutionPolicy Bypass -File .\scripts\check-ignored-tracked-files.ps1
git diff --check
```
