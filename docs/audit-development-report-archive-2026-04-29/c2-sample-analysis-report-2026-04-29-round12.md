# 日期: 2026-04-29
# 署名: Codex

# C2 / APT 分析第十二轮复查评论、优化与开发报告

## 1. 本轮目标

本轮承接第十一轮“CS Host/URI 评分因子可见化”的结果，开始推进独立 **APT 组织画像页** 骨架。目标不是在本轮直接做强归因，而是先把后续银狐 / Silver Fox 等组织画像所需的数据契约、接口、缓存、页面入口和 UI 容器打通。

本轮优先级：

1. 保持 C2 页继续输出技术证据，不把组织归因塞回 C2 标签页。
2. 新增独立 `/apt-analysis` 页面与 `/api/apt-analysis` 接口。
3. 预置 Silver Fox / 银狐 actor profile 骨架。
4. APT 页只消费结构化技术证据：`actorHints`、`sampleFamily`、`campaignStage`、`transportTraits`、`infrastructureHints`、`ttpTags`。
5. 修复上一轮遗留的前端 bridge 字段映射缺口：`signal_tags` 需要正确转成 `signalTags`。

## 2. 对上一轮报告的复查评论

第十一轮已经把 CS Host/URI 聚合的评分因子透出到页面，是继续压低误报和增强可解释性的正确方向。但复查发现一个细节问题：后端已经输出 `signal_tags`，前端类型和 mock 测试也已覆盖 `signalTags`，但 `wailsBridge` 的真实 HTTP payload 转换函数尚未映射 `signal_tags`。

这意味着真实运行时可能无法看到后端返回的评分标签。本轮已同步修正该问题，并将其纳入第十二轮变更。

同时，第十一轮报告提出“APT 画像需要独立页面”的判断继续成立：

- C2 页关注 CS / VShell 等技术家族和流量行为；
- APT 页关注组织 / 活动簇画像、投递链、样本家族和基础设施关联；
- 两者应通过 typed evidence 连接，而不是混成同一个标签体系。

## 3. 本轮代码变更

### 3.1 后端新增 APT 数据契约

文件：`C:\Users\QAQ\Desktop\gshark\backend\internal\model\types.go`

新增类型：

- `APTEvidenceRecord`
- `APTActorProfile`
- `APTAnalysis`

核心字段包括：

- actor：`actor_id` / `actor_name`
- evidence：`evidence_type` / `evidence_value` / `summary` / `evidence`
- traffic refs：`packet_id` / `stream_id` / `source` / `destination` / `host` / `uri`
- attribution extension：`sample_family` / `campaign_stage` / `transport_traits` / `infrastructure_hints` / `ttp_tags`
- aggregate buckets：actors、sample families、campaign stages、transport traits、infrastructure hints、related C2 families

### 3.2 后端新增 APT service 与 Silver Fox 预置画像

文件：`C:\Users\QAQ\Desktop\gshark\backend\internal\engine\service.go`

新增：

- `Service.aptAnalysis` 缓存字段；
- 打开 / 关闭抓包时清理 `aptAnalysis`；
- `APTAnalysis(ctx)`；
- `emptyAPTAnalysis()`；
- `emptySilverFoxProfile()`；
- `buildAPTAnalysisFromC2(c2)`；
- actor hint 标准化与 profile 聚合辅助函数。

Silver Fox / 银狐预置画像包含：

- aliases：`Swimming Snake`、`银狐`、`Silver Fox`
- sample families：`ValleyRAT`、`Winos 4.0`、`Gh0st variant`
- campaign stages：`delivery`、`downloader`、`rat-c2`
- transport traits：`https-c2`、`tcp-long-connection`、`periodic-callback`
- infrastructure hints：`hfs-download-chain`、`fallback-c2`、`custom-high-port`
- TTP tags：`multi-stage-delivery`、`encrypted-c2`、`rat-family`

注意：本轮没有做强归因，Silver Fox profile 的默认 confidence 为 0，仅作为结构化画像骨架。

### 3.3 后端新增 HTTP API

文件：`C:\Users\QAQ\Desktop\gshark\backend\internal\transport\http_server.go`

新增路由：

```text
GET /api/apt-analysis
```

新增 handler：

```go
handleAPTAnalysis
```

该接口接入 `r.Context()`，与 C2 分析一样支持请求取消。

### 3.4 前端新增 APT 类型与 bridge 方法

文件：`C:\Users\QAQ\Desktop\gshark\frontend\src\app\core\types.ts`

新增：

- `APTEvidenceRecord`
- `APTActorProfile`
- `APTAnalysis`

文件：`C:\Users\QAQ\Desktop\gshark\frontend\src\app\integrations\wailsBridge.ts`

新增：

- `getAPTAnalysis(signal?)`
- `/api/apt-analysis` payload 转换
- APT actor profile / evidence record 的 snake_case → camelCase 映射

同时修正第十一轮字段映射：

- `signal_tags` → `signalTags`

### 3.5 前端新增 APT 页面、路由与导航入口

新增文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\AptAnalysis.tsx`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\AptAnalysis.test.tsx`

修改文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\routes.tsx`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\layouts\MainLayout.tsx`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\AnalysisHero.tsx`

新增页面：

```text
/apt-analysis
APT 组织画像
APT ACTOR PROFILING
```

侧边栏新增一级入口：

```text
APT 组织画像
```

顶部“分析”菜单新增：

```text
APT 组织画像
```

`AnalysisHero` 增加 `indigo` 主题，用于 APT 页面。

### 3.6 APT 页面骨架结构

APT 页面当前包含：

- 顶部 hero：Actor Profile / TTP / Infrastructure；
- 总览 stat cards：组织证据、候选组织、样本家族、C2 关联；
- actor tabs：当前预置 Silver Fox / 银狐；
- actor profile 概览：别名、summary、confidence、evidence count；
- Silver Fox 基线预留：样本家族、投递链、网络画像；
- 分布区：样本家族、投递阶段、传输特征、基础设施线索、C2 技术证据来源；
- 证据表：后续承载 C2 / 样本 / 对象 / 威胁狩猎提供的 typed evidence；
- EvidenceActions：证据可跳转定位包 / 打开关联流。

页面缓存策略：

```text
captureRevision + filePath + totalPackets
```

关闭 / 切换抓包时通过现有生命周期清理后端 `aptAnalysis`，前端请求支持 `AbortSignal`。

## 4. 测试补充

### 后端测试

文件：`C:\Users\QAQ\Desktop\gshark\backend\internal\engine\c2_analysis_test.go`

新增：

- `TestServiceAPTAnalysisReturnsSkeleton`
- `TestServiceAPTAnalysisHonorsContextCancel`

文件：`C:\Users\QAQ\Desktop\gshark\backend\internal\transport\http_server_test.go`

新增：

- `TestHandleAPTAnalysisReturnsSkeleton`

### 前端测试

文件：`C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\AptAnalysis.test.tsx`

新增：

- 渲染 APT 骨架与 Silver Fox actor profile；
- 验证样本家族、传输特征、证据表渲染；
- 验证 cache key 生成。

## 5. 验证结果

本轮执行命令：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend; npx tsc --noEmit
cd C:\Users\QAQ\Desktop\gshark\backend; go test ./internal/engine -run 'C2|APT'
cd C:\Users\QAQ\Desktop\gshark\backend; go test ./internal/transport -run 'C2|APT'
cd C:\Users\QAQ\Desktop\gshark\frontend; npm test -- AptAnalysis C2Analysis
cd C:\Users\QAQ\Desktop\gshark\frontend; npm test
cd C:\Users\QAQ\Desktop\gshark\frontend; npm run build
cd C:\Users\QAQ\Desktop\gshark\backend; go test ./...
```

结果：

- TypeScript 类型检查通过。
- 后端 engine C2/APT 专项测试通过。
- 后端 transport C2/APT 专项测试通过。
- 前端 AptAnalysis + C2Analysis 专项测试：2 个测试文件、11 项测试通过。
- 前端全量测试：11 个测试文件、43 项测试通过。
- 前端生产构建通过。
- 后端全量 Go 测试通过。

`go test ./...` 生成的未跟踪 `echo-demo-test-*` 临时插件目录已安全清理。

## 6. 当前效果

当前分析体系已经拆成两层：

```text
C2 样本分析页
  -> CS / VShell 技术证据
  -> actorHints / sampleFamily / campaignStage / transportTraits / infrastructureHints / ttpTags
  -> 证据定位包 / 打开流 / 过滤器

APT 组织画像页
  -> Silver Fox / 银狐 actor profile 骨架
  -> 样本家族 / 投递链 / 传输特征 / 基础设施线索
  -> 消费 C2 typed evidence
  -> 后续可合并 ObjectExport / ThreatHunting / HTTP Login / SMTP / MySQL / NTLM 等专题证据
```

本轮重点是“骨架与接口正确”，不是“直接给出组织归因结论”。这避免把端口、路径或单个 IOC 误当成 APT 强证据。

## 7. 下一轮建议

第十三轮建议继续推进 APT 页的证据消费能力：

1. C2 页真实规则开始填充 Silver Fox 相关字段：
   - `actorHints`
   - `sampleFamily`
   - `campaignStage`
   - `transportTraits`
   - `infrastructureHints`
   - `ttpTags`
2. APT 页新增 evidence source tabs：
   - C2 Evidence
   - Delivery / Object Evidence
   - Threat Hunting Evidence
   - Credential / Auth Evidence
3. 将 Silver Fox 基线从静态 profile 升级为规则模板：
   - ValleyRAT / Winos / Gh0st family hints
   - HFS download chain hints
   - HTTPS/TCP fallback C2 hints
   - periodic callback hints
4. 增加归因解释面板：
   - supporting evidence
   - weak observations
   - missing evidence
   - attribution confidence rationale
5. 与第十一轮建议合并：把 CS `signalTags` 继续升级为结构化 `scoreFactors`，方便 APT 页消费正向 / 负向证据。
