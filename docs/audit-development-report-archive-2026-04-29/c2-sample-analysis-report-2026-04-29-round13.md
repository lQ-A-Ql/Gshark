# 日期: 2026-04-29
# 署名: Codex

# C2 / APT 分析第十三轮复查评论、优化与开发报告

## 1. 本轮目标

本轮承接第十二轮“APT 组织画像页骨架”的结果，开始让 C2 侧真实填充 APT 兼容字段，并让 APT 页具备按证据来源切分的第一版交互能力。

目标范围：

1. 继续保持 C2 页与 APT 页职责分离：C2 侧产生 typed evidence，APT 侧消费并聚合。
2. 在 C2 候选生成处补充 Silver Fox / 银狐弱画像字段：HFS 下载链、ValleyRAT / Winos / Gh0st 家族线索、HTTPS/TCP C2、周期回连、自定义高位端口、fallback C2。
3. 在 APT 证据记录中新增来源字段 `source_module`，便于后续混合 C2 / ObjectExport / ThreatHunting / Credential/Auth 证据。
4. APT 前端证据表增加 evidence source tabs。
5. 补充端到端测试，验证 C2 → APT 的证据流转。

## 2. 对上一轮报告的复查评论

第十二轮已经完成独立 APT 页面、后端接口、缓存生命周期和 Silver Fox 预置 profile，是正确的架构方向。但上一轮仍处于“空骨架 + profile placeholder”阶段，APT 页虽然能展示证据表，却缺少真实 C2 字段填充来源。

因此本轮将重点前移到 C2 候选生成层：在不把弱 IOC 升级为强归因的前提下，把能够被后续组织画像消费的字段补齐。这些字段仍然是“兼容 / 候选 / 弱画像”语义，不是自动归因结论。

## 3. 本轮代码变更

### 3.1 APT evidence 增加来源字段

文件：`C:\Users\QAQ\Desktop\gshark\backend\internal\model\types.go`

`APTEvidenceRecord` 新增：

```go
SourceModule string `json:"source_module,omitempty"`
```

用途：区分证据来自：

- `c2-analysis`
- 后续 `object-export`
- 后续 `threat-hunting`
- 后续 `credential-auth`

当前 `buildAPTAnalysisFromC2` 生成的证据统一写入：

```text
source_module = c2-analysis
```

### 3.2 C2 候选新增 APT enrichment

文件：`C:\Users\QAQ\Desktop\gshark\backend\internal\engine\tool_c2.go`

新增结构：

```go
c2APTEnrichment
```

新增函数：

```go
c2APTEnrichmentForCandidate(...)
c2LooksLikeHFSDeliveryText(...)
```

该逻辑会在 C2 candidate 生成时补充：

- `ActorHints`
- `SampleFamily`
- `CampaignStage`
- `TransportTraits`
- `InfrastructureHints`
- `TTPTags`
- `AttributionConfidence`
- 辅助 tags

当前识别的 Silver Fox 兼容线索包括：

- HFS / HTTP File Server / Rejetto：
  - actor hint: `Silver Fox / 银狐`
  - sample family: `ValleyRAT/Winos-compatible`
  - campaign stage: `delivery`
  - infrastructure hints: `hfs-download-chain`, `hfs-delivery`
  - TTP: `multi-stage-delivery`
- Winos 字符串：
  - sample family: `Winos 4.0`
  - tag: `winos-family-hint`
- ValleyRAT 字符串：
  - sample family: `ValleyRAT`
  - tag: `valleyrat-family-hint`
- Gh0st / Ghost RAT 字符串：
  - sample family: `Gh0st variant`
  - tag: `gh0st-family-hint`
- 443 / HTTPS：
  - transport trait: `https-c2`
  - TTP: `encrypted-c2`
- 周期 / beacon / heartbeat：
  - transport trait: `periodic-callback`
  - TTP: `command-and-control`
- 18856 / 9899：
  - weak actor hint: `Silver Fox / 银狐`
  - infrastructure: `custom-high-port`, `silverfox-case-port-weak`, `fallback-c2`
  - transport: `tcp-long-connection`

### 3.3 C2 candidate 生成接入 enrichment

文件：`C:\Users\QAQ\Desktop\gshark\backend\internal\engine\tool_c2.go`

更新：

- `addCSCandidate(...)`
- `addVShellCandidate(...)`

两者现在都会合并 enrichment 输出，且不覆盖已显式传入的更具体字段。

CS candidate 现在可以携带：

```text
actorHints / sampleFamily / campaignStage / transportTraits / infrastructureHints / ttpTags
```

VShell candidate 也会在已有字段基础上合并 enrichment。

### 3.4 HFS 基础设施线索统一

文件：`C:\Users\QAQ\Desktop\gshark\backend\internal\engine\tool_c2.go`

`c2InfraHints` 中 HFS 线索从单一：

```text
hfs-delivery
```

扩展为：

```text
hfs-delivery
hfs-download-chain
```

以对齐 APT Silver Fox profile 中的基础设施字段。

### 3.5 APT 前端类型与 bridge 同步

文件：

- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\core\types.ts`
- `C:\Users\QAQ\Desktop\gshark\frontend\src\app\integrations\wailsBridge.ts`

新增前端字段：

```ts
sourceModule?: string;
```

并映射：

```text
source_module -> sourceModule
```

### 3.6 APT 页面新增 evidence source tabs

文件：`C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\AptAnalysis.tsx`

新增证据来源标签：

- `全部证据`
- `C2 Evidence`
- `Delivery / Object`
- `Threat Hunting`
- `Credential / Auth`

当前筛选逻辑：

- `C2 Evidence`：`sourceModule` 包含 `c2`，或 family 为 `cs` / `vshell`；
- `Delivery / Object`：campaign stage / tags / infra hints 包含 delivery、download、hfs；
- `Threat Hunting`：预留 hunting / yara / threat；
- `Credential / Auth`：预留 credential / auth / login / ntlm。

证据表的 Actor / Type 栏现在展示：

```text
sourceModule · evidenceType · confidence
```

## 4. 测试补充

### 后端测试

文件：`C:\Users\QAQ\Desktop\gshark\backend\internal\engine\c2_analysis_test.go`

新增测试：

```go
TestBuildC2SampleAnalysisAnnotatesSilverFoxCompatibleHTTP
```

该测试构造稳定 GET/POST HTTP 通信，并在 payload 中加入：

- `Winos updater`
- `HFS/2.3`
- HTTPS 端口 443

验证 C2 candidate 会填充：

- `ActorHints` 包含 `Silver Fox / 银狐`
- `SampleFamily = Winos 4.0`
- `InfrastructureHints` 包含 `hfs-download-chain`
- `TransportTraits` 包含 `https-c2`
- `TTPTags` 包含 `multi-stage-delivery`
- APT evidence 能从 C2 metadata 生成，并带 `SourceModule = c2-analysis`

### 前端测试

文件：`C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\AptAnalysis.test.tsx`

更新 mock 与断言：

- evidence 新增 `sourceModule: c2-analysis`
- campaign stage 使用 `delivery`
- infrastructure hints 包含 `hfs-download-chain`
- 验证页面显示：
  - `C2 Evidence`
  - `Delivery / Object`
  - `c2-analysis · c2-indicator`

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
- 前端全量测试：11 个测试文件、43 项通过。
- 前端生产构建通过。
- 后端全量 Go 测试通过。

`go test ./...` 产生的未跟踪 `echo-demo-test-*` 临时目录已安全清理。

## 6. 当前效果

本轮后，C2 → APT 已经形成第一条真实证据通道：

```text
C2 candidate
  -> actorHints / sampleFamily / campaignStage
  -> transportTraits / infrastructureHints / ttpTags
  -> buildAPTAnalysisFromC2
  -> APTEvidenceRecord(source_module=c2-analysis)
  -> APT evidence source tabs
  -> APT 证据表
```

这条通道仍然遵循弱归因原则：

- HFS、Winos、ValleyRAT、Gh0st、18856 / 9899、60 秒周期等仅作为画像字段或兼容线索；
- 不因单一端口、路径或 IOC 直接输出强归因结论；
- APT 页显示的是“组织画像候选证据”，而不是最终 attribution verdict。

## 7. 下一轮建议

第十四轮建议继续做两件事：

1. **将 CS `signalTags` 升级为结构化 `scoreFactors`**
   - `label`
   - `direction: positive | negative`
   - `weight`
   - `evidence`
   - `consumer: c2 | apt`

2. **APT 页面增加归因解释面板**
   - supporting evidence
   - weak observations
   - missing evidence
   - confidence rationale
   - “为什么只是 Silver Fox compatible，而不是强归因”

3. **开始接入非 C2 来源证据**
   - ObjectExport：下载链、文件名、HFS 目录、可疑 EXE / archive；
   - ThreatHunting：YARA / keyword / IOC；
   - Credential/Auth：NTLM / HTTP login / SMTP / MySQL 异常认证线索。
