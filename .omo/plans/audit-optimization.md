# 优化方案：前端 Context 迁移 + 后端 C2 候选上限 + Wire DTO 类型收窄

## TL;DR

> **Quick Summary**: 基于全量审计发现的 1 个 High + 4 个 Medium 问题，制定分 3 个阶段的优化方案。
> 
> **Deliverables**:
> - 前端页面组件从 `useSentinel()` 迁移到子 context hooks
> - 后端 `appendC2DecryptCandidateUnbounded` 添加上限保护
> - Wire DTO 字段类型从 `unknown` 收窄为具体类型
> - `useSentinelProviderBody` useMemo 粒度优化
> 
> **Estimated Effort**: 3-5 天
> **Parallel Execution**: YES - 3 waves

---

## Context

### 审计发现

| # | 问题 | 严重度 | 来源 |
|---|------|--------|------|
| A3 | 所有消费者仍使用 `useSentinel()`，子 context hooks 未被使用 | 🟠 High | 功能/架构审计 |
| F1 | `appendC2DecryptCandidateUnbounded` 无上限保护 | 🟡 Medium | 功能审计 |
| A4 | `useSentinelProviderBody` 组合 20+ hooks，重渲染粒度粗 | 🟡 Medium | 架构审计 |
| M1 | Wire DTO 所有字段类型为 `unknown`，编译期无类型安全 | 🟡 Medium | 模型审计 |
| A5 | 子 context `useMemo` 依赖数组粒度不够细 | 🟡 Medium | 架构审计 |

### 现状分析

**前端 Context 架构**：
```
SentinelContext (38 行 wrapper)
  └─ useSentinelProviderBody (547 行，组合 20+ hooks)
      ├─ BackendProvider → useBackend()    [已定义，未被消费]
      ├─ CaptureProvider → useCapture()    [已定义，未被消费]
      ├─ PacketProvider → usePacket()      [已定义，未被消费]
      ├─ StreamProvider → useStream()      [已定义，未被消费]
      ├─ FilterProvider → useFilter()      [已定义，未被消费]
      └─ AnalysisProvider → useAnalysis()  [已定义，未被消费]
```

**useSentinel() 消费者分布**（非测试文件）：

| 文件 | 使用的字段 | 需要的子 context |
|------|-----------|-----------------|
| Workspace.tsx | displayFilter, setDisplayFilter, applyFilter, clearFilter, filteredPackets, totalPackets, currentPage, totalPages, isPreloadingCapture, preloadProcessed, preloadTotal, capturePreloadDiagnostics, hasMorePackets, hasPrevPackets, isPageLoading, isFilterLoading, packetPageError, captureTransaction, loadMorePackets, loadPrevPackets, jumpToPage, retryPacketPage, locatePacketById, selectedPacket, selectedPacketRawHex, selectedPacketId, selectPacket, protocolTree, fileMeta, openCapture, stopCapture, retryCapturePreloadConfirm, setActiveStream, backendConnected, backendStatus, tsharkStatus | **全部 6 个子 context** |
| C2Analysis.tsx | backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision | Capture + Backend |
| AptAnalysis.tsx | backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision | Capture + Backend |
| IndustrialAnalysis.tsx | backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision | Capture + Backend |
| VehicleAnalysis.tsx | backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision | Capture + Backend |
| UsbAnalysis.tsx | backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision | Capture + Backend |
| EvidencePanel.tsx | backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision | Capture + Backend |
| TrafficGraph.tsx | backendConnected, isPreloadingCapture, totalPackets, fileMeta, setDisplayFilter, applyFilter, captureRevision | Capture + Backend + Filter |
| HttpStream.tsx | httpStream, selectedPacket, streamIds, setActiveStream, streamSwitchMetrics | Stream + Packet |
| RawStreamPage.tsx | tcpStream, udpStream, selectedPacket, streamIds, setActiveStream, streamSwitchMetrics | Stream + Packet |
| ThreatHunting.tsx | backendConnected, threatHits, threatAnalysisProgress, isThreatAnalysisLoading, preparePacketStream | Analysis + Backend + Stream |
| AnalysisCockpit.tsx | fileMeta | Capture |
| MediaAnalysis.tsx | (minimal) | Capture |
| ObjectExport.tsx | extractedObjects, backendConnected | Analysis + Backend |
| CaptureMissionControl.tsx | packets, threatHits, extractedObjects, streamIds, setDisplayFilter, applyFilter, fileMeta, totalPackets, backendConnected, isPreloadingCapture, setActiveStream | **全部 6 个子 context** |
| CaptureWelcomePanel.tsx | backendConnected, backendStatus, captureTransaction, tsharkStatus, recentCaptures, openCapture | Backend + Capture |
| TLSDecryptionDialog.tsx | (minimal) | Backend |
| MainLayout.tsx | (multiple) | **全部 6 个子 context** |

**关键发现**：
- 6 个分析页面（C2/APT/Industrial/Vehicle/USB/Evidence）使用完全相同的字段集：`{ backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision }`
- 3 个页面（Workspace, CaptureMissionControl, MainLayout）使用全部 6 个子 context
- 2 个流页面（HttpStream, RawStreamPage）只使用 Stream + Packet

---

## Work Objectives

### Core Objective
将前端页面组件从 monolithic `useSentinel()` 迁移到细粒度子 context hooks，减少不必要的重渲染。

### Concrete Deliverables
- 所有非测试页面组件使用子 context hooks 替代 `useSentinel()`
- 后端 `appendC2DecryptCandidateUnbounded` 添加 `c2DecryptMaxStreamRecords` 上限
- 高频 Wire DTO 字段类型从 `unknown` 收窄为具体类型
- `useSentinelProviderBody` 的 `useMemo` 依赖数组按子 context 拆分

### Definition of Done
- [ ] `grep -r "useSentinel()" src/app/ --include="*.tsx" | grep -v test` 返回 0 结果
- [ ] `cd backend && go test ./internal/engine/...` 通过
- [ ] `cd frontend && pnpm run typecheck && pnpm run lint && pnpm run test:run` 全部通过
- [ ] `cd frontend && pnpm run size:check` 通过

### Must Have
- 每个页面组件的子 context 迁移必须保持功能不变
- Wire DTO 类型收窄必须向后兼容（可选字段保持 `?`）
- C2 候选上限必须不影响正常解密流程

### Must NOT Have (Guardrails)
- 不修改子 context provider 的接口定义
- 不修改 `useSentinel()` 导出（保持向后兼容）
- 不引入新的 npm 依赖
- 不修改后端 model 包的 JSON tag

---

## Verification Strategy

> **ZERO HUMAN INTERVENTION** — ALL verification is agent-executed.

### Test Decision
- **Infrastructure exists**: YES
- **Automated tests**: Tests-after
- **Framework**: Vitest (frontend), Go test (backend)

### QA Policy
Every task MUST include agent-executed QA scenarios.
Evidence saved to `.omo/evidence/task-{N}-{scenario-slug}.{ext}`.

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (Start Immediately — 独立修复，无依赖):
├── Task 1: 后端 C2 候选上限保护 [quick]
├── Task 2: Wire DTO 类型收窄 — captureWireDtos.ts [quick]
├── Task 3: Wire DTO 类型收窄 — c2SampleWireDtos.ts + c2DecryptWireDtos.ts [quick]
└── Task 4: Wire DTO 类型收窄 — streamWireDtos.ts + trafficWireDtos.ts [quick]

Wave 2 (After Wave 1 — 前端 context 迁移):
├── Task 5: 分析页面批量迁移（6 个页面，相同字段集） [unspecified-high]
├── Task 6: 流页面迁移（HttpStream + RawStreamPage） [quick]
├── Task 7: 独立页面迁移（TrafficGraph, ThreatHunting, ObjectExport, AnalysisCockpit, MediaAnalysis） [unspecified-high]
└── Task 8: 复杂页面迁移（Workspace, CaptureMissionControl, MainLayout） [deep]

Wave 3 (After Wave 2 — useMemo 优化 + 验证):
├── Task 9: useSentinelProviderBody useMemo 粒度拆分 [unspecified-high]
└── Task 10: 全量回归验证 [quick]

Wave FINAL (After ALL tasks — 4 parallel reviews, then user okay):
├── Task F1: Plan compliance audit (oracle)
├── Task F2: Code quality review (unspecified-high)
├── Task F3: Real manual QA (unspecified-high)
└── Task F4: Scope fidelity check (deep)
-> Present results -> Get explicit user okay
```

### Dependency Matrix

| Task | Depends On | Blocks |
|------|-----------|--------|
| 1 | - | 10 |
| 2 | - | 5, 6, 7, 8, 10 |
| 3 | - | 5, 6, 7, 8, 10 |
| 4 | - | 5, 6, 7, 8, 10 |
| 5 | 2, 3, 4 | 9, 10 |
| 6 | 2, 3, 4 | 9, 10 |
| 7 | 2, 3, 4 | 9, 10 |
| 8 | 2, 3, 4 | 9, 10 |
| 9 | 5, 6, 7, 8 | 10 |
| 10 | 1-9 | F1-F4 |

---

## TODOs

- [x] 1. 后端 C2 候选上限保护

  **What to do**:
  - 在 `c2_decrypt.go` 中添加 `c2DecryptMaxStreamRecords = 500` 常量
  - 将 `appendC2DecryptCandidateUnbounded` 改为 `appendC2DecryptCandidateWithLimit(out, seen, candidate, c2DecryptMaxStreamRecords)`
  - 在 `emitVShellStreamCandidates` 中添加上限检查
  - 运行 `go test ./internal/engine/...` 验证

  **Must NOT do**:
  - 不修改 `c2DecryptMaxRecords`（已有常量）
  - 不改变候选优先级排序逻辑

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 2, 3, 4)
  - **Blocks**: Task 10
  - **Blocked By**: None

  **References**:
  - `backend/internal/engine/c2_decrypt.go:49` — `c2DecryptMaxRecords = 500` 常量定义
  - `backend/internal/engine/c2_decrypt.go:269-271` — `appendC2DecryptCandidateUnbounded` 函数
  - `backend/internal/engine/c2_decrypt.go:697,712` — 调用点

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine/...` → PASS
  - [ ] `grep -n "appendC2DecryptCandidateUnbounded" internal/engine/c2_decrypt.go` → 0 结果

  **QA Scenarios**:
  ```
  Scenario: C2 解密候选数量受限
    Tool: Bash
    Preconditions: backend 编译通过
    Steps:
      1. cd backend && go test -run "TestDecryptVShell" ./internal/engine/...
      2. 验证测试通过，无候选丢失
    Expected Result: 测试通过，候选数量不超过 c2DecryptMaxStreamRecords
    Evidence: .omo/evidence/task-1-c2-candidate-limit.txt

  Scenario: 边界情况 — 空候选列表
    Tool: Bash
    Preconditions: backend 编译通过
    Steps:
      1. cd backend && go test -run "TestDecrypt" ./internal/engine/...
      2. 验证空候选不触发 panic
    Expected Result: 测试通过，无 panic
    Evidence: .omo/evidence/task-1-c2-empty-candidates.txt
  ```

  **Commit**: YES
  - Message: `fix(c2): add upper bound to stream decrypt candidates`
  - Files: `backend/internal/engine/c2_decrypt.go`
  - Pre-commit: `cd backend && go test ./internal/engine/...`

- [x] 2. Wire DTO 类型收窄 — captureWireDtos.ts

  **What to do**:
  - 将 `PacketWireDTO` 的字段类型从 `unknown` 收窄为具体类型
  - 将 `PacketColorFeaturesWireDTO` 的字段类型从 `unknown` 收窄为具体类型
  - 将 `PacketsPageWireDTO` 和 `PacketLocateWireDTO` 的字段类型从 `unknown` 收窄为具体类型
  - 更新 `packetMapper.ts` 中的类型断言

  **Must NOT do**:
  - 不修改 `asPacket` 函数的运行时逻辑
  - 不删除任何字段

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1, 3, 4)
  - **Blocks**: Tasks 5, 6, 7, 8, 10
  - **Blocked By**: None

  **References**:
  - `frontend/src/app/integrations/wire/captureWireDtos.ts` — Wire DTO 定义
  - `frontend/src/app/integrations/mappers/packetMapper.ts` — Mapper 函数
  - `backend/internal/model/types_packet.go` — 后端 JSON tag 参考

  **Acceptance Criteria**:
  - [ ] `cd frontend && pnpm run typecheck` → PASS
  - [ ] `cd frontend && pnpm run test:run` → PASS（237 suites）
  - [ ] `captureWireDtos.ts` 中不再有 `unknown` 类型字段

  **QA Scenarios**:
  ```
  Scenario: PacketWireDTO 类型安全
    Tool: Bash
    Preconditions: frontend 编译通过
    Steps:
      1. cd frontend && pnpm run typecheck
      2. 验证无类型错误
    Expected Result: typecheck 通过
    Evidence: .omo/evidence/task-2-capture-wire-typecheck.txt

  Scenario: Packet 映射功能不变
    Tool: Bash
    Preconditions: frontend 测试通过
    Steps:
      1. cd frontend && pnpm run test:run -- src/app/integrations/mappers/packetMapper.test.ts
      2. 验证所有测试通过
    Expected Result: 测试通过
    Evidence: .omo/evidence/task-2-packet-mapper-test.txt
  ```

  **Commit**: YES
  - Message: `refactor(wire): narrow captureWireDtos field types from unknown`
  - Files: `frontend/src/app/integrations/wire/captureWireDtos.ts`, `frontend/src/app/integrations/mappers/packetMapper.ts`
  - Pre-commit: `cd frontend && pnpm run typecheck`

- [x] 3. Wire DTO 类型收窄 — c2SampleWireDtos.ts + c2DecryptWireDtos.ts

  **What to do**:
  - 将 `C2SampleAnalysisWireDTO`、`C2FamilyWireDTO`、`C2IndicatorRecordWireDTO` 等字段类型从 `unknown` 收窄为具体类型
  - 将 `C2DecryptedRecordWireDTO`、`C2DecryptResultWireDTO` 的字段类型从 `unknown` 收窄为具体类型
  - 更新 `c2FamilyMapper.ts` 和 `c2DecryptMapper.ts` 中的类型断言

  **Must NOT do**:
  - 不修改 mapper 函数的运行时逻辑
  - 不删除任何字段

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1, 2, 4)
  - **Blocks**: Tasks 5, 6, 7, 8, 10
  - **Blocked By**: None

  **References**:
  - `frontend/src/app/integrations/wire/c2SampleWireDtos.ts` — C2 Sample Wire DTO
  - `frontend/src/app/integrations/wire/c2DecryptWireDtos.ts` — C2 Decrypt Wire DTO
  - `frontend/src/app/integrations/mappers/c2FamilyMapper.ts` — C2 Family Mapper
  - `backend/internal/model/types_c2.go` — 后端 JSON tag 参考

  **Acceptance Criteria**:
  - [ ] `cd frontend && pnpm run typecheck` → PASS
  - [ ] `c2SampleWireDtos.ts` 和 `c2DecryptWireDtos.ts` 中不再有 `unknown` 类型字段

  **QA Scenarios**:
  ```
  Scenario: C2 Wire DTO 类型安全
    Tool: Bash
    Preconditions: frontend 编译通过
    Steps:
      1. cd frontend && pnpm run typecheck
      2. 验证无类型错误
    Expected Result: typecheck 通过
    Evidence: .omo/evidence/task-3-c2-wire-typecheck.txt

  Scenario: C2 映射功能不变
    Tool: Bash
    Preconditions: frontend 测试通过
    Steps:
      1. cd frontend && pnpm run test:run -- src/app/integrations/mappers/c2SampleMapper.test.ts src/app/integrations/mappers/c2FamilyMapper.test.ts
      2. 验证所有测试通过
    Expected Result: 测试通过
    Evidence: .omo/evidence/task-3-c2-mapper-test.txt
  ```

  **Commit**: YES
  - Message: `refactor(wire): narrow c2SampleWireDtos and c2DecryptWireDtos field types`
  - Files: `frontend/src/app/integrations/wire/c2SampleWireDtos.ts`, `frontend/src/app/integrations/wire/c2DecryptWireDtos.ts`, `frontend/src/app/integrations/mappers/c2FamilyMapper.ts`
  - Pre-commit: `cd frontend && pnpm run typecheck`

- [x] 4. Wire DTO 类型收窄 — streamWireDtos.ts + trafficWireDtos.ts

  **What to do**:
  - 将 `streamWireDtos.ts` 中的字段类型从 `unknown` 收窄为具体类型
  - 将 `trafficWireDtos.ts` 中的字段类型从 `unknown` 收窄为具体类型
  - 更新相关 mapper 中的类型断言

  **Must NOT do**:
  - 不修改 mapper 函数的运行时逻辑

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1, 2, 3)
  - **Blocks**: Tasks 5, 6, 7, 8, 10
  - **Blocked By**: None

  **References**:
  - `frontend/src/app/integrations/wire/streamWireDtos.ts` — Stream Wire DTO
  - `frontend/src/app/integrations/wire/trafficWireDtos.ts` — Traffic Wire DTO
  - `frontend/src/app/integrations/mappers/streamMapper.ts` — Stream Mapper
  - `frontend/src/app/integrations/mappers/trafficMapper.ts` — Traffic Mapper

  **Acceptance Criteria**:
  - [ ] `cd frontend && pnpm run typecheck` → PASS
  - [ ] `streamWireDtos.ts` 和 `trafficWireDtos.ts` 中不再有 `unknown` 类型字段

  **QA Scenarios**:
  ```
  Scenario: Stream/Traffic Wire DTO 类型安全
    Tool: Bash
    Preconditions: frontend 编译通过
    Steps:
      1. cd frontend && pnpm run typecheck
      2. 验证无类型错误
    Expected Result: typecheck 通过
    Evidence: .omo/evidence/task-4-stream-traffic-wire-typecheck.txt
  ```

  **Commit**: YES
  - Message: `refactor(wire): narrow streamWireDtos and trafficWireDtos field types`
  - Files: `frontend/src/app/integrations/wire/streamWireDtos.ts`, `frontend/src/app/integrations/wire/trafficWireDtos.ts`
  - Pre-commit: `cd frontend && pnpm run typecheck`

- [x] 5. 分析页面批量迁移（6 个页面，相同字段集）

  **What to do**:
  - 迁移以下 6 个页面从 `useSentinel()` 到子 context hooks：
    - `C2Analysis.tsx` → `useCapture()` + `useBackend()`
    - `AptAnalysis.tsx` → `useCapture()` + `useBackend()`
    - `IndustrialAnalysis.tsx` → `useCapture()` + `useBackend()`
    - `VehicleAnalysis.tsx` → `useCapture()` + `useBackend()`
    - `UsbAnalysis.tsx` → `useCapture()` + `useBackend()`
    - `EvidencePanel.tsx` → `useCapture()` + `useBackend()`
  - 每个页面使用的字段集完全相同：`{ backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision }`
  - `backendConnected` 来自 `useBackend()`
  - `isPreloadingCapture, fileMeta, totalPackets, captureRevision` 来自 `useCapture()`

  **Must NOT do**:
  - 不修改页面的业务逻辑
  - 不修改子 context provider 的接口定义

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 6, 7, 8)
  - **Blocks**: Tasks 9, 10
  - **Blocked By**: Tasks 2, 3, 4

  **References**:
  - `frontend/src/app/state/contexts/BackendContext.tsx` — `useBackend()` 定义
  - `frontend/src/app/state/contexts/CaptureContext.tsx` — `useCapture()` 定义
  - `frontend/src/app/pages/C2Analysis.tsx:30-33` — 当前 useSentinel 使用
  - `frontend/src/app/pages/AptAnalysis.tsx:27-30` — 当前 useSentinel 使用

  **Acceptance Criteria**:
  - [ ] 6 个页面文件中 `useSentinel` 导入已移除
  - [ ] 6 个页面文件中使用 `useCapture()` + `useBackend()`
  - [ ] `cd frontend && pnpm run typecheck` → PASS
  - [ ] `cd frontend && pnpm run test:run` → PASS

  **QA Scenarios**:
  ```
  Scenario: 分析页面功能不变
    Tool: Bash
    Preconditions: frontend 编译通过
    Steps:
      1. cd frontend && pnpm run test:run -- src/app/pages/C2Analysis.test.tsx src/app/pages/AptAnalysis.test.tsx
      2. 验证所有测试通过
    Expected Result: 测试通过
    Evidence: .omo/evidence/task-5-analysis-pages-test.txt

  Scenario: 无 useSentinel 残留
    Tool: Bash
    Preconditions: 迁移完成
    Steps:
      1. cd frontend && Select-String -Path "src/app/pages/C2Analysis.tsx","src/app/pages/AptAnalysis.tsx","src/app/pages/IndustrialAnalysis.tsx","src/app/pages/VehicleAnalysis.tsx","src/app/pages/UsbAnalysis.tsx","src/app/pages/EvidencePanel.tsx" -Pattern "useSentinel"
      2. 验证无匹配
    Expected Result: 无 useSentinel 引用
    Evidence: .omo/evidence/task-5-no-useSentinel.txt
  ```

  **Commit**: YES
  - Message: `refactor(ui): migrate analysis pages from useSentinel to sub-context hooks`
  - Files: `frontend/src/app/pages/C2Analysis.tsx`, `AptAnalysis.tsx`, `IndustrialAnalysis.tsx`, `VehicleAnalysis.tsx`, `UsbAnalysis.tsx`, `EvidencePanel.tsx`
  - Pre-commit: `cd frontend && pnpm run typecheck`

- [x] 6. 流页面迁移（HttpStream + RawStreamPage）

  **What to do**:
  - 迁移 `HttpStream.tsx` 从 `useSentinel()` 到 `useStream()` + `usePacket()`
  - 迁移 `RawStreamPage.tsx` 从 `useSentinel()` 到 `useStream()` + `usePacket()`
  - 字段映射：
    - `httpStream, tcpStream, udpStream, streamIds, setActiveStream, streamSwitchMetrics` → `useStream()`
    - `selectedPacket` → `usePacket()`

  **Must NOT do**:
  - 不修改流切换逻辑

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 5, 7, 8)
  - **Blocks**: Tasks 9, 10
  - **Blocked By**: Tasks 2, 3, 4

  **References**:
  - `frontend/src/app/state/contexts/StreamContext.tsx` — `useStream()` 定义
  - `frontend/src/app/state/contexts/PacketContext.tsx` — `usePacket()` 定义
  - `frontend/src/app/pages/HttpStream.tsx:19` — 当前 useSentinel 使用
  - `frontend/src/app/pages/RawStreamPage.tsx:39` — 当前 useSentinel 使用

  **Acceptance Criteria**:
  - [ ] `HttpStream.tsx` 和 `RawStreamPage.tsx` 中 `useSentinel` 导入已移除
  - [ ] `cd frontend && pnpm run typecheck` → PASS

  **QA Scenarios**:
  ```
  Scenario: 流页面功能不变
    Tool: Bash
    Preconditions: frontend 编译通过
    Steps:
      1. cd frontend && pnpm run typecheck
      2. 验证无类型错误
    Expected Result: typecheck 通过
    Evidence: .omo/evidence/task-6-stream-pages-typecheck.txt
  ```

  **Commit**: YES
  - Message: `refactor(ui): migrate stream pages from useSentinel to sub-context hooks`
  - Files: `frontend/src/app/pages/HttpStream.tsx`, `frontend/src/app/pages/RawStreamPage.tsx`
  - Pre-commit: `cd frontend && pnpm run typecheck`

- [x] 7. 独立页面迁移（TrafficGraph, ThreatHunting, ObjectExport, AnalysisCockpit, MediaAnalysis）

  **What to do**:
  - 迁移以下 5 个页面从 `useSentinel()` 到子 context hooks：
    - `TrafficGraph.tsx` → `useCapture()` + `useBackend()` + `useFilter()`
    - `ThreatHunting.tsx` → `useBackend()` + `useAnalysis()` + `useStream()`
    - `ObjectExport.tsx` → `useAnalysis()` + `useBackend()`
    - `AnalysisCockpit.tsx` → `useCapture()`
    - `MediaAnalysis.tsx` → `useCapture()`

  **Must NOT do**:
  - 不修改页面的业务逻辑

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 5, 6, 8)
  - **Blocks**: Tasks 9, 10
  - **Blocked By**: Tasks 2, 3, 4

  **References**:
  - `frontend/src/app/state/contexts/FilterContext.tsx` — `useFilter()` 定义
  - `frontend/src/app/state/contexts/AnalysisContext.tsx` — `useAnalysis()` 定义
  - `frontend/src/app/pages/TrafficGraph.tsx:16-20` — 当前 useSentinel 使用
  - `frontend/src/app/pages/ThreatHunting.tsx:28-31` — 当前 useSentinel 使用

  **Acceptance Criteria**:
  - [ ] 5 个页面文件中 `useSentinel` 导入已移除
  - [ ] `cd frontend && pnpm run typecheck` → PASS

  **QA Scenarios**:
  ```
  Scenario: 独立页面功能不变
    Tool: Bash
    Preconditions: frontend 编译通过
    Steps:
      1. cd frontend && pnpm run test:run -- src/app/pages/AnalysisCockpit.test.tsx
      2. 验证所有测试通过
    Expected Result: 测试通过
    Evidence: .omo/evidence/task-7-independent-pages-test.txt
  ```

  **Commit**: YES
  - Message: `refactor(ui): migrate independent pages from useSentinel to sub-context hooks`
  - Files: `frontend/src/app/pages/TrafficGraph.tsx`, `ThreatHunting.tsx`, `ObjectExport.tsx`, `AnalysisCockpit.tsx`, `MediaAnalysis.tsx`
  - Pre-commit: `cd frontend && pnpm run typecheck`

- [x] 8. 复杂页面迁移（Workspace, CaptureMissionControl, MainLayout）

  **What to do**:
  - 迁移以下 3 个复杂页面从 `useSentinel()` 到子 context hooks：
    - `Workspace.tsx` → 使用全部 6 个子 context hooks
    - `CaptureMissionControl.tsx` → 使用全部 6 个子 context hooks
    - `MainLayout.tsx` → 使用全部 6 个子 context hooks
  - 这些页面使用大量字段，需要仔细验证每个字段的来源

  **Must NOT do**：
  - 不修改页面的业务逻辑
  - 不修改子 context provider 的接口定义

  **Recommended Agent Profile**:
  - **Category**: `deep`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 5, 6, 7)
  - **Blocks**: Tasks 9, 10
  - **Blocked By**: Tasks 2, 3, 4

  **References**:
  - `frontend/src/app/pages/Workspace.tsx:30-67` — 当前 useSentinel 使用（38 个字段）
  - `frontend/src/app/components/CaptureMissionControl.tsx:28-32` — 当前 useSentinel 使用
  - `frontend/src/app/components/MainLayout.tsx:49` — 当前 useSentinel 使用
  - `frontend/src/app/state/contexts/index.ts` — 所有子 context 导出

  **Acceptance Criteria**：
  - [ ] 3 个文件中 `useSentinel` 导入已移除
  - [ ] `cd frontend && pnpm run typecheck` → PASS
  - [ ] `cd frontend && pnpm run test:run` → PASS

  **QA Scenarios**:
  ```
  Scenario: Workspace 功能不变
    Tool: Bash
    Preconditions: frontend 编译通过
    Steps:
      1. cd frontend && pnpm run test:run -- src/app/pages/Workspace.test.tsx
      2. 验证所有测试通过
    Expected Result: 测试通过
    Evidence: .omo/evidence/task-8-workspace-test.txt

  Scenario: 全量测试通过
    Tool: Bash
    Preconditions: 迁移完成
    Steps:
      1. cd frontend && pnpm run test:run
      2. 验证 237 suites 全部通过
    Expected Result: 237 suites, 766 tests 全部通过
    Evidence: .omo/evidence/task-8-full-test.txt
  ```

  **Commit**: YES
  - Message: `refactor(ui): migrate complex pages from useSentinel to sub-context hooks`
  - Files: `frontend/src/app/pages/Workspace.tsx`, `frontend/src/app/components/CaptureMissionControl.tsx`, `frontend/src/app/components/MainLayout.tsx`
  - Pre-commit: `cd frontend && pnpm run typecheck`

- [x] 9. useSentinelProviderBody useMemo 粒度拆分

  **What to do**：
  - 将 `useSentinelProviderBody.ts` 中的单个大 `useMemo`（依赖 50+ 变量）拆分为按子 context 的独立 `useMemo`
  - 每个子 context 的 value 对象只依赖该子 context 相关的变量
  - 减少不必要的重渲染：当只有 `threatHits` 变化时，`PacketProvider` 不应重新计算

  **Must NOT do**：
  - 不修改子 context provider 的接口定义
  - 不修改 `useSentinel()` 的返回值

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 3 (after Tasks 5-8)
  - **Blocks**: Task 10
  - **Blocked By**: Tasks 5, 6, 7, 8

  **References**:
  - `frontend/src/app/state/useSentinelProviderBody.ts:409-547` — 当前 useMemo 定义
  - `frontend/src/app/state/contexts/BackendContext.tsx` — BackendContextValue 定义
  - `frontend/src/app/state/contexts/CaptureContext.tsx` — CaptureContextValue 定义

  **Acceptance Criteria**：
  - [ ] `useSentinelProviderBody.ts` 中有 6 个独立的 `useMemo`（每个子 context 一个）
  - [ ] `cd frontend && pnpm run typecheck` → PASS
  - [ ] `cd frontend && pnpm run test:run` → PASS

  **QA Scenarios**：
  ```
  Scenario: useMemo 拆分后功能不变
    Tool: Bash
    Preconditions: frontend 编译通过
    Steps:
      1. cd frontend && pnpm run test:run
      2. 验证 237 suites 全部通过
    Expected Result: 237 suites, 766 tests 全部通过
    Evidence: .omo/evidence/task-9-usememo-split-test.txt

  Scenario: 无 ESLint 警告
    Tool: Bash
    Preconditions: 迁移完成
    Steps:
      1. cd frontend && pnpm run lint
      2. 验证无警告
    Expected Result: lint 通过
    Evidence: .omo/evidence/task-9-lint.txt
  ```

  **Commit**: YES
  - Message: `refactor(state): split useSentinelProviderBody useMemo into per-context memoization`
  - Files: `frontend/src/app/state/useSentinelProviderBody.ts`
  - Pre-commit: `cd frontend && pnpm run typecheck`

- [x] 10. 全量回归验证

  **What to do**：
  - 运行完整的 CI 检查套件：
    - `cd frontend && pnpm run typecheck`
    - `cd frontend && pnpm run lint`
    - `cd frontend && pnpm run format:check`
    - `cd frontend && pnpm run size:check`
    - `cd frontend && pnpm run boundary:check`
    - `cd frontend && pnpm run test:run`
    - `cd backend && go test ./...`
    - `cd backend && go vet ./...`
    - `cd backend && gofmt -l .`
  - 验证所有检查通过

  **Must NOT do**：
  - 不修改任何代码

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: []

  **Parallelization**：
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 3 (after Task 9)
  - **Blocks**: F1-F4
  - **Blocked By**: Tasks 1-9

  **References**：
  - `scripts/check-all.ps1` — 全量检查脚本

  **Acceptance Criteria**：
  - [ ] `cd frontend && pnpm run typecheck` → PASS
  - [ ] `cd frontend && pnpm run lint` → PASS（0 warnings）
  - [ ] `cd frontend && pnpm run format:check` → PASS
  - [ ] `cd frontend && pnpm run size:check` → PASS
  - [ ] `cd frontend && pnpm run boundary:check` → PASS
  - [ ] `cd frontend && pnpm run test:run` → PASS（237 suites, 766 tests）
  - [ ] `cd backend && go test ./...` → PASS（8 packages）
  - [ ] `cd backend && go vet ./...` → PASS
  - [ ] `cd backend && gofmt -l .` → 干净

  **QA Scenarios**：
  ```
  Scenario: 全量 CI 检查通过
    Tool: Bash
    Preconditions: 所有任务完成
    Steps:
      1. cd frontend && pnpm run typecheck && pnpm run lint && pnpm run format:check && pnpm run size:check && pnpm run boundary:check && pnpm run test:run
      2. cd backend && go test ./... && go vet ./... && gofmt -l .
      3. 验证所有检查通过
    Expected Result: 所有检查通过
    Evidence: .omo/evidence/task-10-full-ci.txt
  ```

  **Commit**: NO

---

## Final Verification Wave

- [x] F1. **Plan Compliance Audit** — `oracle`
  Read the plan end-to-end. For each "Must Have": verify implementation exists. For each "Must NOT Have": search codebase for forbidden patterns. Check evidence files exist.
  Output: `Must Have [N/N] | Must NOT Have [N/N] | Tasks [N/N] | VERDICT: APPROVE/REJECT`

- [x] F2. **Code Quality Review** — `unspecified-high`
  Run `tsc --noEmit` + linter + `pnpm run test:run`. Review all changed files for: `as any`/`@ts-ignore`, empty catches, console.log in prod, commented-out code, unused imports.
  Output: `Build [PASS/FAIL] | Lint [PASS/FAIL] | Tests [N pass/N fail] | Files [N clean/N issues] | VERDICT`

- [x] F3. **Real Manual QA** — `unspecified-high`
  Start from clean state. Execute EVERY QA scenario from EVERY task. Test cross-task integration.
  Output: `Scenarios [N/N pass] | Integration [N/N] | Edge Cases [N tested] | VERDICT`

- [x] F4. **Scope Fidelity Check** — `deep`
  For each task: read "What to do", read actual diff. Verify 1:1 — everything in spec was built, nothing beyond spec was built.
  Output: `Tasks [N/N compliant] | Contamination [CLEAN/N issues] | Unaccounted [CLEAN/N files] | VERDICT`

---

## Commit Strategy

| Task | Commit Message | Files |
|------|---------------|-------|
| 1 | `fix(c2): add upper bound to stream decrypt candidates` | `backend/internal/engine/c2_decrypt.go` |
| 2 | `refactor(wire): narrow captureWireDtos field types from unknown` | `captureWireDtos.ts`, `packetMapper.ts` |
| 3 | `refactor(wire): narrow c2SampleWireDtos and c2DecryptWireDtos field types` | `c2SampleWireDtos.ts`, `c2DecryptWireDtos.ts`, `c2FamilyMapper.ts` |
| 4 | `refactor(wire): narrow streamWireDtos and trafficWireDtos field types` | `streamWireDtos.ts`, `trafficWireDtos.ts` |
| 5 | `refactor(ui): migrate analysis pages from useSentinel to sub-context hooks` | 6 analysis page files |
| 6 | `refactor(ui): migrate stream pages from useSentinel to sub-context hooks` | `HttpStream.tsx`, `RawStreamPage.tsx` |
| 7 | `refactor(ui): migrate independent pages from useSentinel to sub-context hooks` | 5 independent page files |
| 8 | `refactor(ui): migrate complex pages from useSentinel to sub-context hooks` | `Workspace.tsx`, `CaptureMissionControl.tsx`, `MainLayout.tsx` |
| 9 | `refactor(state): split useSentinelProviderBody useMemo into per-context memoization` | `useSentinelProviderBody.ts` |

---

## Success Criteria

### Verification Commands
```bash
cd frontend && pnpm run typecheck   # Expected: PASS
cd frontend && pnpm run lint        # Expected: 0 warnings
cd frontend && pnpm run format:check # Expected: PASS
cd frontend && pnpm run size:check  # Expected: PASS
cd frontend && pnpm run boundary:check # Expected: PASS
cd frontend && pnpm run test:run    # Expected: 237 suites, 766 tests PASS
cd backend && go test ./...         # Expected: 8 packages PASS
cd backend && go vet ./...          # Expected: PASS
cd backend && gofmt -l .            # Expected: (empty)
```

### Final Checklist
- [ ] All "Must Have" present
- [ ] All "Must NOT Have" absent
- [ ] All tests pass
- [ ] No `useSentinel()` in non-test production code
- [ ] No `appendC2DecryptCandidateUnbounded` calls
- [ ] No `unknown` type fields in narrowed Wire DTOs
