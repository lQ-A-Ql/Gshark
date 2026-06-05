# Frontend Performance and Evidence Stability Repair

## TL;DR
> **Summary**: Fix three reported defects with a compatibility-preserving repair: Traffic Graph topology correctness, Evidence Wails IPC timeout/cold-load stability, and route-switch/UI jank. The plan avoids broad rewrites and adds executable tests plus timing evidence before deeper optimization.
> **Deliverables**:
> - Backend/frontend traffic topology contract fix using explicit `top_conversations` edges while preserving `top_talkers`.
> - Evidence typed IPC timeout stopgap, collector timing instrumentation, scoped/paged loading, and large-list render cap.
> - Route transition/remount jank reduction and targeted backend in-flight dedupe for known cold builders.
> - Regression tests and full verification evidence under `.omo/evidence/`.
> **Effort**: Medium
> **Parallel**: YES - 4 waves
> **Critical Path**: Task 1 → Task 2 → Task 4 → Final Verification Wave

## Context
### Original Request
User reported:
- 流量图分析显示异常.
- 前端页面切换明显卡顿.
- 证据页返回 Wails IPC typed-ipc 请求超时：`DesktopApp.GetEvidenceWithFilter（10000ms）`（偶发性）.
- Then requested: `制定修复方案`.

### Interview Summary
- The diagnosis is evidence-backed from direct code reads plus explore/librarian agents.
- No additional user decisions are blocking; defaults are encoded below.
- This is a repair plan, not a redesign plan.

### Research Findings
- Traffic topology contract bug: backend `top_talkers` is endpoint-only, while frontend `TrafficGraphPanels.tsx` parses labels as `src -> dst` conversation edges.
- Wails v2 does not impose a 10s default timeout; app frontend `typedCall` default is 10000ms.
- `GetEvidenceWithFilter` uses the default typed IPC timeout even though Go desktop proxy/backend allow 30s and Evidence aggregation can be cold/heavy.
- Wails v2 JS timeout rejects the Promise but does not cancel the Go method.
- Evidence cold aggregation serially touches many heavy modules: hunting, C2, APT, industrial, object, vehicle, USB, media, misc.
- Workspace overview concurrently prefetches global traffic/industrial/vehicle/media/USB and can contend with Evidence cold-load.
- Route switching jank has likely contributors: pathname-keyed route subtree remount, blur/filter-heavy animations, non-virtualized Evidence table, and repeated large-list transforms.

### Metis Review (gaps addressed)
- Preserve API compatibility: keep `top_talkers` exactly endpoint-oriented.
- Add a new explicit traffic edge contract; do not infer graph edges from labels.
- Treat longer IPC timeout as a stopgap, not the root fix.
- Add collector timing/status instrumentation and executable acceptance criteria.
- Avoid broad UI redesign, global timeout changes, framework changes, and full cache rewrites.

### Oracle Verification (phase 1)
- `VERDICT: GO`
- Required precision encoded:
  - New traffic contract: `top_conversations: [{ src, dst, count }]`.
  - Evidence default page behavior: fetch current backend Evidence response but render-limit the table to 200 rows initially; all-visible expansion/export remains explicit.
  - Route jank criteria: no pathname-keyed route remount; no route transition CSS `filter`, `blur`, or `backdrop-filter`.
  - Targeted singleflight builders: global traffic stats, industrial, vehicle, USB default options, media analysis, and C2 analysis. Object export/YARA is explicitly excluded from this repair plan.

## Work Objectives
### Core Objective
Make Traffic Graph accurate, Evidence loading stable under cold-cache desktop usage, and route switching measurably less janky without changing product scope or visual identity.

### Deliverables
- Backend `GlobalTrafficStats` includes explicit `top_conversations` directional edges.
- Frontend traffic topology consumes `topConversations`, not parsed `topTalkers` labels.
- Evidence typed IPC uses explicit 30s timeout and reports collector timing.
- Evidence UI renders page-limited rows by default and keeps full export behavior explicit.
- Route transitions avoid forced remount and blur/filter-heavy animation.
- Targeted backend in-flight dedupe prevents duplicate cold builds for overlapping requests.

### Definition of Done (verifiable conditions with commands)
- `cd backend && go test ./...` passes.
- `cd frontend && pnpm run test:run` passes or only pre-existing unrelated flaky test is documented with focused pass.
- `cd frontend && pnpm run typecheck` passes.
- `cd frontend && pnpm run lint` passes.
- `cd frontend && pnpm run format:check` passes.
- `cd frontend && pnpm run build` passes.
- Evidence files exist:
  - `.omo/evidence/task-1-traffic-contract.txt`
  - `.omo/evidence/task-2-traffic-ui.txt`
  - `.omo/evidence/task-3-evidence-ipc.txt`
  - `.omo/evidence/task-4-evidence-render.txt`
  - `.omo/evidence/task-5-route-jank.txt`
  - `.omo/evidence/task-6-singleflight.txt`
  - `.omo/evidence/final-verification.md`

### Must Have
- Preserve `top_talkers` response meaning and shape.
- Add `top_conversations` as a new compatibility-safe field.
- Use explicit Evidence typed IPC timeout of 30000ms only for Evidence calls.
- Add module-level Evidence collector timing logs/status details.
- Keep Evidence full export available but not render all records by default.
- Use tests to lock traffic contract, timeout config, pagination/row cap, route CSS/remount behavior, and singleflight behavior.

### Must NOT Have
- No global typed IPC timeout increase.
- No full Evidence architecture rewrite.
- No new frontend/backend framework.
- No broad visual redesign.
- No parsing endpoint labels as graph edges.
- No changing product branding or compatibility identifiers.
- No human-only acceptance criterion like “looks smoother”.

## Verification Strategy
> ZERO HUMAN INTERVENTION - all verification is agent-executed.
- Test decision: tests-after + focused regression tests + existing suites.
- QA policy: Every task includes agent-executed happy and failure/edge scenarios.
- Evidence: `.omo/evidence/task-{N}-{slug}.{ext}`.

## Execution Strategy
### Parallel Execution Waves
> Target: 5-8 tasks per wave. This repair has shared backend/frontend dependencies, so waves are smaller to avoid conflicts.

Wave 1: Task 1 traffic backend contract, Task 3 Evidence IPC/instrumentation foundation.
Wave 2: Task 2 traffic frontend mapping, Task 6 targeted singleflight.
Wave 3: Task 4 Evidence render/page cap, Task 5 route jank CSS/remount.
Wave 4: Task 7 verification hardening and evidence consolidation.

### Dependency Matrix (full, all tasks)
- Task 1 blocks Task 2.
- Task 3 partially blocks Task 4 because paging/scoping should reuse Evidence request semantics and timing labels.
- Task 6 can run after Task 3 identifies timing labels but should avoid editing the same functions concurrently with Task 3.
- Task 5 is independent of Tasks 1-4 except final integration verification.
- Task 7 depends on Tasks 1-6.

### Agent Dispatch Summary
- Wave 1 → 2 tasks → `unspecified-high`, `quick`.
- Wave 2 → 2 tasks → `visual-engineering`, `unspecified-high`.
- Wave 3 → 2 tasks → `visual-engineering`, `quick`.
- Wave 4 → 1 task → `unspecified-high`.

## TODOs
> Implementation + Test = ONE task. Never separate.
> EVERY task MUST have: Agent Profile + Parallelization + QA Scenarios.

- [x] 1. Add explicit backend traffic conversation contract

  **What to do**: Add a new backend traffic edge field while preserving existing endpoint `top_talkers`.
  - Update `backend/internal/model/types_packet.go` with a new struct, exactly:
    - Add `TrafficConversation` with fields `Src string` tagged `json:"src"`, `Dst string` tagged `json:"dst"`, and `Count int` tagged `json:"count"`.
    - Add `TopConversations []TrafficConversation json:"top_conversations"` to `GlobalTrafficStats`.
  - Update `backend/internal/tshark/traffic_stats.go` accumulator:
    - Keep current `talkerMap` behavior unchanged for `TopTalkers`.
    - Add a separate `conversationMap map[string]conversationCount` keyed internally by `src + "\x00" + dst`.
    - For each packet row with non-empty `src` and `dst`, increment directional edge `src -> dst` by 1.
    - Empty src/dst rows must not create conversation edges.
    - Sort `TopConversations` by `count desc`, then `src asc`, then `dst asc`.
    - Limit `TopConversations` to 200 edges to bound frontend topology work.
  - Update backend contract tests in `backend/internal/transport/http_contract_test.go` and/or `backend/internal/tshark/traffic_stats_test.go`:
    - Confirm `top_talkers` remains endpoint-only.
    - Confirm `top_conversations` contains directional `{src,dst,count}` edges.
    - Include IPv6 and one-way traffic test if the existing test fixture format supports it.

  **Must NOT do**:
  - Do not rename or change `top_talkers`.
  - Do not encode conversations as display labels.
  - Do not add protocol/port fields in this task; keep first contract minimal.

  **Recommended Agent Profile**:
  - Category: `unspecified-high` - Reason: backend DTO contract and tshark aggregation correctness.
  - Skills: [] - No special skill required beyond Go/testing.
  - Omitted: `playwright` - Backend-only task.

  **Parallelization**: Can Parallel: YES | Wave 1 | Blocks: Task 2 | Blocked By: none

  **References**:
  - Pattern: `backend/internal/model/types_packet.go:193-207` - existing `GlobalTrafficStats` DTO.
  - Pattern: `backend/internal/tshark/traffic_stats.go:107-118` - current endpoint talker counting; preserve this for `TopTalkers`.
  - Pattern: `backend/internal/tshark/traffic_stats.go:178-190` - current finish/top bucket assembly.
  - Pattern: `backend/internal/tshark/traffic_stats.go:243-257` - count-desc/label-asc sorting style to mirror.
  - Test: `backend/internal/tshark/traffic_stats_test.go` - existing accumulator tests.
  - Test: `backend/internal/transport/http_contract_test.go:413-426` - stable response key checks.

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/tshark -run TestGlobalTrafficStats -count=1 -v` passes.
  - [ ] `cd backend && go test ./internal/transport -run TestGlobalTrafficStatsContract -count=1 -v` passes.
  - [ ] Test output or fixture confirms `top_conversations[0]` has separate `src`, `dst`, and `count` fields.
  - [ ] Existing `top_talkers` test expectation remains endpoint-only, not `src -> dst`.

  **QA Scenarios**:
  ```
  Scenario: Directional conversation edge emitted
    Tool: Bash
    Steps: cd backend; go test ./internal/tshark -run TestGlobalTrafficStatsAccumulatorConsumesRows -count=1 -v
    Expected: Test passes and asserts `top_conversations` contains expected src/dst/count.
    Evidence: .omo/evidence/task-1-traffic-contract.txt

  Scenario: Empty endpoint rows do not fabricate topology
    Tool: Bash
    Steps: cd backend; go test ./internal/tshark -run TestGlobalTrafficStats -count=1 -v
    Expected: Test passes with no conversation edge for blank src or dst.
    Evidence: .omo/evidence/task-1-traffic-contract-edge.txt
  ```

  **Commit**: NO | Message: included in final commit `fix(app): stabilize traffic graph and evidence loading` | Files: `backend/internal/model/types_packet.go`, `backend/internal/tshark/traffic_stats.go`, backend tests

- [x] 2. Update Traffic Graph frontend to consume explicit conversations

  **What to do**: Map and render topology from `top_conversations` only.
  - Update frontend traffic types in `frontend/src/app/core/types/traffic.ts`:
    - Add `TrafficConversation { src: string; dst: string; count: number }`.
    - Add `topConversations: TrafficConversation[]` to `GlobalTrafficStats`.
  - Update wire DTO in `frontend/src/app/integrations/wire/trafficWireDtos.ts` with `top_conversations?: { src?: unknown; dst?: unknown; count?: unknown }[]` or stricter existing style.
  - Update mapper `frontend/src/app/integrations/mappers/trafficMapper.ts`:
    - Map `top_conversations` to `topConversations`.
    - Coerce src/dst to trimmed strings and count to number.
    - Drop entries with empty src or dst.
  - Update `frontend/src/app/features/traffic/TrafficGraphPanels.tsx`:
    - Accept `topConversations` prop.
    - Build topology edges from `{src,dst,count}` directly.
    - Do not split `topTalkers.label` anywhere for topology.
    - Memoize `timelinePoints`, `topologyEdges`, and `chartPanels` with `useMemo` to prevent avoidable recomputation.
  - Update `frontend/src/app/pages/TrafficGraph.tsx` to pass `stats.topConversations`.
  - Update `buildStatsFromPackets` fallback in `frontend/src/app/features/traffic/useTrafficGraph.ts`:
    - Generate `topConversations` from packet `source -> destination` if source/destination exist.
    - Keep `topTalkers` endpoint-based.
    - Keep fallback `timeline`/`protocolHierarchy` behavior unchanged unless tests require minimal defaults.
  - Add/extend tests:
    - `trafficMapper.test.ts` maps `top_conversations`.
    - `TrafficGraphPanels` or helper test proves topology uses conversations and ignores endpoint-only `topTalkers`.

  **Must NOT do**:
  - Do not parse `topTalkers.label` as an edge.
  - Do not redesign graph styling.
  - Do not remove existing bar charts.

  **Recommended Agent Profile**:
  - Category: `visual-engineering` - Reason: frontend data mapping plus graph component rendering.
  - Skills: [] - Existing React/Vitest patterns are enough.
  - Omitted: `frontend-design` - This is correctness/performance, not new visual design.

  **Parallelization**: Can Parallel: YES | Wave 2 | Blocks: Task 7 | Blocked By: Task 1

  **References**:
  - Pattern: `frontend/src/app/integrations/mappers/trafficMapper.ts:14-30` - DTO mapping style.
  - Pattern: `frontend/src/app/features/traffic/TrafficGraphPanels.tsx:45-69` - current derived arrays and topology edge creation.
  - Pattern: `frontend/src/app/features/traffic/TrafficTopologyGraph.tsx:33-100` - memoized topology layout consuming edges.
  - Test: `frontend/src/app/integrations/mappers/trafficMapper.test.ts` - mapper test style.
  - Test: `frontend/src/app/features/traffic/TrafficGraphOverview.test.tsx` - component test style.

  **Acceptance Criteria**:
  - [ ] `cd frontend && pnpm run test:run -- trafficMapper TrafficGraph` passes.
  - [ ] A test with endpoint-only `topTalkers` and empty `topConversations` renders empty topology rather than fake edges.
  - [ ] A test with `topConversations: [{src:"10.0.0.1",dst:"10.0.0.2",count:3}]` renders/constructs a topology edge.
  - [ ] `cd frontend && pnpm run typecheck` passes.

  **QA Scenarios**:
  ```
  Scenario: Topology renders explicit conversation edge
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- trafficMapper TrafficGraph
    Expected: Tests pass and assert conversation mapping/topology edge behavior.
    Evidence: .omo/evidence/task-2-traffic-ui.txt

  Scenario: Endpoint top talkers are not parsed as edges
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- TrafficGraph
    Expected: Test passes with no fabricated edge from label `10.0.0.1`.
    Evidence: .omo/evidence/task-2-traffic-ui-edge.txt
  ```

  **Commit**: NO | Message: included in final commit `fix(app): stabilize traffic graph and evidence loading` | Files: frontend traffic types/mapper/components/tests

- [x] 3. Stabilize Evidence typed IPC with explicit timeout and collector timings

  **What to do**: Make Evidence timeout explicit and observable without pretending timeout alone fixes cold-load cost.
  - Update `frontend/src/app/integrations/desktopTypedBridgeAnalysis.ts`:
    - `getEvidence` and `getEvidenceWithFilter` must call `typedCall(..., ..., signal, 30000)` or use a named constant `EVIDENCE_TYPED_IPC_TIMEOUT_MS = 30000` exported near the typed bridge core.
    - Do not change the global default `DEFAULT_TYPED_IPC_TIMEOUT_MS = 10000`.
  - Update/extend `frontend/src/app/integrations/desktopBridge.test.ts` or typed bridge tests:
    - Confirm Evidence timeout error message now references `30000ms` when a mocked Evidence Wails call never resolves.
    - Confirm unrelated quick typed calls still use `10000ms` if existing tests cover this.
  - Update `backend/internal/engine/evidence.go`:
    - Add per-module timing wrapper around each collector call.
    - Emit status entries through existing `s.emitStatus(...)` with module name, duration, record count, and error/canceled state.
    - Keep existing partial-success behavior: collector errors are skipped unless context canceled.
    - Ensure context cancellation still exits promptly between modules.
  - Use stable status text prefix exactly: `__evidence_timing__:<module>:<duration_ms>:<records>:<status>` so frontend/debug tooling can parse later.
  - Add backend unit test using a service status hook/channel or existing status capture helper to assert at least one emitted status matches regex `^__evidence_timing__:[a-z]+:[0-9]+:[0-9]+:(ok|error|canceled)$` during a focused `GatherEvidence` call.

  **Must NOT do**:
  - Do not globally increase typed IPC timeout.
  - Do not remove frontend timeout handling.
  - Do not make Evidence collector errors fail the whole response unless context canceled.

  **Recommended Agent Profile**:
  - Category: `quick` - Reason: bounded bridge timeout and instrumentation changes.
  - Skills: [] - No special skill required.
  - Omitted: `external-context` - Wails docs research already completed.

  **Parallelization**: Can Parallel: YES | Wave 1 | Blocks: Task 4 and Task 6 | Blocked By: none

  **References**:
  - Pattern: `frontend/src/app/integrations/desktopTypedBridgeCore.ts:3-17` - default and long typed timeout usage.
  - Pattern: `frontend/src/app/integrations/desktopTypedBridgeAnalysis.ts:62-71` - Evidence typed calls needing explicit timeout.
  - Pattern: `frontend/src/app/integrations/desktopIpcControls.ts:65-86` - timeout error behavior.
  - Pattern: `desktop_backend_proxy.go:1090-1112` - Go proxy already allows 30s.
  - Pattern: `backend/internal/engine/evidence.go:30-127` - sequential Evidence collector structure.
  - Test: `frontend/src/app/integrations/desktopBridge.test.ts` - desktop bridge behavior tests.
  - Test: `backend/internal/engine/evidence_test.go` - Evidence aggregation/cancellation tests.

  **Acceptance Criteria**:
  - [ ] Evidence typed timeout tests prove `DesktopApp.GetEvidenceWithFilter` uses 30000ms.
  - [ ] Existing non-Evidence typed calls are not globally changed to 30000ms.
  - [ ] Backend Evidence timing emits `__evidence_timing__` status entries via `s.emitStatus(...)` per attempted module.
  - [ ] Backend test asserts emitted status matches `^__evidence_timing__:[a-z]+:[0-9]+:[0-9]+:(ok|error|canceled)$`.
  - [ ] `cd backend && go test ./internal/engine -run TestGatherEvidence -count=1 -v` passes.
  - [ ] `cd frontend && pnpm run test:run -- desktopBridge` passes.

  **QA Scenarios**:
  ```
  Scenario: Evidence typed IPC no longer fails at 10000ms
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- desktopBridge
    Expected: Test asserts Evidence timeout budget is 30000ms while default remains 10000ms for unrelated calls.
    Evidence: .omo/evidence/task-3-evidence-ipc.txt

  Scenario: Evidence collector timing survives cancellation path
    Tool: Bash
    Steps: cd backend; go test ./internal/engine -run TestGatherEvidence -count=1 -v
    Expected: Tests pass; cancellation behavior remains intact.
    Evidence: .omo/evidence/task-3-evidence-ipc-backend.txt
  ```

  **Commit**: NO | Message: included in final commit `fix(app): stabilize traffic graph and evidence loading` | Files: typed bridge files/tests, `backend/internal/engine/evidence.go`, backend tests

- [x] 4. Add Evidence page-limited rendering and scoped loading controls

  **What to do**: Prevent the Evidence page from rendering all records by default and make expensive all-module/full-list behavior explicit.
  - Default Evidence page behavior:
    - Initial load uses current selected modules if any; if no modules are selected, still request all modules but render only first 200 filtered/sorted records.
    - Add UI text showing `Showing 200 of N evidence records` when capped.
    - Add an explicit control `Show next 200` or pagination to increase visible rows by 200 increments.
    - Keep export action exporting all records that match current filters from the already fetched Evidence response; do not fetch additional modules, do not bypass current filters, and do not expand visible rows automatically.
    - Add explicit `Show all visible rows` action if needed; this only expands render limit to current filtered record count and must not trigger a backend fetch.
  - Update `frontend/src/app/features/evidence/useEvidencePanelModel.ts`:
    - Keep metrics/facets over all fetched records.
    - Return `visibleRecords`, `visibleLimit`, `hasMoreVisibleRecords`, and a setter/increment callback.
    - Keep selected record lookup valid for currently visible rows; if selection is outside visible slice after filter changes, reset to first visible record.
  - Update `frontend/src/app/features/evidence/EvidenceResults.tsx` or section wrapper to render `visibleRecords` through `AnalysisDataTable`.
  - Optimize obvious repeated scans in `evidencePanelRules.ts` only if needed for tests; prefer small helper maps over broad rewrite.
  - Add tests with at least 500 synthetic records:
    - Initial table row count is capped at 200.
    - `Show next 200` increases rows to 400.
    - Search/filter still uses all fetched records and updates counts.
    - Export still includes all filtered records, not only visible rows.

  **Must NOT do**:
  - Do not introduce a new table library.
  - Do not remove existing Evidence detail/report/facet sections.
  - Do not change backend `/api/evidence` semantics in this task.

  **Recommended Agent Profile**:
  - Category: `visual-engineering` - Reason: frontend page UX and render-performance behavior.
  - Skills: [] - Existing React/Vitest patterns sufficient.
  - Omitted: `playwright` - Component tests are primary; Playwright remains final QA optional.

  **Parallelization**: Can Parallel: YES | Wave 3 | Blocks: Task 7 | Blocked By: Task 3

  **References**:
  - Pattern: `frontend/src/app/pages/EvidencePanel.tsx:44-60` - Evidence model wiring.
  - Pattern: `frontend/src/app/features/evidence/useEvidencePanelModel.ts:16-32` - current model outputs.
  - Pattern: `frontend/src/app/features/evidence/EvidenceResults.tsx:70-149` - result rendering.
  - Pattern: `frontend/src/app/components/analysis/AnalysisDataTable.tsx:88-151` - non-virtualized table mapping all rows.
  - Pattern: `frontend/src/app/features/evidence/evidencePanelRules.ts:72-78` - full-list sort.
  - Test: `frontend/src/app/pages/EvidencePanel.test.tsx` - Evidence page component tests.

  **Acceptance Criteria**:
  - [ ] `cd frontend && pnpm run test:run -- EvidencePanel evidencePanelRules` passes.
  - [ ] Test with 500 records renders at most 200 data rows initially.
  - [ ] Test proves export uses all filtered records, not only visible rows.
  - [ ] `cd frontend && pnpm run typecheck` passes.

  **QA Scenarios**:
  ```
  Scenario: Large evidence list is capped on initial render
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- EvidencePanel
    Expected: Synthetic 500-record test renders 200 visible rows and shows capped count text.
    Evidence: .omo/evidence/task-4-evidence-render.txt

  Scenario: Full export remains complete
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- EvidencePanel evidencePanelRules
    Expected: Export assertion includes all filtered records, including rows beyond initial visible cap.
    Evidence: .omo/evidence/task-4-evidence-render-export.txt
  ```

  **Commit**: NO | Message: included in final commit `fix(app): stabilize traffic graph and evidence loading` | Files: Evidence model/components/tests

- [x] 5. Reduce route-switch jank from forced remount and heavy CSS filters

  **What to do**: Remove deterministic route remount and filter-heavy route animation while preserving simple transitions.
  - Update `frontend/src/app/layouts/MainLayout.tsx`:
    - Remove `key={\`route-${location.pathname}\`}` from the route content wrapper around `<Outlet />`.
    - Keep layout shell stable across navigation.
    - If any route depends on remount-to-reset behavior, replace with targeted effect in that route only; do not reintroduce pathname key at layout level.
  - Update route/background CSS in `frontend/src/styles/theme.css`:
    - For route transition classes/keyframes, remove `filter: blur(...)` and any route-specific `backdrop-filter` animation.
    - Preserve opacity/transform transitions only.
    - Do not remove existing static tile/backdrop styling outside route transition unless tests or profiling identify it as necessary.
  - Add tests:
    - Existing `MainLayout.test.ts` should assert route motion direction still works.
    - Add a static test or focused assertion scanning relevant CSS/class strings to ensure route transition keyframes do not include `filter`, `blur`, or `backdrop-filter`.
    - Add a component-level route switch test if existing harness supports it: layout shell remains mounted when pathname changes.

  **Must NOT do**:
  - Do not redesign navigation/sidebar/header/footer.
  - Do not remove all animations; keep lightweight opacity/transform.
  - Do not disable all backdrop styling globally.

  **Recommended Agent Profile**:
  - Category: `quick` - Reason: bounded route/CSS performance tweak with tests.
  - Skills: [] - No special skill required.
  - Omitted: `frontend-design` - No design redesign.

  **Parallelization**: Can Parallel: YES | Wave 3 | Blocks: Task 7 | Blocked By: none

  **References**:
  - Pattern: `frontend/src/app/layouts/MainLayout.tsx:214-220` - route content wrapper with pathname key.
  - Pattern: `frontend/src/styles/theme.css:255-270` - background/route animation classes.
  - Pattern: `frontend/src/styles/theme.css:1415-1449` - keyframes using filter/blur.
  - Test: `frontend/src/app/layouts/MainLayout.test.ts` - route motion/drag guard tests.

  **Acceptance Criteria**:
  - [ ] No `key={route-${location.pathname}}` or equivalent pathname-keyed route wrapper remains in `MainLayout.tsx`.
  - [ ] Route transition CSS/keyframes do not contain `filter`, `blur`, or `backdrop-filter`.
  - [ ] `cd frontend && pnpm run test:run -- MainLayout` passes.
  - [ ] `cd frontend && pnpm run lint` passes.

  **QA Scenarios**:
  ```
  Scenario: Route shell no longer forces remount by pathname
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- MainLayout
    Expected: Test passes and static/component assertion confirms no pathname-keyed route wrapper.
    Evidence: .omo/evidence/task-5-route-jank.txt

  Scenario: Route transition avoids blur/filter jank
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- MainLayout
    Expected: Test passes and CSS assertion confirms route transition excludes filter/blur/backdrop-filter.
    Evidence: .omo/evidence/task-5-route-jank-css.txt
  ```

  **Commit**: NO | Message: included in final commit `fix(app): stabilize traffic graph and evidence loading` | Files: `MainLayout.tsx`, `theme.css`, route/layout tests

- [x] 6. Add targeted backend in-flight dedupe for cold analysis builders

  **What to do**: Prevent duplicate cold work when overview, Traffic Graph, and Evidence request overlapping analyses.
  - Add a small internal in-flight/singleflight helper in `backend/internal/engine`.
    - Use stdlib primitives only; do not add a dependency unless already present.
    - Key format must include capture identity and operation/options.
    - A failed call must wake waiters and must not permanently poison the cache.
    - Context behavior: waiters canceled by their own context should return their context error without canceling the shared builder for other waiters.
  - Apply only to targeted known-overlap builders:
    - `GlobalTrafficStatsWithContext` / `cachedAnalysis` path for global traffic stats.
    - `IndustrialAnalysisWithContext` via existing `cachedAnalysis` path.
    - `VehicleAnalysisWithContext` via existing `cachedAnalysis` path.
    - `USBAnalysisWithOptions` for identical normalized `USBAnalysisOptions`.
    - `mediaAnalysisWithForce(false)` for non-force cached media analysis only; do not dedupe force-refresh transcription/export paths.
    - `C2SampleAnalysis` for same capture.
    - Exclude `ObjectsWithContext`/YARA/object export from this task; leave existing object/YARA cache behavior unchanged except where indirectly called by other tasks.
  - Integrate with existing `cachedAnalysis` generic helper for global/industrial/vehicle and add targeted wrappers for USB/media/C2 only.
  - Add concurrency tests:
    - Two concurrent identical global/industrial/vehicle style cold calls run builder once.
    - Two different USB option keys do not dedupe incorrectly.
    - Failed builder releases waiters and a later retry can run again.

  **Must NOT do**:
  - Do not serialize unrelated modules behind one global lock.
  - Do not change cache invalidation on capture replacement except to clear in-flight state for old capture if needed.
  - Do not dedupe `force=true` media refresh or export/transcription operations.

  **Recommended Agent Profile**:
  - Category: `unspecified-high` - Reason: backend concurrency and cache correctness.
  - Skills: [] - No special skill required.
  - Omitted: `ultrabrain` - Complex but bounded with tests.

  **Parallelization**: Can Parallel: YES | Wave 2 | Blocks: Task 7 | Blocked By: Task 3

  **References**:
  - Pattern: `backend/internal/engine/service_analysis.go:34-60` - existing `cachedAnalysis` helper lacks in-flight coalescing.
  - Pattern: `backend/internal/engine/service_analysis.go:67-120` - global/industrial/vehicle cached analysis usage.
  - Pattern: `backend/internal/engine/service_analysis.go:300-362` - USB cache keyed by normalized options.
  - Pattern: `backend/internal/engine/service_analysis.go:369-417` - C2 cache path.
  - Exclusion reference: `backend/internal/engine/service_tools.go:259-384` - object export cache path is intentionally not changed in this task.
  - Test: `backend/internal/engine/usb_analysis_cache_test.go` - USB cache/dedupe testing patterns.

  **Acceptance Criteria**:
  - [ ] `cd backend && go test ./internal/engine -run "Test.*Singleflight|TestUSBAnalysisWithOptions" -count=1 -v` passes.
  - [ ] Concurrency test proves identical cold builder invocation count is 1.
  - [ ] Test proves different USB option keys do not share results.
  - [ ] `cd backend && go test ./internal/engine -run "TestGatherEvidence|Test.*Singleflight|TestUSBAnalysisWithOptions|Test.*Analysis" -count=1 -v` passes.

  **QA Scenarios**:
  ```
  Scenario: Concurrent identical cold analysis coalesces
    Tool: Bash
    Steps: cd backend; go test ./internal/engine -run Test.*Singleflight -count=1 -v
    Expected: Test passes and builder invocation counter is exactly 1 for duplicate requests.
    Evidence: .omo/evidence/task-6-singleflight.txt

  Scenario: Different analysis options remain isolated
    Tool: Bash
    Steps: cd backend; go test ./internal/engine -run TestUSBAnalysisWithOptions -count=1 -v
    Expected: Tests pass and distinct USB option cache keys are not incorrectly deduped.
    Evidence: .omo/evidence/task-6-singleflight-options.txt
  ```

  **Commit**: NO | Message: included in final commit `fix(app): stabilize traffic graph and evidence loading` | Files: backend engine cache/concurrency helpers and tests

- [x] 7. Run full verification and capture performance-stability evidence

  **What to do**: Validate the combined repair and collect command evidence.
  - Run backend targeted tests first:
    - `cd backend && go test ./internal/tshark -run TestGlobalTrafficStats -count=1 -v`
    - `cd backend && go test ./internal/transport -run TestGlobalTrafficStatsContract -count=1 -v`
    - `cd backend && go test ./internal/engine -run "TestGatherEvidence|Test.*Singleflight|TestUSBAnalysisWithOptions" -count=1 -v`
  - Run frontend targeted tests:
    - `cd frontend && pnpm run test:run -- trafficMapper TrafficGraph EvidencePanel evidencePanelRules MainLayout desktopBridge`
  - Run full frontend gates:
    - `cd frontend && pnpm run typecheck`
    - `cd frontend && pnpm run lint`
    - `cd frontend && pnpm run format:check`
    - `cd frontend && pnpm run build`
  - Run broader backend gate:
    - `cd backend && go test ./...`
  - Optional but recommended if time allows:
    - `./scripts/check-all.ps1`
  - Create `.omo/evidence/final-verification.md` containing:
    - Commands run.
    - Pass/fail results.
    - Any pre-existing flaky tests and focused rerun evidence.
    - Confirmation that no `.omo/*`, temporary Playwright, Obsidian workspace, or md5 artifacts are included in source commit.

  **Must NOT do**:
  - Do not fix unrelated failures unless they block proving this repair and are clearly introduced by these tasks.
  - Do not commit status/tool artifacts.
  - Do not skip failing tests silently.

  **Recommended Agent Profile**:
  - Category: `unspecified-high` - Reason: cross-stack verification and evidence consolidation.
  - Skills: [] - No special skill required.
  - Omitted: `playwright` - Optional only if browser-level jank verification is requested by reviewer.

  **Parallelization**: Can Parallel: NO | Wave 4 | Blocks: Final Verification Wave | Blocked By: Tasks 1-6

  **References**:
  - Pattern: `AGENTS.md` - repo command rules: backend tests from `backend`, frontend `pnpm`, full `./scripts/check-all.ps1`.
  - Pattern: `.omo/evidence/` - required evidence directory.
  - Prior finding: full frontend test may have unrelated `UsbAnalysis.hidPanel.test.tsx` timeout; if it recurs, rerun focused and document.

  **Acceptance Criteria**:
  - [ ] Backend targeted traffic/evidence/singleflight tests pass.
  - [ ] Frontend targeted traffic/Evidence/layout/bridge tests pass.
  - [ ] `cd frontend && pnpm run typecheck` passes.
  - [ ] `cd frontend && pnpm run lint` passes.
  - [ ] `cd frontend && pnpm run format:check` passes.
  - [ ] `cd frontend && pnpm run build` passes.
  - [ ] `cd backend && go test ./...` passes.
  - [ ] `.omo/evidence/final-verification.md` exists and summarizes results.

  **QA Scenarios**:
  ```
  Scenario: Combined targeted regression suite passes
    Tool: Bash
    Steps: Run backend and frontend targeted commands listed above.
    Expected: All targeted tests pass with traffic contract, Evidence timeout/render, route jank, and singleflight covered.
    Evidence: .omo/evidence/final-verification.md

  Scenario: Full build gates pass
    Tool: Bash
    Steps: Run frontend typecheck/lint/format/build and backend go test ./...
    Expected: All gates pass. If a known flaky test fails, the same test must pass in a focused rerun and final evidence must classify it as unrelated with command output.
    Evidence: .omo/evidence/final-verification.md
  ```

  **Commit**: YES | Message: `fix(app): stabilize traffic graph and evidence loading` | Files: all source/test files changed by Tasks 1-6; exclude `.omo/*` unless user explicitly requests evidence commit

## Final Verification Wave (MANDATORY — after ALL implementation tasks)
> 4 review agents run in PARALLEL. ALL must APPROVE. Present consolidated results to user and get explicit "okay" before completing.
> **Do NOT auto-proceed after verification. Wait for user's explicit approval before marking work complete.**
> **Never mark F1-F4 as checked before getting user's okay.** Rejection or user feedback -> fix -> re-run -> present again -> wait for okay.
- [x] F1. Plan Compliance Audit — oracle
- [x] F2. Code Quality Review — unspecified-high
- [x] F3. Real Manual QA — unspecified-high (+ playwright if UI)
- [x] F4. Scope Fidelity Check — deep

## Commit Strategy
- One final commit after all tasks and verification pass.
- Suggested message: `fix(app): stabilize traffic graph and evidence loading`
- Commit only source/test files required by this plan.
- Do not commit `.omo/*`, Obsidian workspace, generated temp files, or Playwright runtime directories.

## Success Criteria
- Traffic topology no longer depends on parsing endpoint labels.
- Evidence typed IPC timeout budget is explicitly 30000ms for Evidence calls, and backend emits parseable per-module timing status for every attempted Evidence collector.
- Route switching avoids forced route remount and blur/filter-heavy route animation.
- Large Evidence datasets render page-limited rows by default.
- Duplicate cold analysis work is deduped for the targeted high-contention builders.
