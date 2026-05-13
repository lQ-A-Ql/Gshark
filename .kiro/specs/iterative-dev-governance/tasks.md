# Tasks: Iterative Dev Governance

## Phase 1 — Governance Package Foundation

### 1. Create `backend/internal/governance/` package with data models

- [x] 1.1 Create `backend/internal/governance/models.go` defining all data types:
  - `Priority` string type with constants `PriorityP0`, `PriorityP1`, `PriorityP2`, `PriorityP3`
  - `DefectStatus` string type with constants `DefectOpen`, `DefectResolved`
  - `DefectEntry` struct (ID, Priority, Title, Description, KeyFiles, Status, ResolvedAt, ResolvedIn)
  - `DefectRegister` struct (Entries []DefectEntry)
  - `ValidationAttempt` struct (AttemptNumber, Output, Pass)
  - `ValidationResult` struct (Command, Pass, Output, Attempts)
  - `RoundReport` struct (RoundNumber, Author, Timestamp, Timezone, Defect, ModifiedFiles, Validations, RisksAndDefects, NextSteps)
  - `DefectClosure` struct (DefectID, Title, ResolvedAt, RoundNumber)
  - `SelfAuditReport` struct (RoundNumber, Timestamp, CompletedDefects, DriftDetected, DriftDescription, PriorityAdjusted, DirectionNote, CIGateResult)
  - `ArchivePath` struct (Date, Directory, ReportFile, ReadmeFile)

- [x] 1.2 Create `backend/internal/governance/archive_path.go` implementing `ResolveArchivePath(date time.Time) ArchivePath`:
  - Directory: `docs/audit-development-report-archive-YYYY-MM-DD/`
  - ReportFile: `docs/audit-development-report-archive-YYYY-MM-DD/dev-governance-report-YYYY-MM-DD.md`
  - ReadmeFile: `docs/audit-development-report-archive-YYYY-MM-DD/README.md`
  - Use `date.Format("2006-01-02")` for zero-padded formatting

- [x] 1.3 Create `backend/internal/governance/self_audit.go` implementing `ShouldTriggerSelfAudit(roundNumber int) bool`:
  - Returns `true` if and only if `roundNumber > 0 && roundNumber%10 == 0`

- [x] 1.4 Create `backend/internal/governance/task_selector.go` implementing `TaskSelector`:
  - `NextTask(register DefectRegister) (DefectEntry, bool)` iterates priorities P0→P1→P2→P3
  - Within each priority, selects the first open defect by ID order
  - Returns `(DefectEntry{}, false)` when all defects are resolved

- [x] 1.5 Create `backend/internal/governance/report_render.go` implementing rendering helpers:
  - `RenderRoundReport(report RoundReport) string` — renders full markdown with all five required sections in order: 本轮目标、已完成改动、验证记录、当前缺陷与风险、下一步建议
  - `RenderSelfAuditHeading(roundNumber int) string` — returns `## Self-Audit Round N`
  - `RenderProgressUpdateHeading(t time.Time) string` — returns `## Progress Update - YYYY-MM-DD HH:MM:SS +08:00`
  - `CacheKey(params interface{}) string` — deterministic, collision-resistant key using `fmt.Sprintf` + SHA-256 of canonical JSON encoding


## Phase 2 — Property-Based Tests (14 Properties)

### 2. Write property tests for archive path and report rendering

- [x] 2.1 Write property test for Property 1 — Archive path date formatting (PBT)

  Create `backend/internal/governance/archive_path_test.go`.
  Use `testing/quick` with random `time.Time` values.
  Assert `ResolveArchivePath(date).Directory` matches `docs/audit-development-report-archive-YYYY-MM-DD/` with correct zero-padding.
  Annotate: `// Feature: iterative-dev-governance, Property 1: Archive path date formatting is correct`
  **Validates: Requirements 1.1**

- [x] 2.2 Write property test for Property 9 — No cross-date append (PBT)

  Add to `backend/internal/governance/archive_path_test.go`.
  Use `testing/quick` with random date pairs where dates differ.
  Assert that `ResolveArchivePath(dateA).ReportFile != ResolveArchivePath(dateB).ReportFile` when `dateA.Format("2006-01-02") != dateB.Format("2006-01-02")`.
  Annotate: `// Feature: iterative-dev-governance, Property 9: Report writer does not append across date boundaries`
  **Validates: Requirements 8.3**

- [x] 2.3 Write property tests for Properties 2, 3, 4, 5, 8, 10 — Report rendering (PBT)

  Create `backend/internal/governance/report_render_test.go`.
  Use `testing/quick` with random `RoundReport` values.

  - Property 2: rendered string contains all five section headings in order (本轮目标 before 已完成改动 before 验证记录 before 当前缺陷与风险 before 下一步建议). Annotate: `// Property 2: Round_Report contains all required sections in order`. **Validates: Requirements 1.2**
  - Property 3: first 10 lines contain `署名: Kiro` and a line matching `日期: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \+08:00`. Annotate: `// Property 3: Round_Report header contains author and timestamp`. **Validates: Requirements 1.3**
  - Property 4: every path in `ModifiedFiles` appears in the 已完成改动 section. Annotate: `// Property 4: Modified files are all listed in 已完成改动`. **Validates: Requirements 1.6**
  - Property 5: `RenderProgressUpdateHeading(t)` matches `## Progress Update - YYYY-MM-DD HH:MM:SS +08:00` with correct zero-padding. Annotate: `// Property 5: Progress Update heading uses correct format`. **Validates: Requirements 1.5**
  - Property 8: `RenderSelfAuditHeading(n)` equals `fmt.Sprintf("## Self-Audit Round %d", n)` for any positive `n`. Annotate: `// Property 8: Self-Audit heading contains correct round number`. **Validates: Requirements 3.2**
  - Property 10: rendered self-audit report contains every `DefectClosure.DefectID` and its `RoundNumber`. Annotate: `// Property 10: Defect closure table contains all resolved defects`. **Validates: Requirements 8.6**

- [x] 2.4 Write property test for Property 6 — Task selector priority (PBT)

  Create `backend/internal/governance/task_selector_test.go`.
  Use `pgregory.net/rapid` to generate random `DefectRegister` values with mixed P0–P3 open defects.
  Assert `NextTask` returns a defect whose priority is the minimum (P0 < P1 < P2 < P3) among all open defects.
  Annotate: `// Feature: iterative-dev-governance, Property 6: Task selector always returns highest-priority open defect`
  **Validates: Requirements 2.4, 4.1**

- [x] 2.5 Write property test for Property 7 — Self-Audit trigger (PBT)

  Create `backend/internal/governance/self_audit_test.go`.
  Use `testing/quick` with random positive integers.
  Assert `ShouldTriggerSelfAudit(n) == (n > 0 && n%10 == 0)`.
  Annotate: `// Feature: iterative-dev-governance, Property 7: Self-Audit trigger fires exactly on multiples of ten`
  **Validates: Requirements 3.1**


## Phase 3 — Integration Tests

### 3. Write integration tests for archive directory creation and README updates

- [x] 3.1 Write integration test: Report_Archive directory creation + README.md generation

  Add to `backend/internal/governance/integration_test.go`.
  Use a `t.TempDir()` as the project root.
  Call a `CreateArchiveDirectory(root string, date time.Time) error` helper (to be implemented in `archive_path.go`).
  Assert the directory exists and `README.md` is created inside it with non-empty content.
  **Validates: Requirements 1.4**

- [x] 3.2 Write integration test: `docs/README.md` archive description table update

  Add to `backend/internal/governance/integration_test.go`.
  Seed a temporary `docs/README.md` with a minimal table.
  Call `UpdateDocsReadme(root string, path ArchivePath) error` (to be implemented in `report_render.go`).
  Assert the new archive directory name appears in the updated `docs/README.md`.
  **Validates: Requirements 8.2**

- [x] 3.3 Implement `CreateArchiveDirectory` and `UpdateDocsReadme` to make integration tests pass

  In `backend/internal/governance/archive_path.go`:
  - `CreateArchiveDirectory(root string, date time.Time) error` — creates the archive directory and writes a `README.md` index stub.

  In `backend/internal/governance/report_render.go`:
  - `UpdateDocsReadme(root string, path ArchivePath) error` — appends the new archive entry to the archive description table in `docs/README.md`.

- [x] 3.4 Run `cd backend && go test ./internal/governance/...` and verify all tests pass; fix any failures


## Phase 4 — P0 Defect Fixes

### 4. P0-1: tshark capability degradation — graceful fallback

- [x] 4.1 Read `backend/internal/tshark/capabilities.go` and `analysis_helpers.go` to understand the current field-presence check and failure path

- [x] 4.2 Add `MissingOptionalFields []string` to the capabilities/result type returned by the capability-aware analysis function

- [x] 4.3 Implement graceful fallback: when optional tshark fields are absent, log each missing field name (using the existing logger pattern in the package) and continue with a partial result instead of returning empty/nil

- [x] 4.4 Write property test for Property 11 — Tshark optional-field degradation returns partial results (PBT)

  Add to `backend/internal/tshark/capabilities_test.go` (or a new `capabilities_property_test.go`).
  Use `pgregory.net/rapid` to generate random subsets of optional fields marked absent.
  Assert the function returns a non-nil, non-empty partial result and `MissingOptionalFields` is non-empty.
  Annotate: `// Feature: iterative-dev-governance, Property 11: Tshark optional-field degradation returns partial results`
  **Validates: Requirements 4.2**

- [x] 4.5 Run `cd backend && go test ./internal/tshark/...` and verify all tests pass

### 5. P0-2: field scan cache key — deterministic, collision-resistant

- [x] 5.1 Read `backend/internal/tshark/analysis_helpers.go` to identify the scan parameter struct and the cache lookup site

- [x] 5.2 Implement `CacheKey(params ScanParams) string` in `analysis_helpers.go` (or a new `cache_key.go`):
  - Canonically encode all scan parameters (sorted map keys if any maps are involved)
  - Hash with SHA-256 and return hex string
  - Must be deterministic: same params → same key on every call

- [x] 5.3 Wire `CacheKey` into the existing cache lookup so every cache read/write uses the new key

- [x] 5.4 Write property test for Property 12 — Cache key determinism and collision resistance (PBT)

  Add to `backend/internal/tshark/analysis_helpers_test.go` (or a new `cache_key_property_test.go`).
  Use `pgregory.net/rapid` to generate random scan param pairs.
  Assert: (a) `CacheKey(p) == CacheKey(p)` for any `p`; (b) `CacheKey(a) != CacheKey(b)` when `a != b`.
  Annotate: `// Feature: iterative-dev-governance, Property 12: Field scan cache key is deterministic and collision-resistant`
  **Validates: Requirements 4.3**

- [x] 5.5 Run `cd backend && go test ./internal/tshark/...` and verify all tests pass

### 6. P0-3: `_ws.col.*` field severity downgrade

- [x] 6.1 Read `backend/internal/tshark/capabilities.go` to locate where `_ws.col.Protocol` and `_ws.col.Info` fields are classified

- [x] 6.2 Introduce a `DisplayLayerField` category (or equivalent named constant) and assign `_ws.col.*` fields to it

- [x] 6.3 Update the severity mapping so display-layer fields produce a lower alert level than protocol-layer anomaly fields; add a named constant for each severity level to replace any magic strings/numbers

- [x] 6.4 Add a unit test in `backend/internal/tshark/capabilities_test.go` asserting that `_ws.col.Protocol` and `_ws.col.Info` produce a severity strictly lower than a representative protocol-layer anomaly field

- [x] 6.5 Run `cd backend && go test ./internal/tshark/...` and verify all tests pass

### 7. P0-4: plugin local code execution boundary

- [x] 7.1 Read `backend/internal/plugin/manager.go` and `runtime.go` to understand the current plugin execution path

- [x] 7.2 Add an explicit permission check (or sandbox gate) before any plugin executes local code:
  - Define a `PluginPermission` type with at least `PermLocalExec`
  - `Manager` must verify the plugin's declared permissions before invoking local execution
  - Plugins without `PermLocalExec` must receive a descriptive error, not a silent failure

- [x] 7.3 Add a test in `backend/internal/plugin/manager_test.go` that verifies a plugin without `PermLocalExec` is denied local execution and receives the expected error

- [x] 7.4 Run `cd backend && go test ./internal/plugin/...` and verify all tests pass

### 8. Validation baseline after P0 phase

- [x] 8.1 Run `cd backend && gofmt -l .` and fix any formatting violations introduced in Phase 4
- [x] 8.2 Run `cd backend && go test ./...` and confirm all 6+ packages pass
- [x] 8.3 Run `cd frontend && pnpm run ci` and confirm no regressions


## Phase 5 — P1 Defect Fixes

### 9. P1-1: BackendBridge super-interface split

- [x] 9.1 Read `backend/internal/transport/http_server.go` and `backend/internal/engine/service.go` to map all methods on the current `engine.Service` interface used by the transport layer

- [x] 9.2 Define focused domain interfaces in `backend/internal/transport/` (one per analysis domain, e.g. `CaptureService`, `C2Service`, `EvidenceService`, `ToolService`, `MediaService`), each covering no more than one domain

- [x] 9.3 Update `http_server.go` to accept the split interfaces instead of the monolithic `engine.Service`; update `Server` struct fields accordingly

- [x] 9.4 Update all call sites in `backend/internal/transport/` that reference the old interface

- [x] 9.5 Update `backend/internal/transport/http_server_test.go` to cover the refactored interface boundaries

- [x] 9.6 Run `cd backend && go test ./internal/transport/...` and verify all tests pass

### 10. P1-2: SentinelContext state ownership

- [x] 10.1 Read `frontend/src/app/state/SentinelContext.tsx` and `frontend/src/app/state/sentinelTypes.ts` to identify all independent state slices currently mixed in the single context

- [x] 10.2 Extract each independent state slice into its own owner module under `frontend/src/app/state/` (e.g. `captureSessionState.ts`, `streamViewState.ts`) following the existing pattern of co-located `.test.ts` files

- [x] 10.3 Update `SentinelContext.tsx` to compose the extracted slices; ensure no cross-slice direct mutation remains (each slice is only mutated by its own owner)

- [x] 10.4 Update or add tests for each extracted slice module

- [x] 10.5 Run `cd frontend && pnpm run typecheck` and `cd frontend && pnpm run ci` and verify no regressions

### 11. P1-3: `useCaptureStartWorkflow` parameter reduction

- [x] 11.1 Read `frontend/src/app/state/hooks/useCaptureStartWorkflow.ts` to identify all parameters and group them by concern

- [x] 11.2 Define typed option objects (e.g. `CaptureSourceOptions`, `CaptureRuntimeOptions`) grouping related parameters

- [x] 11.3 Refactor `useCaptureStartWorkflow` to accept the typed option objects instead of the flat parameter list

- [x] 11.4 Update all call sites of `useCaptureStartWorkflow` within the same task

- [x] 11.5 Update `frontend/src/app/state/hooks/useCaptureStartWorkflow.test.tsx` to use the new signature

- [x] 11.6 Run `cd frontend && pnpm run typecheck` and `cd frontend && pnpm run ci` and verify no regressions

### 12. P1-4: tool runtime config persistence consistency

- [x] 12.1 Read `backend/internal/engine/tool_runtime.go` and `frontend/src/app/state/toolRuntimeStorage.ts` to identify all config read/write paths

- [x] 12.2 Consolidate backend config reads and writes to a single authoritative path in `tool_runtime.go`; add a `sync.RWMutex` guard for concurrent access

- [x] 12.3 Verify `frontend/src/app/state/toolRuntimeStorage.ts` and `toolRuntimeOfflineSnapshot.ts` use a consistent key/path; fix any divergence

- [x] 12.4 Update `frontend/src/app/state/toolRuntimeStorage.test.ts` to cover concurrent-safe read/write round-trips

- [x] 12.5 Run `cd backend && go test ./internal/engine/...` and `cd frontend && pnpm run ci` and verify no regressions

### 13. P1-5: frontend/backend contract mapper round-trip

- [x] 13.1 Read `frontend/src/app/integrations/mappers/` and `bridgeTypes.ts` to identify all hand-written mapper functions and the contract types they handle

- [x] 13.2 For each contract type, derive or generate the mapper from the shared type definition (e.g. using a code-gen script or a typed factory function) rather than hand-writing field assignments

- [x] 13.3 Write property test for Property 13 — Contract mapper round-trip (PBT)

  Add to `frontend/src/app/integrations/` (e.g. `mappers/contractMapper.property.test.ts`).
  Use `fast-check` (already available via Vitest) to generate random contract type instances.
  Assert `decode(encode(x))` deep-equals `x` for each contract type.
  Annotate: `// Feature: iterative-dev-governance, Property 13: Contract mapper round-trip preserves data`
  **Validates: Requirements 5.6**

- [x] 13.4 Update existing mapper tests in `frontend/src/app/integrations/` to cover the refactored mappers

- [x] 13.5 Run `cd frontend && pnpm run ci` and verify all tests pass

### 14. Validation baseline after P1 phase

- [x] 14.1 Run `cd backend && gofmt -l .` and fix any formatting violations
- [x] 14.2 Run `cd backend && go test ./...` and confirm all packages pass
- [x] 14.3 Run `cd frontend && pnpm run ci` and confirm no regressions


## Phase 6 — P2 Defect Fixes

### 15. P2-1: report/evidence package boundary enforcement

- [x] 15.1 Read `backend/internal/engine/evidence.go`, `evidence_collectors_*.go`, and `evidence_rules.go` to identify which internal evidence types are imported by packages outside the designated owner

- [x] 15.2 Move any evidence types that leak across package boundaries into a dedicated `evidence` sub-package or enforce access via exported accessor functions only

- [x] 15.3 Add a boundary test (e.g. using `golang.org/x/tools/go/packages` or a simple `go list` assertion in a `TestMain`) that fails if any package outside the designated owner imports internal evidence types directly

- [x] 15.4 Run `cd backend && go test ./...` and verify the boundary test passes and no existing tests regress

### 16. P2-2: replace hardcoded rules with named constants

- [x] 16.1 Read `backend/internal/tshark/industrial_rules.go` and any other files flagged in the defect register for magic numbers/strings

- [x] 16.2 Replace each hardcoded value with a named constant (e.g. `const ModbusDefaultPort = 502`) or a configuration entry; add a comment documenting the valid range or allowed values for each constant

- [x] 16.3 Run `cd backend && go test ./internal/tshark/...` and verify all existing tests still pass

### 17. P2-3: frontend boundary check depth extension

- [x] 17.1 Read `frontend/scripts/check-boundaries.mjs` and `check-boundaries.test.mjs` to understand the current boundary rules

- [x] 17.2 Extend the boundary script to cover feature-level import boundaries identified in the 2026-05-12 engineering report (at minimum: no cross-feature direct imports between `features/` subdirectories; `integrations/` is the only allowed bridge)

- [x] 17.3 Update `check-boundaries.test.mjs` to cover the new rules

- [x] 17.4 Run `cd frontend && pnpm run ci` and verify the boundary checks pass

### 18. P2-4: field scan cache LRU/TTL capacity control

- [x] 18.1 Read `backend/internal/tshark/capabilities.go` to locate the current unbounded cache implementation

- [x] 18.2 Implement an LRU eviction policy with a configurable `maxEntries` parameter (default: 256); alternatively implement TTL-based eviction if the access pattern warrants it

- [x] 18.3 Write property test for Property 14 — Cache capacity invariant (PBT)

  Add to `backend/internal/tshark/capabilities_test.go` (or a new `cache_capacity_property_test.go`).
  Use `pgregory.net/rapid` to generate random insertion sequences and random `maxEntries` values (1–1000).
  Assert the cache size never exceeds `maxEntries` after any insertion.
  Annotate: `// Feature: iterative-dev-governance, Property 14: Field scan cache never exceeds configured capacity`
  **Validates: Requirements 6.5**

- [x] 18.4 Run `cd backend && go test ./internal/tshark/...` and verify all tests pass

### 19. P2-5: `analysis_helpers.go` split into focused modules

- [x] 19.1 Read `backend/internal/tshark/analysis_helpers.go` to identify distinct responsibilities (e.g. field extraction helpers, severity mapping, cache utilities, protocol classification)

- [x] 19.2 Split into focused files, each with a single responsibility:
  - `field_helpers.go` — field extraction and normalization utilities
  - `severity_mapping.go` — severity classification logic
  - `cache_key.go` — cache key generation (if not already extracted in task 5.2)
  - Keep `analysis_helpers.go` only if residual shared utilities remain; otherwise delete it

- [x] 19.3 Verify all existing tests in `backend/internal/tshark/analysis_helpers_test.go` and `analysis_detection_test.go` still compile and pass after the split

- [x] 19.4 Run `cd backend && go test ./internal/tshark/...` and verify all tests pass

### 20. Validation baseline after P2 phase

- [x] 20.1 Run `cd backend && gofmt -l .` and fix any formatting violations
- [x] 20.2 Run `cd backend && go test ./...` and confirm all packages pass
- [x] 20.3 Run `cd frontend && pnpm run ci` and confirm no regressions


## Phase 7 — P3 Defect Fixes

### 21. P3-1: maturity markers for non-production-ready features

- [x] 21.1 Audit all feature entry points (frontend feature pages and backend analysis endpoints) to identify functions/components not yet production-ready

- [x] 21.2 Add maturity markers to non-production-ready features:
  - Backend: add a `// Stability: experimental` or `// Stability: beta` comment block at the top of each relevant file, and return a `X-Feature-Maturity: experimental` response header from the corresponding HTTP handler
  - Frontend: add a visible `ExperimentalBadge` or `BetaBadge` component to the feature's page header where applicable

- [x] 21.3 Run `cd backend && go test ./...` and `cd frontend && pnpm run ci` and verify no regressions

### 22. P3-2: real PCAP regression cases

- [x] 22.1 Identify the major analysis domains that currently lack real PCAP regression tests (at minimum: industrial protocol analysis, vehicle CAN analysis, C2 traffic detection)

- [x] 22.2 Add at least one real PCAP regression test per identified domain in the corresponding `*_test.go` files under `backend/internal/engine/` or `backend/internal/tshark/`:
  - Each test loads a small, representative PCAP sample (stored under `backend/testdata/` or an existing sample directory)
  - Each test asserts at least one domain-specific detection result (e.g. a specific protocol identified, a threat indicator present)

- [x] 22.3 Run `cd backend && go test ./...` and verify the new regression tests pass

### 23. Validation baseline after P3 phase

- [x] 23.1 Run `cd backend && gofmt -l .` and fix any formatting violations
- [x] 23.2 Run `cd backend && go test ./...` and confirm all packages pass
- [x] 23.3 Run `cd frontend && pnpm run ci` and confirm no regressions


## Phase 8 — Full CI Gate Verification

### 24. Run full CI gate and write initial governance report

- [x] 24.1 Run `./scripts/check-all.ps1` and record the result; fix any failures before proceeding

- [x] 24.2 Add `pgregory.net/rapid` to `backend/go.mod` and `backend/go.sum` if not already present:
  ```
  cd backend && go get pgregory.net/rapid
  ```

- [x] 24.3 Write the initial Round_Report to `docs/audit-development-report-archive-<today>/dev-governance-report-<today>.md` using the `RenderRoundReport` helper implemented in Phase 1:
  - Author: `Kiro`
  - Timestamp: current local time in `+08:00`
  - 本轮目标: governance package foundation and all defect fixes
  - 已完成改动: list all files created or modified across Phases 1–7
  - 验证记录: results of `go test ./...`, `pnpm run ci`, `gofmt -l .`, and `check-all.ps1`
  - 当前缺陷与风险: any remaining open items
  - 下一步建议: next governance iteration direction

- [x] 24.4 Create `docs/audit-development-report-archive-<today>/README.md` index stub

- [x] 24.5 Update `docs/README.md` to include the new archive directory in the recommended reading order and archive description table

