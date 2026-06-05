# Frontend Evidence UI Upgrade

## TL;DR
> **Summary**: Upgrade the existing Evidence page into a high-density investigation center and embed the newly added backend capabilities into their existing specialty pages. The implementation must make JA3/JA3S, WebShell/China Chopper, DNP3, IOC availability, Playbooks, Rules, and Evidence aggregation visible without inventing data when backend contracts are incomplete.
> **Deliverables**:
> - Existing Evidence page upgraded with facets, dense results, detail panel, and feature/entity metadata.
> - Existing specialty pages enhanced: Threat Hunting playbooks, WebShell family/China Chopper metadata, DNP3 industrial section, JA3/JA3S TLS fingerprint surface.
> - Contract-safe optional frontend types/mappers/tests for missing or partial backend fields.
> - Frontend tests and CI checks passing.
> **Effort**: Large
> **Parallel**: YES - 4 waves
> **Critical Path**: Task 1 → Task 2 → Task 7 → Task 8 → Task 9

## Context
### Original Request
User selected UI方案 B+C: embed new capabilities in existing specialty pages and upgrade Evidence information density/range. Then user asked for a directly executable plan.

### Interview Summary
- Expand existing `EvidencePanel` route; do not add a new top-level route.
- Specialty features are embedded widgets/sections in existing pages, not new navigation destinations.
- No dark theme. Use a light, high-density security investigation style compatible with current components.
- Backend changes are not prerequisites. Missing backend fields/API must produce explicit unavailable/partial states, never fake records.
- Playbooks should be interactive where existing client/API supports it, with localized empty/error states.

### Metis Review (gaps addressed)
- Evidence data contract must be locked before UI expansion.
- Avoid app-shell redesign, navigation duplication, backend assumptions, and false completeness.
- Each feature needs its own acceptance target and executable tests.

### Oracle Clearance
- Oracle phase 1 returned `VERDICT: GO`: scope, constraints, existing files, backend gaps, and implementation waves are sufficient.

## Work Objectives
### Core Objective
Make recently added backend capabilities visible and usable in the frontend by upgrading Evidence into a unified investigation center and embedding feature-specific panels into existing specialty pages.

### Deliverables
- Evidence optional metadata model: feature/entity/version/protocol/rule/playbook/IOC/TLS fields.
- Evidence investigation center: facet sidebar, dense list, detail panel, export/search, explicit gap states.
- Threat Hunting Playbook workspace mounted in `ThreatHunting.tsx`.
- WebShell source UI shows family/version hints and China Chopper as a first-class classification label when data exists.
- Industrial DNP3 section derived from existing generic industrial details/control commands.
- JA3/JA3S TLS fingerprint display in existing packet/C2/TLS surface discovered during implementation.
- Tests for mapper/rules/UI empty states and each visible specialty surface.

### Definition of Done (verifiable conditions with commands)
- `cd frontend && pnpm run test:run` exits 0.
- `cd frontend && pnpm run typecheck` exits 0.
- `cd frontend && pnpm run lint` exits 0.
- `cd frontend && pnpm run format:check` exits 0.
- `cd frontend && pnpm run build` exits 0.
- Evidence page has tested UI assertions for facets, dense rows, detail panel, and no `undefined` rendering for missing optional fields.
- Threat Hunting page has tested Playbook visibility/empty/error state.
- WebShell UI has tested China Chopper/family metadata rendering from hints.
- Industrial page has tested DNP3 visible section or explicit DNP3 unavailable state.
- JA3/JA3S UI has tested optional fingerprint display or explicit unavailable state.

### Must Have
- Existing Evidence page remains the route for the investigation center.
- All new metadata fields are optional and backward compatible.
- Existing backend module filtering remains compatible with coarse modules.
- Missing IOC API and WebShell unified version API are shown as unavailable/partial, not mocked as complete.
- Existing pages keep their current workflows.

### Must NOT Have
- No dark theme work.
- No unrelated app shell/navigation redesign.
- No fake evidence rows, hardcoded threat data, or production sample data.
- No backend implementation tasks in this plan.
- No `as any`, `@ts-ignore`, `@ts-expect-error`, empty catch blocks, or silent fallback that hides contract gaps.
- No package manager file churn unless a command legitimately updates it and the executor explains why.

## Verification Strategy
> ZERO HUMAN INTERVENTION - all verification is agent-executed.
- Test decision: tests-first for Evidence contract and empty states; tests-after acceptable for visual composition if component structure is still being discovered.
- Framework: Vitest + React Testing Library + existing frontend scripts.
- QA policy: Every task includes agent-executed happy and failure/edge scenarios.
- Evidence: `.omo/evidence/task-{N}-{slug}.{ext}` for command logs or UI screenshots where applicable.

## Execution Strategy
### Parallel Execution Waves
> Target: 5-8 tasks per wave. This plan uses fewer tasks per wave where dependencies are real and file overlap is high.

Wave 1: Task 1 only — freeze optional contracts and tests.
Wave 2: Tasks 2-6 in parallel — model/rules and specialty surfaces.
Wave 3: Tasks 7-8 — Evidence investigation center and cross-feature polish.
Wave 4: Task 9 — full verification.

### Dependency Matrix (full, all tasks)
| Task | Blocked By | Blocks |
|---|---|---|
| 1 Contract tests | none | 2,3,4,5,6 |
| 2 Evidence model/mapper/rules | 1 | 7,8 |
| 3 Threat Hunting Playbooks | 1 | 8 |
| 4 WebShell/China Chopper UI | 1 | 8 |
| 5 Industrial DNP3 UI | 1 | 8 |
| 6 JA3/JA3S TLS UI | 1 | 8 |
| 7 Evidence Investigation Center | 2 | 8,9 |
| 8 Cross-feature polish | 2,3,4,5,6,7 | 9 |
| 9 Final verification | 8 | none |

### Agent Dispatch Summary
- Wave 1 → 1 task → `unspecified-low`
- Wave 2 → 5 tasks → `quick`/`unspecified-low`
- Wave 3 → 2 tasks → `visual-engineering` + `unspecified-low`
- Wave 4 → 1 task → `quick`

## TODOs
> Implementation + Test = ONE task. Never separate.
> EVERY task MUST have: Agent Profile + Parallelization + QA Scenarios.

- [x] 1. Add Evidence optional-contract fixtures and empty-state tests

  **What to do**: Inspect current tests, then add/extend tests for optional Evidence metadata and missing-field behavior. Cover records for JA3/JA3S, WebShell family/version, China Chopper, DNP3, IOC, Playbook, and Rule. Tests should drive optional frontend fields and prove missing metadata does not render `undefined`, fake records, or fake completion states.
  **Must NOT do**: Do not redesign UI, edit backend, or make production code changes beyond minimal test compatibility.

  **Recommended Agent Profile**:
  - Category: `unspecified-low` - Reason: focused test/fixture work.
  - Skills: [] - no specialized skill required.
  - Omitted: [`frontend-design`] - visual design is not needed for contract tests.

  **Parallelization**: Can Parallel: NO | Wave 1 | Blocks: 2,3,4,5,6 | Blocked By: none

  **References**:
  - Pattern: `frontend/src/app/features/evidence/evidencePanelRules.test.ts` - existing helper and rule assertions.
  - Pattern: `frontend/src/app/integrations/mappers/evidenceMapper.test.ts` - mapper fixture style.
  - Pattern: `frontend/src/app/pages/EvidencePanel.test.tsx` - mocked backend evidence page tests.
  - Contract: `frontend/src/app/core/evidenceTypes.ts` - current `UnifiedEvidenceRecord` and module union.

  **Acceptance Criteria**:
  - [ ] Tests cover mapper/rule behavior for source types or optional fields representing `ja3`, `ja3s`, `webshell`, `china_chopper`, `dnp3`, `ioc`, `playbook`, and `rule`.
  - [ ] Tests assert missing optional values render/filter/export safely without `undefined` text or fake evidence rows.
  - [ ] Targeted tests run: `cd frontend && pnpm run test:run -- evidenceMapper evidencePanelRules EvidencePanel`.

  **QA Scenarios**:
  ```
  Scenario: Optional evidence domains normalize safely
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- evidenceMapper evidencePanelRules
    Expected: targeted tests pass and include optional metadata fixtures
    Evidence: .omo/evidence/task-1-evidence-contract-tests.txt

  Scenario: Missing optional fields do not fake UI data
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- EvidencePanel
    Expected: tests assert no undefined/fake records in rendered output
    Evidence: .omo/evidence/task-1-evidence-empty-state.txt
  ```

  **Commit**: YES | Message: `test(frontend): cover evidence ui contract gaps` | Files: evidence tests only, plus minimal related fixtures if needed

- [x] 2. Extend Evidence schema, mapper, rules, and panel model

  **What to do**: Add optional metadata fields while keeping old records valid. Extend wire DTOs, mapper, search/filter/export rules, labels, and panel model to support feature/entity/protocol/version/playbook/rule/IOC/TLS metadata. Keep backend module filters compatible with existing coarse modules.
  **Must NOT do**: Do not require backend changes, remove existing module values, or force new fields as required.

  **Recommended Agent Profile**:
  - Category: `quick` - Reason: contained TypeScript model/rules work.
  - Skills: [] - no specialized skill required.
  - Omitted: [`frontend-design`] - data contract work only.

  **Parallelization**: Can Parallel: YES | Wave 2 | Blocks: 7,8 | Blocked By: 1

  **References**:
  - API/Type: `frontend/src/app/core/evidenceTypes.ts` - add optional fields here.
  - API/Type: `frontend/src/app/integrations/wire/evidenceWireDtos.ts` - add optional snake_case DTO keys.
  - Pattern: `frontend/src/app/integrations/mappers/evidenceMapper.ts` - normalize optional wire fields.
  - Pattern: `frontend/src/app/features/evidence/evidencePanelRules.ts` - labels/search/export/filter rules.
  - Pattern: `frontend/src/app/features/evidence/useEvidencePanelModel.ts` - filtered/sorted/report/export model.

  **Acceptance Criteria**:
  - [ ] `UnifiedEvidenceRecord` supports optional `feature`, `entityType`, `protocol`, `version`, `displayName`, `ruleId`, `ruleName`, `playbookId`, `playbookName`, `iocType`, `iocValue`, `ja3Hash`, `ja3sHash`, and `metadata` or equivalent strongly typed optional fields.
  - [ ] Mapper reads optional snake_case backend fields and does not crash on malformed payloads.
  - [ ] Search includes hash, IOC, family/version, protocol, playbook, rule, and technique/tag fields.
  - [ ] CSV/JSON exports include new metadata when present.
  - [ ] `media` and `misc` module coverage is not lost; unknown modules remain explicit.

  **QA Scenarios**:
  ```
  Scenario: Old evidence payload remains compatible
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- evidenceMapper evidencePanelRules evidenceSchema
    Expected: existing and new tests pass
    Evidence: .omo/evidence/task-2-evidence-model-tests.txt

  Scenario: New optional metadata is searchable/exportable
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- evidencePanelRules
    Expected: tests prove search/export includes JA3/IOC/WebShell/DNP3/Playbook metadata
    Evidence: .omo/evidence/task-2-evidence-search-export.txt
  ```

  **Commit**: YES | Message: `feat(frontend): extend evidence investigation model` | Files: evidence types, DTOs, mapper, rules, model, related tests

- [x] 3. Mount Playbook workspace in Threat Hunting

  **What to do**: Add a wrapper component that uses existing playbook client/hook/components and mount it in `ThreatHunting.tsx` below or beside the existing workbench. It must show playbook list/detail, last run, saved searches, and hypotheses when available. API failures must be localized to the Playbook section.
  **Must NOT do**: Do not disrupt existing YARA/prefix threat hunting workflow or create a new route.

  **Recommended Agent Profile**:
  - Category: `quick` - Reason: existing hook/components already exist.
  - Skills: [] - standard React composition.
  - Omitted: [`frontend-design`] - minor composition, not a new visual system.

  **Parallelization**: Can Parallel: YES | Wave 2 | Blocks: 8 | Blocked By: 1

  **References**:
  - Pattern: `frontend/src/app/pages/ThreatHunting.tsx` - host page, currently no playbook mount.
  - Pattern: `frontend/src/app/features/hunting/PlaybookPanels.tsx` - existing list/detail/saved-search/hypothesis UI.
  - API/Type: `frontend/src/app/features/hunting/usePlaybookManagement.ts` - existing management hook.
  - API/Type: `frontend/src/app/integrations/clients/playbookClient.ts` - existing API client.

  **Acceptance Criteria**:
  - [ ] Threat Hunting page renders a Playbook workspace without blocking existing workbench.
  - [ ] Empty playbooks, saved searches, and hypotheses show explicit empty states.
  - [ ] API error state is visible only inside the Playbook workspace.
  - [ ] Existing `ThreatHunting` tests still pass; new test asserts playbook workspace is mounted.

  **QA Scenarios**:
  ```
  Scenario: Playbook workspace visible on Threat Hunting
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- ThreatHunting Playbook
    Expected: tests assert Playbook area renders and existing hunting UI remains
    Evidence: .omo/evidence/task-3-playbook-mount.txt

  Scenario: Playbook API unavailable is localized
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- ThreatHunting
    Expected: test mocks playbook failure and verifies no page-level crash
    Evidence: .omo/evidence/task-3-playbook-error-state.txt
  ```

  **Commit**: YES | Message: `feat(frontend): mount hunting playbooks` | Files: ThreatHunting, playbook wrapper/tests, minimal panel adjustments

- [x] 4. Surface WebShell family/version and China Chopper metadata

  **What to do**: Make WebShell family metadata prominent in payload source cards and decoder workbench. Normalize China Chopper aliases from `familyHint`, decoder hints, or source metadata, and show `菜刀 / China Chopper` as a first-class label when evidence exists. Show version only if provided; otherwise show a small unavailable/unknown state.
  **Must NOT do**: Do not claim a dedicated China Chopper decoder exists unless the current decoder pipeline supports it. Do not invent version values.

  **Recommended Agent Profile**:
  - Category: `quick` - Reason: contained WebShell UI enhancement.
  - Skills: [] - standard frontend work.
  - Omitted: [`frontend-design`] - use current WebShell workbench primitives.

  **Parallelization**: Can Parallel: YES | Wave 2 | Blocks: 8 | Blocked By: 1

  **References**:
  - Pattern: `frontend/src/app/misc/modules/PayloadWebShellDecoderModule.tsx` - source/workbench host.
  - Pattern: `frontend/src/app/misc/modules/PayloadWebShellSourceUtils.ts` - badge and label helpers.
  - Pattern: `frontend/src/app/misc/modules/PayloadWebShellSourceList.tsx` - likely source card rendering.
  - Pattern: `frontend/src/app/components/StreamDecoderWorkbench.tsx` and related decoder components - candidate/workbench display.
  - API/Type: `frontend/src/app/core/types/stream.ts` - `StreamPayloadSource` optional metadata.

  **Acceptance Criteria**:
  - [ ] Source cards display family, decoder, confidence, role, and China Chopper label when hints match.
  - [ ] Version is shown only when provided by source/candidate metadata.
  - [ ] Existing Behinder/AntSword/Godzilla hint tests still pass.
  - [ ] Tests cover China Chopper alias normalization and no-version fallback.

  **QA Scenarios**:
  ```
  Scenario: China Chopper-like source is visible
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- MiscTools PayloadWebShellSourceUtils StreamDecoder
    Expected: tests assert China Chopper label from hints/aliases
    Evidence: .omo/evidence/task-4-china-chopper-ui.txt

  Scenario: Missing version is explicit but not fake
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- MiscTools
    Expected: tests assert unknown/unavailable version state and no fabricated version
    Evidence: .omo/evidence/task-4-webshell-version-empty.txt
  ```

  **Commit**: YES | Message: `feat(frontend): surface webshell family metadata` | Files: WebShell modules, stream types/helpers/tests

- [x] 5. Add DNP3-specific industrial section

  **What to do**: Add a DNP3 section to the existing Industrial page using current `analysis.details`, `analysis.controlCommands`, and `analysis.ruleHits`. Derive DNP3 records by matching protocol/name/rule fields containing DNP3. Show counts, operations, targets, results, and command/anomaly rows. If no DNP3 data exists, show a compact explicit unavailable/empty state only when appropriate.
  **Must NOT do**: Do not add backend parsing, duplicate all generic industrial details, or hide generic panels.

  **Recommended Agent Profile**:
  - Category: `quick` - Reason: focused panel from existing data.
  - Skills: [] - no specialized skill required.
  - Omitted: [`frontend-design`] - use existing analysis primitives.

  **Parallelization**: Can Parallel: YES | Wave 2 | Blocks: 8 | Blocked By: 1

  **References**:
  - Pattern: `frontend/src/app/pages/IndustrialAnalysis.tsx` - host page.
  - Pattern: `frontend/src/app/features/industrial/IndustrialAuxiliaryPanels.tsx` - current control/details panels.
  - API/Type: `frontend/src/app/integrations/mappers/industrialMapper.ts` - generic industrial payload mapping.
  - Test: `frontend/src/app/pages/IndustrialAnalysis.test.tsx` - page rendering patterns.

  **Acceptance Criteria**:
  - [ ] DNP3 has a visible first-class section when DNP3 details/commands/rules are present.
  - [ ] Section shows frame/operation/target/result counts or compact fallback values.
  - [ ] Generic industrial panels remain unchanged.
  - [ ] Tests cover DNP3-present and DNP3-absent behavior.

  **QA Scenarios**:
  ```
  Scenario: DNP3 details render as a dedicated section
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- IndustrialAnalysis industrialMapper
    Expected: tests assert DNP3 section and key fields appear
    Evidence: .omo/evidence/task-5-dnp3-section.txt

  Scenario: No DNP3 does not fake findings
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- IndustrialAnalysis
    Expected: tests assert no fake DNP3 records and graceful empty/unavailable state
    Evidence: .omo/evidence/task-5-dnp3-empty.txt
  ```

  **Commit**: YES | Message: `feat(frontend): add dnp3 industrial panel` | Files: Industrial page/panels/helpers/tests

- [x] 6. Surface optional JA3/JA3S in packet, C2, or TLS UI

  **What to do**: Discover the current frontend packet/C2/TLS display seam, then add optional JA3/JA3S field mapping and display. Preferred host is the existing C2/TLS analysis or packet detail surface that already renders TLS/capture context. Show hash chips, copyable values if a copy pattern exists, and availability callout when no fingerprint exists.
  **Must NOT do**: Do not create a new route, require TLS decryption changes, or show empty hash placeholders as findings.

  **Recommended Agent Profile**:
  - Category: `unspecified-low` - Reason: small discovery plus UI patch across packet/C2 seams.
  - Skills: [] - no specialized skill required.
  - Omitted: [`frontend-design`] - use existing packet/C2 visual patterns.

  **Parallelization**: Can Parallel: YES | Wave 2 | Blocks: 8 | Blocked By: 1

  **References**:
  - API/Type: `backend/internal/model/types_packet.go` - backend `tls_fingerprint` contract with `ja3_hash`, `ja3s_hash`, `ja3_raw`, `ja3s_raw`.
  - Pattern: `frontend/src/app/integrations/mappers/packetMapper.ts` - likely packet mapper seam.
  - Pattern: `frontend/src/app/pages/C2Analysis*.tsx` and `frontend/src/app/features/c2/*` - likely C2 host surface.
  - Pattern: `frontend/src/app/components/TLSDecryptionDialog.tsx` - TLS terminology reference only, not necessarily the host.

  **Acceptance Criteria**:
  - [ ] Frontend packet/TLS type includes optional JA3/JA3S fields or a typed `tlsFingerprint` object.
  - [ ] Existing packet/C2/TLS UI shows JA3/JA3S when provided.
  - [ ] Missing fingerprint data renders no fake hash and a clear availability note where appropriate.
  - [ ] Tests cover optional fingerprint mapping and display.

  **QA Scenarios**:
  ```
  Scenario: Packet/C2 UI displays JA3 and JA3S hashes
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- packetMapper C2Analysis TLS
    Expected: tests assert hashes are displayed when provided
    Evidence: .omo/evidence/task-6-ja3-display.txt

  Scenario: Missing fingerprint is safe
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- packetMapper C2Analysis
    Expected: tests assert no fake hashes or undefined strings
    Evidence: .omo/evidence/task-6-ja3-empty.txt
  ```

  **Commit**: YES | Message: `feat(frontend): surface tls fingerprints` | Files: packet/C2/TLS types, mapper, UI/tests

- [x] 7. Upgrade Evidence page into investigation center

  **What to do**: Refactor the existing `EvidencePanel` route into a light-theme investigation center. Add a facet sidebar, dense evidence results, and right-side detail panel. Use optional metadata from Task 2. Keep report/export/search. Make backend gaps explicit with small callouts.
  **Must NOT do**: Do not add a new route, dark theme, app shell redesign, or fake evidence.

  **Recommended Agent Profile**:
  - Category: `visual-engineering` - Reason: primary UI composition and information-density task.
  - Skills: [`frontend-design`] - apply polished light investigation-center layout while preserving repo design primitives.
  - Omitted: [`playwright`] - not needed during implementation; final QA can use browser only if existing dev flow is available.

  **Parallelization**: Can Parallel: NO | Wave 3 | Blocks: 8,9 | Blocked By: 2

  **References**:
  - Pattern: `frontend/src/app/pages/EvidencePanel.tsx` - existing route to refactor.
  - Pattern: `frontend/src/app/features/evidence/EvidenceFilters.tsx` - severity/module toolbar patterns.
  - Pattern: `frontend/src/app/features/evidence/EvidenceResults.tsx` - current table/status patterns.
  - Pattern: `frontend/src/app/components/analysis/AnalysisPrimitives` - existing analysis UI primitives.
  - Pattern: `frontend/src/app/components/DesignSystem.tsx` - `MetricCard`, `StatusHint`, `SurfacePanel`.

  **Acceptance Criteria**:
  - [ ] Evidence route has Hero + summary metrics + facet sidebar + dense result list/table + detail panel.
  - [ ] Facets include module, feature/source type, entity, severity, confidence/search where supported by current data.
  - [ ] Detail panel shows overview/context/detection/actions sections, hiding absent fields cleanly.
  - [ ] Report/export remain available.
  - [ ] Tests assert facet filtering, row selection, detail panel content, empty data, and no `undefined` text.

  **QA Scenarios**:
  ```
  Scenario: Evidence investigation center filters and selects evidence
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- EvidencePanel
    Expected: tests assert facets, dense row selection, and detail panel content
    Evidence: .omo/evidence/task-7-evidence-center.txt

  Scenario: Evidence center handles unavailable metadata
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- EvidencePanel evidencePanelRules
    Expected: tests assert missing JA3/IOC/WebShell version data shows explicit partial/unavailable state without fake records
    Evidence: .omo/evidence/task-7-evidence-center-empty.txt
  ```

  **Commit**: YES | Message: `feat(frontend): upgrade evidence investigation center` | Files: Evidence page/components/rules/tests

- [x] 8. Align cross-feature labels, empty states, and actions

  **What to do**: Run an integration polish pass across Evidence, Threat Hunting, WebShell, Industrial, and JA3/TLS surfaces. Normalize labels and copy: `JA3/JA3S`, `菜刀 / China Chopper`, `WebShell family`, `version unavailable`, `DNP3`, `IOC API unavailable`, `Playbook`. Ensure packet/stream actions appear only when IDs exist.
  **Must NOT do**: Do not introduce new features or rewrite completed components.

  **Recommended Agent Profile**:
  - Category: `unspecified-low` - Reason: cross-file polish and consistency pass.
  - Skills: [] - no specialized skill required.
  - Omitted: [`code-simplifier`] - simplification is not the goal.

  **Parallelization**: Can Parallel: NO | Wave 3 | Blocks: 9 | Blocked By: 2,3,4,5,6,7

  **References**:
  - Pattern: all files changed in Tasks 2-7.
  - Pattern: `frontend/src/app/features/evidence/evidencePanelRules.ts` - central labels/search/export.
  - Pattern: `frontend/src/app/features/evidence/evidenceInvestigationReport.ts` - report labels.

  **Acceptance Criteria**:
  - [ ] Labels are consistent across all new surfaces.
  - [ ] Missing backend contracts are called out as unavailable/partial, not hidden silently.
  - [ ] Packet/stream actions render only with valid IDs.
  - [ ] Focused tests for changed surfaces still pass.

  **QA Scenarios**:
  ```
  Scenario: Cross-feature labels are consistent
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- EvidencePanel MiscTools IndustrialAnalysis ThreatHunting C2Analysis
    Expected: focused page/component tests pass with consistent labels
    Evidence: .omo/evidence/task-8-label-polish.txt

  Scenario: Actions only render with valid context
    Tool: Bash
    Steps: cd frontend; pnpm run test:run -- EvidencePanel
    Expected: tests assert packet/stream actions are hidden/disabled without IDs
    Evidence: .omo/evidence/task-8-action-guards.txt
  ```

  **Commit**: YES | Message: `test(frontend): verify evidence specialty integrations` | Files: cross-feature label/action polish and tests

- [x] 9. Run full frontend verification and fix introduced issues only

  **What to do**: Review changed files, run diagnostics/checks, fix only issues introduced by this plan, and produce evidence logs. If a pre-existing failure is found, document it and do not expand scope without user approval.
  **Must NOT do**: Do not make unrelated refactors, dependency changes, or backend edits.

  **Recommended Agent Profile**:
  - Category: `quick` - Reason: verification and small fixes.
  - Skills: [] - no specialized skill required.
  - Omitted: [`gh-fix-ci`] - this is local verification, not GitHub CI triage.

  **Parallelization**: Can Parallel: NO | Wave 4 | Blocks: none | Blocked By: 8

  **References**:
  - Command: `cd frontend && pnpm run test:run`
  - Command: `cd frontend && pnpm run typecheck`
  - Command: `cd frontend && pnpm run lint`
  - Command: `cd frontend && pnpm run format:check`
  - Command: `cd frontend && pnpm run build`
  - Project rule: `AGENTS.md` frontend uses pnpm only; do not reintroduce `package-lock.json`.

  **Acceptance Criteria**:
  - [ ] `pnpm run test:run` exits 0.
  - [ ] `pnpm run typecheck` exits 0.
  - [ ] `pnpm run lint` exits 0.
  - [ ] `pnpm run format:check` exits 0.
  - [ ] `pnpm run build` exits 0.
  - [ ] `git diff --stat -- ':!node_modules'` contains only expected frontend and `.omo/evidence` changes.

  **QA Scenarios**:
  ```
  Scenario: Full frontend verification passes
    Tool: Bash
    Steps: cd frontend; pnpm run test:run; pnpm run typecheck; pnpm run lint; pnpm run format:check; pnpm run build
    Expected: all commands exit 0
    Evidence: .omo/evidence/task-9-full-frontend-checks.txt

  Scenario: Scope check excludes unrelated churn
    Tool: Bash
    Steps: git diff --stat -- ':!node_modules'
    Expected: changed files match this UI upgrade scope; unrelated package/cache/state files are reverted or explained
    Evidence: .omo/evidence/task-9-scope-check.txt
  ```

  **Commit**: YES | Message: `chore(frontend): verify evidence ui upgrade` | Files: verification fixes only if needed

## Final Verification Wave (MANDATORY — after ALL implementation tasks)
> 4 review agents run in PARALLEL. ALL must APPROVE. Present consolidated results to user and get explicit "okay" before completing.
> **Do NOT auto-proceed after verification. Wait for user's explicit approval before marking work complete.**
> **Never mark F1-F4 as checked before getting user's okay.** Rejection or user feedback -> fix -> re-run -> present again -> wait for okay.
- [x] F1. Plan Compliance Audit — oracle
- [x] F2. Code Quality Review — unspecified-high
- [x] F3. Real Manual QA — unspecified-high (+ playwright if the frontend dev server can be started)
- [x] F4. Scope Fidelity Check — deep

## Commit Strategy
- Commit after each task only if the task passes its focused QA.
- Keep commits atomic by surface: tests, evidence model, playbooks, WebShell, DNP3, JA3, Evidence center, polish, verification.
- Do not commit `.omo/drafts/*`.
- Do not push unless explicitly requested.

## Success Criteria
- User can open existing Evidence page and see a high-density investigation workflow for new capabilities.
- User can open existing specialty pages and see embedded first-class surfaces for Playbooks, WebShell/China Chopper, DNP3, and JA3/JA3S where data exists.
- IOC gap is explicitly visible as unavailable/partial where relevant until backend HTTP contract exists.
- Backend contract gaps do not crash UI and are never represented as fake findings.
- All frontend checks pass.
