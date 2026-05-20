# Frontend Full Visual Audit And Beautification Plan

- Author: Codex
- Timestamp: 2026-05-20 22:39:44 +08:00

## Scope

This round is a frontend-wide visual and interaction audit using the `frontend-design` skill. It does not change runtime behavior, API contracts, routes, state flow, tests, or frontend source code.

The goal is to define the next executable beautification round for the GShark Sentinel frontend after the 2026-05-20 glass cockpit redesign work.

## Latest Document Review

Reviewed current project instructions and the newest docs under `docs/` before drafting this plan.

Key documents reviewed:

- `docs/frontend-engineering-audit-spec-2026-05-15.md`
- `docs/audit-development-report-archive-2026-05-20/frontend-density-style-unification-2026-05-20.md`
- `docs/audit-development-report-archive-2026-05-20/frontend-tiled-glass-redesign-implementation-2026-05-20.md`
- `docs/audit-development-report-archive-2026-05-20/frontend-page-card-residue-cleanup-2026-05-20.md`
- `docs/audit-development-report-archive-2026-05-20/frontend-no-card-grid-reset-2026-05-20.md`
- `docs/audit-development-report-archive-2026-05-20/frontend-global-glass-curtain-no-grid-2026-05-20.md`
- `docs/audit-development-report-archive-2026-05-20/frontend-usb-glass-spacing-refinement-2026-05-20.md`
- `docs/audit-development-report-archive-2026-05-20/frontend-soft-glass-flow-spacing-fix-2026-05-20.md`
- `docs/audit-development-report-archive-2026-05-20/frontend-diffuse-edge-glass-refinement-2026-05-20.md`
- `docs/audit-development-report-archive-2026-05-20/frontend-logo-control-form-boundary-dissolve-2026-05-20.md`
- `docs/audit-development-report-archive-2026-05-20/frontend-forensic-cockpit-refinement-2026-05-20.md`

Review conclusions:

- The latest design direction is already clear: light forensic cockpit, global frosted glass shell, no-card rectangular partitioning, low-boundary controls, soft diffuse edges, and dense security-workbench information architecture.
- The current direction should not be replaced by a new theme. The next round should consolidate and govern the existing visual language.
- HTTP/TCP/UDP stream pages were repeatedly documented as structurally preserved. The next round may visually sync controls, but should not migrate their workbench structure into generic tiled pages without a separate decision.
- Prior reports contain strong validation discipline: targeted Vitest, typecheck, lint, format, size, boundary checks, full `pnpm run ci`, and Playwright/Chrome screenshot review. The next beautification round should keep that bar.
- Some documentation files from mid-evening contain garbled control characters around filenames/commands, likely encoding or paste artifacts. Future docs should keep UTF-8 clean text and command fences valid.

## Current Frontend Position

The frontend is a React 18 + Vite + TypeScript strict Wails desktop UI. It is not a marketing page; it is a dense offline traffic investigation workbench for packets, streams, threat hunting, C2/APT, industrial/vehicle/USB/media analysis, MISC protocol tooling, evidence, object extraction, runtime settings, and updates.

Current visual infrastructure:

- Global route shell: `frontend/src/app/layouts/MainLayout.tsx`
- Theme and cockpit utilities: `frontend/src/styles/theme.css`
- Route color tokens: `frontend/src/app/layouts/mainLayoutConfig.ts`
- Page shell: `frontend/src/app/components/PageShell.tsx`
- Hero primitive: `frontend/src/app/components/AnalysisHero.tsx`
- Shared cockpit primitives: `frontend/src/app/components/DesignSystem.tsx`
- Analysis cards/panels: `frontend/src/app/components/analysis/AnalysisCards.tsx`
- Analysis table: `frontend/src/app/components/analysis/AnalysisDataTable.tsx`
- UI primitives: `frontend/src/app/components/ui/*`

The existing `gshark-*` visual primitives are now the center of gravity:

- `gshark-page-bg`
- `gshark-glass-shell`
- `gshark-theme-main`
- `gshark-tile-page`
- `gshark-tile-grid`
- `gshark-tile`
- `gshark-tile-header`
- `gshark-tile-toolbar`
- `gshark-tile-table`
- `gshark-soft-fill`
- `gshark-diffuse-edge`
- `gshark-diffuse-chip`
- `gshark-control`
- `gshark-field`
- `gshark-form-surface`
- `gshark-forensic-scan`
- `gshark-status-dot`
- `gshark-risk-accent`
- `gshark-evidence-accent`
- `gshark-workbench-panel`
- `gshark-stream-control-cluster`

## Static Audit Snapshot

Static scan over `frontend/src/app/**/*.tsx`:

| Pattern | Count |
|---|---:|
| `gshark-tile` | 238 |
| `gshark-control` | 62 |
| `gshark-soft-fill` | 60 |
| `bg-slate-50` | 152 |
| `border-slate-200` | 161 |
| `bg-white` | 44 |
| `rounded-full` | 41 |
| `shadow-sm` | 40 |
| `rounded-lg` | 35 |
| `rounded-xl` | 15 |
| `rounded-2xl` | 8 |
| `shadow-md` | 1 |
| `shadow-lg` | 1 |
| `shadow-xl` | 1 |

The scan confirms that the new visual language is dominant, but hard white/surface residues still exist. Not every match is a defect: dialogs, tooltips, stream payload workbenches, badges, graph points, and terminal/code blocks can legitimately keep stronger surfaces or round shapes.

Top residue hotspots by repeated old-style tokens:

- `frontend/src/app/components/TLSDecryptionDialog.tsx`
- `frontend/src/app/features/hunting/ThreatHuntingResultPanels.tsx`
- `frontend/src/app/App.tsx`
- `frontend/src/app/features/c2/C2AggregateDetails.tsx`
- `frontend/src/app/features/c2/C2DecryptResultPanel.tsx`
- `frontend/src/app/misc/modules/HTTPLoginAttemptTable.tsx`
- `frontend/src/app/features/apt/APTDisplayComponents.tsx`
- `frontend/src/app/misc/modules/ShiroRememberMeKeyResultsPanel.tsx`
- `frontend/src/app/components/stream/StreamPayloadDialog.tsx`
- `frontend/src/app/misc/modules/*`
- `frontend/src/app/features/update/UpdateCenterPanels.tsx`

## Visual Assessment

### What Works

- The product now has a recognizable identity: a light forensic cockpit with transparent partitions, soft evidence/risk accents, and dense analysis surfaces.
- The app shell, left navigation, header, footer, settings sidebar, and major analysis pages visually belong to the same product family.
- `AnalysisHero`, `MetricCard`, `StatusHint`, `AnalysisPanel`, and `AnalysisDataTable` are strong enough to be the canonical primitives for most new screens.
- The tile model fits the product better than floating SaaS cards because the app is about repeated scanning, comparison, and investigation.
- Route-level accent themes help users understand context without turning each page into a different product.

### Main Problems

- The design system is currently implicit in CSS utility names and recent reports, not explicit as a frontend design contract. Future work may reintroduce hard cards or one-off gradients because there is no short rulebook near the code.
- Some module-specific components still use local `bg-slate-50`, `border-slate-200`, `bg-white`, and rounded/shadow patterns that compete with the diffuse glass language.
- Startup and degraded-runtime screens still read like older SaaS cards and do not fully match the mature cockpit entry experience.
- APT, threat hunting, C2 decrypt, and MISC modules contain many semantically similar chips, status panels, empty states, result blocks, and JSON/code previews implemented with local class strings.
- The visual vocabulary has too many near-equivalent containers: `gshark-tile`, `gshark-soft-fill`, `gshark-diffuse-chip`, `gshark-form-surface`, `AnalysisPanel`, `SurfacePanel`, `Card`, and page-specific mini panels. The next round should clarify when to use each.
- There is no automated visual residue check. The team currently relies on manual `rg`, review, and Playwright screenshots.

## Design Direction For Next Round

Keep the current direction and sharpen it:

**Forensic Glass Operations Console**

Traits:

- Light, cold, analytical, and precise.
- Continuous rectangular information grid instead of floating rounded cards.
- Soft glass surfaces with minimal border contrast.
- Evidence/risk/status accents reserved for meaning, not decoration.
- Dense tables and compact controls for repeated analyst workflows.
- Motion used sparingly: route transition, scan highlight, focus glow, loading progress.
- Strong contrast only for code, payloads, warnings, destructive actions, and selected investigation context.

Non-goals:

- Do not introduce dark mode in this beautification round.
- Do not switch to a marketing, landing-page, or dashboard-card aesthetic.
- Do not add ornamental gradient blobs, decorative illustrations, or large empty hero compositions.
- Do not migrate HTTP/TCP/UDP stream workbench structure unless separately approved.
- Do not replace Tailwind, Radix, lucide, Vite, or the existing React architecture.

## Beautification Plan

### Phase 1: Design Contract And Token Cleanup

Deliverables:

- Add a short design-system note, either in `frontend/guidelines/Guidelines.md` or a new `docs/frontend-visual-system-2026-05-20.md`.
- Define allowed surface roles:
  - Page shell
  - Tile region
  - Toolbar
  - Soft fill
  - Diffuse chip
  - Form field
  - Floating overlay
  - Code/payload block
  - Risk/evidence/status accent
- Document allowed exceptions for round badges, graph marks, dialogs, tooltips, selects, media player surfaces, and stream payload tools.
- Rename or group CSS comments in `theme.css` so future contributors can understand the hierarchy without reading every historical report.

Acceptance:

- The design rules are readable in under five minutes.
- The rules explicitly say when `bg-white`, hard `border-slate-200`, large `rounded-*`, and `shadow-*` are allowed.

### Phase 2: Startup And Runtime Entry Polish

Priority files:

- `frontend/src/app/App.tsx`
- `frontend/src/app/components/CaptureWelcomePanel.tsx`
- `frontend/src/app/components/RuntimeSettingsSidebar.tsx`
- `frontend/src/app/components/TLSDecryptionDialog.tsx`

Tasks:

- Convert the startup gate from old centered white card to the same forensic glass cockpit language.
- Add compact engine/tool status rows using `gshark-status-dot`, `gshark-soft-fill`, and shared controls.
- Keep the TShark path recovery workflow obvious and accessible.
- Bring TLS decryption dialog surfaces into the same low-boundary style while preserving warning contrast and form affordance.

Acceptance:

- First launch, backend loading, TShark missing, and tool probe degraded states all visually match the main app.
- No text overflow at 1280x720 and 1440x900.
- Existing startup behavior is unchanged.

### Phase 3: Module Residue Sweep

Priority files:

- `frontend/src/app/features/hunting/ThreatHuntingResultPanels.tsx`
- `frontend/src/app/features/c2/C2AggregateDetails.tsx`
- `frontend/src/app/features/c2/C2DecryptResultPanel.tsx`
- `frontend/src/app/features/c2/C2CandidateTable.tsx`
- `frontend/src/app/features/apt/APTDisplayComponents.tsx`
- `frontend/src/app/features/apt/APTEvidenceBadges.tsx`
- `frontend/src/app/features/apt/APTEvidenceTimeline.tsx`
- `frontend/src/app/features/update/UpdateCenterPanels.tsx`
- `frontend/src/app/misc/modules/*`

Tasks:

- Replace local hard surface tokens with shared primitives where semantics match.
- Convert repeated chips to `AnalysisBadge` or `gshark-diffuse-chip`.
- Convert repeated status messages to `StatusHint` or a small shared module alert primitive.
- Convert repeated result panels to `gshark-soft-fill` or `AnalysisPanel`.
- Keep payload/code/JSON previews distinct, but standardize their border and scroll styling.

Acceptance:

- Static residue counts decrease meaningfully for non-exception files:
  - `bg-white` target: below 25 in `frontend/src/app/**/*.tsx`
  - `border-slate-200` target: below 110
  - `shadow-sm` target: below 25
  - `rounded-xl` + `rounded-2xl` target: below 12 combined
- Every remaining old-style token is either in an approved exception category or documented in the PR/development report.

### Phase 4: Shared Primitive Consolidation

Priority files:

- `frontend/src/app/components/DesignSystem.tsx`
- `frontend/src/app/components/analysis/AnalysisCards.tsx`
- `frontend/src/app/components/analysis/AnalysisDataTable.tsx`
- `frontend/src/app/components/analysis/AnalysisCollections.tsx`
- `frontend/src/app/misc/modules/MiscModuleSurface.tsx`
- `frontend/src/app/misc/ui.tsx`

Tasks:

- Decide whether `SurfacePanel` and `AnalysisPanel` should remain separate. If both remain, document their use cases.
- Add a small shared `PayloadPreviewBlock` or `CodePreviewBlock` if current modules repeat JSON/code preview styling.
- Add a shared `ModuleStatusHint` if MISC modules keep repeating module-specific alert shells.
- Ensure table header, selected row, expanded row, and hover states use the same semantic variables.

Acceptance:

- New visual work can be implemented through shared primitives instead of copying class strings.
- No behavior changes to mapper, client, state, or backend calls.

### Phase 5: Stream Page Light Sync

Priority files:

- `frontend/src/app/pages/HttpStream.tsx`
- `frontend/src/app/pages/HttpStreamSections.tsx`
- `frontend/src/app/pages/RawStreamPage.tsx`
- `frontend/src/app/pages/RawStreamControlBar.tsx`
- `frontend/src/app/pages/RawStreamPayloadPanels.tsx`
- `frontend/src/app/components/stream/*`

Tasks:

- Keep stream pages structurally separate.
- Sync only toolbar, navigator, search, view mode, metric chips, and payload dialog surface tokens.
- Avoid forcing stream payload grids into generic `PageShell`.

Acceptance:

- `/http-stream`, `/tcp-stream`, and `/udp-stream` still feel like specialized workbenches.
- Their controls no longer look visually older than the rest of the app.

### Phase 6: Browser Visual QA And Regression Guard

Tasks:

- Run Playwright/Chrome screenshot review for:
  - `/`
  - `/analysis-cockpit`
  - `/c2-analysis`
  - `/apt-analysis`
  - `/hunting`
  - `/misc`
  - `/evidence`
  - `/objects`
  - `/traffic-graph`
  - `/industrial-analysis`
  - `/vehicle-analysis`
  - `/media-analysis`
  - `/usb-analysis`
  - `/updates`
  - `/http-stream`
  - `/tcp-stream`
  - `/udp-stream`
- Check at least:
  - 1280x720
  - 1440x900
  - 1920x1080
- Confirm:
  - no horizontal page overflow
  - no clipped header/footer/sidebar controls
  - no unreadable text on glass backgrounds
  - no card-in-card regression
  - no oversized hero typography inside dense workbench panels
  - stream pages keep expected structure

Optional follow-up:

- Add a local visual residue script that reports old-style token counts and approved exception paths.

## Suggested Implementation Order

1. Write the visual-system rulebook.
2. Polish `App.tsx` startup gate and runtime recovery surfaces.
3. Sweep highest-count non-stream residue files.
4. Consolidate repeated module status/code/result primitives.
5. Light-sync stream controls without structural migration.
6. Run full frontend CI plus browser visual QA.

This order keeps the entry experience and shared rules ahead of broad mechanical cleanup.

## Validation Plan

For documentation-only follow-up:

```powershell
cd C:\Users\QAQ\Desktop\gshark
git diff -- docs
```

For source changes:

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run typecheck
pnpm run lint
pnpm run format:check
pnpm run size:check
pnpm run boundary:check
pnpm run test:run
pnpm run ci
```

For targeted visual/source slices:

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec vitest run <touched test files>
```

For final local visual acceptance:

- Start backend and Vite with the same token.
- Use Chrome/Playwright screenshots across the route list above.
- Remove screenshots and temporary browser state after review unless the user asks to keep artifacts.

## Current Round Summary

- Read the `frontend-design` skill and applied it as an audit/design-planning workflow.
- Reviewed the newest frontend development documents under `docs/audit-development-report-archive-2026-05-20/`.
- Audited the frontend visual architecture, route shell, theme tokens, shared primitives, representative pages, and static style residues.
- Produced this beautification plan for the next implementation round.
- No frontend source files were modified in this round.

## Self Review

- The plan preserves the existing 2026-05-20 forensic cockpit direction instead of introducing a conflicting theme.
- The plan identifies concrete files and measurable residue targets.
- The plan keeps stream page structural boundaries intact.
- The plan includes validation steps matching the repository's frontend CI and recent Playwright review practice.
- Risk: static token counts include valid exceptions, so implementation should use judgment rather than blindly removing every match.
