# Worker A Frontend Hard Card Residue Cleanup

- Author: Codex Worker A
- Timestamp: 2026-05-20 22:55:59 +08:00

## Scope

This round covered only Worker A frontend beautification files for threat hunting, C2, APT, and update center panels. The change is visual-only: no API calls, routing, state transitions, filtering logic, table data flow, export behavior, or tests were intentionally changed.

## Latest Document Review

Required documents reviewed before implementation:

- `docs/audit-development-report-archive-2026-05-20/frontend-full-visual-audit-beautification-plan-2026-05-20.md`
- `docs/audit-development-report-archive-2026-05-20/frontend-forensic-cockpit-refinement-2026-05-20.md`

Review conclusions:

- The current design direction is stable: light forensic cockpit, frosted glass shell, dense rectangular workbench partitions, and low-boundary controls.
- Worker A should reduce local hard-card styling rather than introduce a new theme or restructure pages.
- `gshark-soft-fill`, `gshark-diffuse-chip`, `gshark-tile-header`, `gshark-control`, and existing analysis primitives are the right replacement targets for neutral panels, chips, and compact actions.
- Code, JSON, payload, and plaintext previews may keep stronger contrast when it improves forensic readability.

## Changed Areas

- Threat hunting result and summary panels
  - Removed hard slate table/header borders and hard pale backgrounds from result headers and detail panes.
  - Updated hit-detail actions to use `gshark-control`.
  - Kept threat match preview in a risk-colored surface for visual salience.

- C2 aggregate, decrypt, candidate, and display components
  - Replaced neutral sub-panels with `gshark-soft-fill`.
  - Replaced local pill/tag shells with `gshark-diffuse-chip`.
  - Reworked expand/export controls to use `gshark-control`.
  - Switched table header/row styling to shared tile/table variables.
  - Kept decrypt plaintext preview as a high-contrast code block.

- APT display, evidence, timeline, and attribution panels
  - Replaced local status badges with `AnalysisBadge` where available.
  - Replaced neutral timeline cards and missing-evidence blocks with `gshark-soft-fill`.
  - Replaced APT evidence tags and caveat chips with diffuse chip styling.

- Update center panels
  - Replaced release note, status tile, step card, and diagnostic row hard surfaces with `gshark-soft-fill`.

## Static Residue Result

The Worker A file set was scanned for:

```powershell
bg-white|bg-slate-50|border-slate-200|shadow-sm|rounded-xl|rounded-2xl
```

Result: no matches remain in the Worker A file set.

## Validation

Passed:

```powershell
cd frontend
pnpm exec prettier --check src/app/features/hunting/ThreatHuntingResultPanels.tsx src/app/features/hunting/ThreatHuntingSummaryPanels.tsx src/app/features/c2/C2AggregateDetails.tsx src/app/features/c2/C2DecryptResultPanel.tsx src/app/features/c2/C2CandidateTable.tsx src/app/features/c2/C2DisplayComponents.tsx src/app/features/apt/APTDisplayComponents.tsx src/app/features/apt/APTEvidenceBadges.tsx src/app/features/apt/APTEvidenceTimeline.tsx src/app/features/apt/APTAttributionPanel.tsx src/app/features/update/UpdateCenterPanels.tsx
pnpm exec eslint src/app/features/hunting/ThreatHuntingResultPanels.tsx src/app/features/hunting/ThreatHuntingSummaryPanels.tsx src/app/features/c2/C2AggregateDetails.tsx src/app/features/c2/C2DecryptResultPanel.tsx src/app/features/c2/C2CandidateTable.tsx src/app/features/c2/C2DisplayComponents.tsx src/app/features/apt/APTDisplayComponents.tsx src/app/features/apt/APTEvidenceBadges.tsx src/app/features/apt/APTEvidenceTimeline.tsx src/app/features/apt/APTAttributionPanel.tsx src/app/features/update/UpdateCenterPanels.tsx
pnpm exec vitest run src/app/pages/C2Analysis.test.tsx src/app/pages/C2Analysis.decrypt.test.tsx src/app/pages/C2Analysis.candidates.test.tsx src/app/pages/C2Analysis.vshell.test.tsx src/app/pages/AptAnalysis.test.tsx src/app/features/hunting/ThreatHuntingMetricCards.test.tsx src/app/features/update/useUpdateCenter.test.tsx src/app/features/update/UpdateReleaseMarkdown.test.tsx src/app/features/update/updateCenterUtils.test.ts
pnpm run typecheck
```

Targeted Vitest result: 9 files passed, 24 tests passed.

## Remaining Risk

- This was a scoped visual cleanup without browser screenshot QA. Final visual review should happen after parallel workers finish and the full frontend surface is coherent.
- The working tree contains unrelated parallel frontend changes outside Worker A scope; they were not modified or reverted in this round.
