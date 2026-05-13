# Development Report Summary - 2026-05-09 to 2026-05-12

Author: Codex

Timestamp: 2026-05-12 20:06:00 +08:00

## Scope

This index reorganizes recent engineering reports by actual development date. It does not replace the source reports and does not move historical entries. The main cleanup target is the misleading placement of many 2026-05-12 rounds inside `docs/audit-development-report-archive-2026-05-11/frontend-engineering-report-2026-05-11.md`.

## Source Map

| Actual date | Primary source reports | Notes |
|---|---|---|
| 2026-05-09 | `docs/audit-development-report-archive-2026-05-09/frontend-engineering-report-2026-05-09.md` | Frontend presentation and feature split baseline. |
| 2026-05-10 | `docs/audit-development-report-archive-2026-05-10/frontend-engineering-report-2026-05-10.md` | Frontend module split continued into evidence, stream, C2, industrial, vehicle, USB, and workspace areas. |
| 2026-05-11 | `docs/audit-development-report-archive-2026-05-11/mainline-audit-and-roadmap-2026-05-11.md`; parts of `docs/audit-development-report-archive-2026-05-11/frontend-engineering-report-2026-05-11.md` | Mainline evidence/report contract work, transport contracts, benign baseline calibration, bridge guardrails. |
| 2026-05-12 | Many entries currently inside `docs/audit-development-report-archive-2026-05-11/frontend-engineering-report-2026-05-11.md`; see `docs/audit-development-report-archive-2026-05-12/README.md` | Actual 2026-05-12 rounds should be treated as the 2026-05-12 archive even though the source file name says 2026-05-11. |
| 2026-05-06 corpus context | `docs/public-sample-corpus-2026-05-06.md` | Public/benign sample policy and threat corpus tracking context used by later validation work. |

## 2026-05-09 Summary

Primary theme: first major frontend engineering split pass.

Main work:

- Split stream decoder UI and workbench sections into smaller render and settings units.
- Split runtime settings sidebar, capture mission panels, packet virtual table parts, packet byte layout, USB and vehicle overview panels.
- Extracted shared raw TCP/UDP stream helpers.
- Split APT attribution, media transcription workflow, update center, and object export feature surfaces.
- Introduced or maintained focused validation through frontend typecheck, lint, size check, Vitest, and build runs.

Interpretation:

- This date established the presentation-split pattern: pages and large panels were reduced without changing public behavior.
- Engineering value was mostly file-size reduction and lower-risk UI composition boundaries.

## 2026-05-10 Summary

Primary theme: feature-level frontend split and C2/workbench cleanup.

Main work:

- Split Evidence panel sections and shared result/table components.
- Split HTTP stream page and raw stream controls/dialog sections.
- Split C2 decrypt workbench, candidate/results panels, aggregate panels, and related feature hooks.
- Continued industrial, vehicle, USB, threat hunting, and workspace component decomposition.
- Strengthened size-budget discipline and kept `pnpm run ci` as the frontend validation target.

Interpretation:

- This date moved from generic UI split toward domain feature modules.
- The work reduced page bloat but still mainly addressed file structure rather than deeper state ownership or backend contracts.

## 2026-05-11 Summary

Primary theme: mainline guardrails, evidence/report contracts, and baseline calibration.

Main work:

- Added shared investigation report contract and frontend consumption contract.
- Improved Evidence and Investigation Report alignment around severity, tags, packet linkage, and object evidence usefulness.
- Added backend/frontend regression gates for report schema and evidence/report convergence.
- Expanded transport and bridge contract tests, including aggregation and factory-level behavior.
- Added public/benign protocol baselines and refined USB/object false-positive handling.
- Kept MISC as an auxiliary workbench rather than mixing it into unified Evidence.

Interpretation:

- This date marks the shift from "make files smaller" to "make mainline security-analysis behavior testable."
- The strongest source for 2026-05-11 direction is `mainline-audit-and-roadmap-2026-05-11.md`.

## 2026-05-12 Summary

Primary theme: contract and ownership hardening after the first engineering split phase.

Important note:

- The primary source is currently `docs/audit-development-report-archive-2026-05-11/frontend-engineering-report-2026-05-11.md`.
- That file contains many entries whose `Time:` value is 2026-05-12, including rounds 188-205 near the top and rounds 156-179 near the bottom.
- Treat those entries as 2026-05-12 work when reviewing progress.

Main work:

- Migrated frontend code toward domain clients and away from aggregate bridge usage.
- Split backend client singleton/facade boundaries and added Wails bridge import and size guards.
- Added boundary-script regression coverage and bridge type import guards.
- Extracted Sentinel state ownership slices for selected packet, stream, capture start workflow, and packet page state.
- Added capability-aware TShark field planning across packet list, fast list, direct scans, C2 HTTP candidates, stream follow, traffic stats, frame IDs, and USB analysis.
- Added optional TShark field degradation notes so missing optional fields can be explained instead of silently failing.
- Deepened frontend boundary checks around feature boundaries and Evidence page contract imports.
- Moved Evidence contracts toward core ownership.
- Extracted tool runtime state helpers.

Interpretation:

- This date targets the second engineering layer: calling-contract boundaries, state ownership, external dependency drift, and architecture checks.
- The report location is misleading, but the content aligns with the current engineering roadmap.

## Current Report Hygiene Problems

1. `frontend-engineering-report-2026-05-11.md` is no longer a pure 2026-05-11 report.
2. Round numbering is not chronological in that file: newer rounds appear near the top, while later appended 2026-05-12 rounds also appear near the bottom.
3. Source reports mix daily engineering logs, roadmap/audit notes, validation results, and self-audit entries.
4. Archive folder date and actual `Time:` date can disagree.

## Cleanup Decision

This pass does not physically split or rewrite the historical source report. The safer cleanup is:

- Keep original reports immutable for traceability.
- Add this date-based index as the review entry point.
- Add a 2026-05-12 archive README that points to the misplaced source entries.
- From now on, append new work to the actual-date archive path.

Physical splitting of the 2026-05-11 report is possible later, but it would create a large diff and risks losing historical ordering context.

## Forward Rule

For future development rounds:

1. Choose report archive by actual local date, not by the previous report filename.
2. Use `docs/audit-development-report-archive-YYYY-MM-DD/README.md` as the archive entry point.
3. Keep daily reports focused:
   - engineering log
   - audit/roadmap
   - sample/corpus validation
   - release/runtime diagnostics
4. If a report continues past midnight, start a new dated archive instead of appending to the old file.
5. End every round with author, timestamp, validation status, and explicit source files touched.

## Latest Round Note

This cleanup only reorganizes documentation entry points. No source code, tests, samples, build outputs, or report history were modified.
