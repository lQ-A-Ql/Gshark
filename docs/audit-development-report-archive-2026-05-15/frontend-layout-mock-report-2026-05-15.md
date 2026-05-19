# Frontend Layout Mock Report - 2026-05-15

Author: Codex

Timestamp: 2026-05-15 01:34:11 +08:00

## Round Goal

Generate a static approval mock before touching real frontend React code. The mock must preserve the current logo image placement, keep the main workspace 品字形 structure, and show a high-density work-module card direction.

## Files Changed

- `frontend/mock.html`
- `docs/audit-development-report-archive-2026-05-15/frontend-layout-mock-report-2026-05-15.md`

No React source, Vite config, package manifest, lockfile, mapper/client/wire code, or route implementation was changed in this round.

## Document Review

- `docs/README.md` still frames the product as an offline traffic analysis, dangerous-application triage, and evidence-chain workbench. The mock follows that operational tool direction instead of a marketing-page direction.
- `docs/frontend-engineering-audit-spec-2026-05-15.md` identifies UI engineering consistency, frontend boundary checks, pnpm-only governance, and dense workbench behavior as current concerns. The mock is intentionally isolated from CI-sensitive source paths.
- `docs/backend-engineering-audit-spec-2026-05-14.md` continues to connect frontend DTO/schema maturity to `P2-6`; this round does not touch contracts.
- `docs/misc-module-interface.md` and `docs/plugin-interface.md` clarify that MISC/plugins are local trusted extension points. The mock reflects MISC module cards as host-rendered work units rather than plugin-owned custom frontend surfaces.
- `docs/governance-defect-register.json` still keeps `P2-6` open; no governance status changes were made.

## Implementation Notes

- Created a standalone static HTML approval page at `frontend/mock.html`.
- The page directly references `src/assets/logo.png`, matching the current welcome-panel asset location.
- The welcome panel keeps the logo as a low-opacity absolute-position watermark inside the main welcome area.
- The workspace preview preserves the 品字形 pattern: packet table above, protocol tree and Hex/ASCII below.
- Dense module cards show collapsed and expanded states with compact titles, status chips, hit counts, and right-aligned actions.
- The mock uses no external dependencies and does not require a local dev server.

## Validation

- `git status --short` was inspected before editing; existing unrelated changes were left untouched.
- Documentation context was reviewed before writing the mock.
- `Test-Path frontend/mock.html` — PASS.
- `Test-Path docs/audit-development-report-archive-2026-05-15/frontend-layout-mock-report-2026-05-15.md` — PASS.
- `Select-String frontend/mock.html -Pattern "watermark-logo|Workspace 品字形 locked|Dense module cards candidate|src/assets/logo.png"` — PASS.
- `git diff --check -- frontend/mock.html docs/audit-development-report-archive-2026-05-15/frontend-layout-mock-report-2026-05-15.md` — PASS.

## Self-Review

- The mock is scoped as an approval artifact only, so it should not be treated as production UI implementation.
- It avoids package changes and frontend source changes, so current pnpm, boundary, mapper, wire, and Vite gates are not affected.
- The design intentionally keeps the existing logo and workspace structure stable while making module cards denser and more scan-friendly.

## Remaining Risks

- Visual approval is still manual; browser screenshots across 1440, 1280, 768, and 390 widths should be reviewed before migrating the design to React components.
- If approved, the real implementation must update component tests and run the current frontend CI gate.

## Next Recommended Task

Open `frontend/mock.html` in a browser and approve or adjust the three visual locks: logo placement, 品字形 workspace, and dense work-module card density. After approval, migrate the accepted card density into the real React components with full frontend gate validation.

## Follow-up Revision - 2026-05-15 01:42:46 +08:00

### Revision Goal

Split the welcome page and main workspace into separate approval pages, then complete static mock coverage for the remaining frontend route surfaces.

### Files Changed

- `frontend/mock.html`
- `docs/audit-development-report-archive-2026-05-15/frontend-layout-mock-report-2026-05-15.md`

### Document Review

- Rechecked `docs/README.md` and confirmed the UI direction should remain an operational offline traffic analysis and evidence-chain workbench.
- Rechecked the latest tail of `docs/backend-engineering-audit-spec-2026-05-14.md`; script governance work is complete through `BE-SCRIPT-7.5`, with next backend focus on model classification or schema/codegen decision notes.
- Rechecked `frontend/src/app/routes.tsx` and used it as the route list for mock coverage.

### Implementation Notes

- Reworked `frontend/mock.html` into a route-level static approval console.
- Added tab and left-rail switching using dependency-free inline JavaScript.
- Split `Welcome` and `Workspace` into separate pages.
- Preserved the welcome logo image as `src/assets/logo.png` in the welcome page's low-opacity watermark position.
- Preserved the main workspace 品字形 layout on its own page.
- Added mock pages for:
  - analysis cockpit
  - HTTP stream
  - TCP stream
  - UDP stream
  - threat hunting
  - object export
  - MISC tools
  - update center
  - traffic graph
  - C2 analysis
  - APT analysis
  - industrial analysis
  - vehicle analysis
  - media analysis
  - USB analysis
  - evidence panel
- Kept the mock independent from React/Vite routes, dependencies, lockfiles, frontend source, mapper/client/wire code, and package manager behavior.

### Validation

- `Test-Path frontend/mock.html` — PASS.
- `Test-Path docs/audit-development-report-archive-2026-05-15/frontend-layout-mock-report-2026-05-15.md` — PASS.
- `Select-String frontend/mock.html -Pattern "id=\"page-|src/assets/logo.png|watermark-logo|Workspace 品字形 locked|data-page=\"welcome\"|data-page=\"workspace\""` — PASS.
- `Select-String frontend/mock.html -Pattern "class=\"mock-page"` — PASS, 18 pages found.
- Static target consistency check — PASS, 18 pages, 18 targets, 0 targets without pages, 0 pages without targets.
- `git diff --check -- frontend/mock.html docs/audit-development-report-archive-2026-05-15/frontend-layout-mock-report-2026-05-15.md` — PASS.
