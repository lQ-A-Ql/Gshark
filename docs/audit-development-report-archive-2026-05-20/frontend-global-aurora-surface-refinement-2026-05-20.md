# Frontend Global Aurora Surface Refinement

- Author: Codex
- Timestamp: 2026-05-20 23:56:51 +08:00

## Scope

This round continued the frontend-wide beautification pass after user visual review. The work is visual-only and focuses on reducing the detached-card feeling of secondary panels and primary actions.

No API contracts, routing behavior, capture lifecycle, stream loading logic, or backend code were changed.

## Latest Document Review

Reviewed current project instructions and newest frontend development reports before implementation:

- `docs/audit-development-report-archive-2026-05-20/frontend-full-visual-audit-beautification-plan-2026-05-20.md`
- `docs/audit-development-report-archive-2026-05-20/worker-a-frontend-hard-card-residue-cleanup-2026-05-20.md`
- `docs/audit-development-report-archive-2026-05-20/frontend-stream-light-sync-worker-c-2026-05-20.md`

Review conclusions:

- The established design direction remains the light forensic cockpit with low-boundary glass surfaces.
- Stream pages should stay as dedicated payload workbenches, but their chrome and empty states should match the global surface language.
- The newest user feedback is valid: some nested aurora panels and primary buttons still looked like independent blocks because they reused first-level surface styling too deeply.

## Changes

- Added `gshark-inset-halo` as a lightweight nested information surface.
  - It removes hard borders and avoids outer drop shadows.
  - It uses route theme variables through `--gshark-bg-accent` and `--gshark-bg-accent-2`.
  - It is intended for secondary guide cards, empty states, and inline hints inside a larger aurora surface.
- Replaced welcome guide cards with `gshark-inset-halo`.
- Replaced the UDP/TCP/HTTP current chunk empty-state shell with `gshark-inset-halo`.
- Reduced `gshark-control-primary` from a saturated blue block into a translucent theme-aware glass action.
- Removed forced white text from the stream view-mode selected segment so the new light primary action keeps readable theme-color text.

## Browser QA

Checked the running local app at `http://127.0.0.1:5174/`.

Reviewed:

- Home welcome page guide cards and the `选择文件` primary action.
- `/udp-stream` current chunk empty state.
- Header and sidebar geometry after the surface-position fix from the previous pass.
- Route theme variables on `/udp-stream`.

Observed results:

- Home guide cards now render as subtle inset halos instead of separate hard panels.
- `选择文件` now blends with the page background while remaining identifiable as the primary action.
- UDP current chunk empty state uses the cyan route accent and no longer reads as a nested card.
- Header remains `1918 x 48`; sidebar remains `64px` wide with `44 x 44` nav items.
- No horizontal overflow was observed in the browser checks.

Saved QA screenshots:

- `output/visual-qa/home-inset-halo-primary-2026-05-20.png`
- `output/visual-qa/udp-inset-halo-empty-2026-05-20.png`

## Validation

Passed:

```powershell
cd frontend
pnpm run ci
```

CI included package-manager check, TypeScript strict check, ESLint, scoped Prettier format check, size budget, boundary checks, client/mapper/wire any checks, Wails binding check, Vitest, and Vite build.

Vitest result from CI:

- 225 test files passed
- 692 tests passed

Also passed:

```powershell
git diff --check
```

## Self Review

- The latest changes use theme variables rather than a fixed blue/cyan overlay, so pages with rose, amber, emerald, indigo, blue, and cyan accents can share the same surface grammar.
- The new nested surface role avoids repeating first-level aurora depth inside an already translucent parent.
- Primary actions are softer now, but still preserve color and hover affordance.
- Remaining risk: some module-specific hard color utilities still exist in specialized MISC and decoder modules. The global fallback softens many of them, but a future pass should migrate those components to shared primitives where it is semantically safe.
