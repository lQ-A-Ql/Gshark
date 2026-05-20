# Frontend Diffuse Edge Glass Refinement

- Author: Codex
- Timestamp: 2026-05-20 21:33:03 +08:00

## Summary

Implemented the global "soft diffuse edge" refinement for the frontend glass redesign. The change weakens hard 1px outlines, icon boxes, tab boxes, report section chips, and repeated module shell borders into softer translucent boundaries with low-contrast glow and frosted fill.

Stream tracing pages remain structurally excluded: HTTP/TCP/UDP raw stream workbench files were not migrated.

## Changed Areas

- `frontend/src/styles/theme.css`
  - Lowered tile/divider/curtain border strength.
  - Added diffuse edge and diffuse chip utilities.
  - Added tiled-page CSS fallback that softens common hard border/background utility classes inside tiled pages.
- `frontend/src/app/components/AnalysisHero.tsx`
  - Converted hero icon, tags, and refresh action to diffuse glass styling.
- `frontend/src/app/components/analysis/AnalysisCards.tsx`
  - Reused soft fill/diffuse chip styling for shared stat, panel, badge, and callout primitives.
- `frontend/src/app/components/analysis/AnalysisDataTable.tsx`
  - Replaced hard row borders with the global tile divider variable.
- `frontend/src/app/components/DesignSystem.tsx`
  - Softened shared metric, status, and workbench title bar primitives.
- `frontend/src/app/components/InvestigationReportPanel.tsx`
  - Softened report schema badges, severity chips, tags, caveats, and section surfaces.
- `frontend/src/app/components/ui/{badge,button,card,select,dialog,alert-dialog,tooltip,FloatingSurface}.tsx`
  - Aligned shared UI primitives with diffuse glass borders while keeping focus/interaction states visible.
- `frontend/src/app/misc/**`
  - Softened MISC hero, module cards, generic module chrome, form fields, result panels, module badges, delete actions, evidence actions, and module icon surfaces.

## Review Notes

- The implementation is intentionally global-first. Page-specific MISC and analysis shell edits only replace repeated hard border patterns that were not fully covered by shared primitives.
- Hard code/terminal blocks remain visually distinct where semantic contrast is useful.
- Dialog, select, tooltip, and floating surfaces retain panel identity but use reduced opacity borders and softer shadows.

## Validation

- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run format:check` passed.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run boundary:check` passed.
- `cd frontend && pnpm exec vitest run src/app/pages/MiscTools.test.tsx src/app/pages/EvidencePanel.test.tsx src/app/pages/UsbAnalysis.test.tsx src/app/pages/AptAnalysis.test.tsx src/app/pages/C2Analysis.test.tsx` passed.
- `cd frontend && pnpm exec vitest run src/app/pages/C2Analysis.decrypt.test.tsx` passed after updating the select style assertion.
- `cd frontend && pnpm run ci` passed.
- `git diff --check` passed.

## Chrome / Playwright Check

Used Playwright CLI with Chrome against local Vite/backend services.

Checked routes:

- `/misc`
- `/usb-analysis`
- `/c2-analysis`
- `/apt-analysis`
- `/vehicle-analysis`
- `/industrial-analysis`
- `/media-analysis`
- `/evidence`
- `/objects`
- `/updates`
- `/http-stream`
- `/tcp-stream`
- `/udp-stream`

Result:

- Main analysis pages show softened boundaries and diffuse frosted sections instead of hard line boxes.
- No horizontal overflow was observed during screenshot review.
- `/http-stream`, `/tcp-stream`, and `/udp-stream` remained in their stream workbench structure.
- Temporary screenshots and local review services were removed after inspection.

## Artifacts

No build output, Playwright screenshots, samples, or generated frontend dist assets are intended for commit.
