# Frontend Forensic Cockpit Refinement

- Author: Codex
- Timestamp: 2026-05-20 22:25:16 +08:00

## Summary

Continued the frontend visual refresh toward a mature forensic cockpit style while preserving the existing light gradient, global frosted glass shell, no-card rectangular partition model, and low-boundary controls.

The change is visual-only: no API, route, cache, backend contract, data model, or analysis behavior was changed.

## Changed Areas

- `frontend/src/styles/theme.css`
  - Added forensic cockpit semantic variables for risk, evidence, scan highlight, status glow, and dense table states.
  - Enhanced the global glass curtain with a subtle diagonal sheen and slightly stronger blur/saturation.
  - Added shared utilities: `gshark-forensic-scan`, `gshark-status-dot`, `gshark-risk-accent`, `gshark-evidence-accent`, and `gshark-workbench-panel`.
  - Tuned shared tile, soft fill, table header, hover, and primary control surfaces for a more consistent cockpit feel.

- Shared visual components
  - Updated `AnalysisHero`, `AnalysisCards`, `AnalysisDataTable`, and `DesignSystem` primitives.
  - Added status dots to `StatusHint`.
  - Unified workbench title bars and chips with the same evidence-accent glass surface.
  - Improved table header density and row hover/expanded states.

- Workspace and capture cockpit
  - Softened `HexAsciiPanel` header, packet badge, empty state, byte selection, and row hover states.
  - Updated capture mission overview, recommendations, quick filters, threat hits, and payload shortcut panels to use shared cockpit utilities instead of hard white blocks and visible borders.

- Runtime settings
  - Migrated settings header, action bar, footer, section shells, fields, dependency cards, status lines, and mini status blocks to shared glass controls and soft status accents.

- MISC module shell
  - Migrated common MISC module surfaces, generic module chrome, meta chips, and error blocks to shared soft-edge utilities.
  - This reduces page-specific visual fragments without changing module behavior.

- Stream tracing light sync
  - Lightly updated HTTP/TCP/UDP shared controls: title bar, control bar, navigator, search box, view mode toggle, metric chips, and export buttons.
  - Stream layout, payload panels, route behavior, data flow, scrolling behavior, and workbench structure were not migrated.

## Validation

- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run format:check` passed.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run boundary:check` passed.
- Targeted Vitest set passed:
  - `Workspace.test.tsx`
  - `AnalysisCockpit.test.tsx`
  - `C2Analysis.decrypt.test.tsx`
  - `AptAnalysis.test.tsx`
  - `UsbAnalysis.test.tsx`
  - `UsbAnalysis.hidPanel.test.tsx`
  - `EvidencePanel.test.tsx`
  - `ObjectExportPanels.test.tsx`
  - `MiscTools.test.tsx`
  - `IndustrialAnalysis.test.tsx`
  - `VehicleAnalysis.test.tsx`
  - `MediaAnalysis.test.tsx`
  - `TrafficGraph.test.ts`
- `cd frontend && pnpm run ci` passed.
- `git diff --check` passed.

## Chrome / Playwright Check

Used Playwright CLI with Chrome against local backend and Vite services.

Checked routes:

- `/`
- `/analysis-cockpit`
- `/misc`
- `/usb-analysis`
- `/c2-analysis`
- `/apt-analysis`
- `/evidence`
- `/objects`
- `/vehicle-analysis`
- `/industrial-analysis`
- `/media-analysis`
- `/updates`
- `/http-stream`
- `/tcp-stream`
- `/udp-stream`

Result:

- No horizontal overflow was observed on checked routes.
- No runtime error text was detected on checked routes.
- Main analysis pages keep the unified light-glass no-card cockpit style.
- MISC and settings surfaces now share softer status and evidence accents.
- HTTP/TCP/UDP stream pages kept their workbench structure and only inherited shared-control visual softening.

## Artifacts

Temporary screenshots were created under the system temp directory and removed after inspection. Playwright CLI's local temporary state directory was removed after the check. No samples, build outputs, screenshots, or this development report are intended for commit.

## Follow-up: Stream Control Cluster Polish

- Author: Codex
- Timestamp: 2026-05-20 22:30:55 +08:00

Refined the HTTP/TCP/UDP stream tracing control cluster shown in the toolbar. The old region read as three separate boxed widgets; it now uses a shared stream control cluster surface, softer metric chip, inset stream location segment, compact numeric stream input, and smoother segmented view-mode toggle.

Changed files:

- `frontend/src/styles/theme.css`
  - Added `gshark-stream-control-cluster`, `gshark-stream-segment`, and `gshark-stream-value`.
- `frontend/src/app/components/DesignSystem.tsx`
  - Updated `WorkbenchChip` to use the stream control cluster treatment.
- `frontend/src/app/components/stream/StreamNavigator.tsx`
  - Reworked stream switcher spacing, segment, arrow buttons, and stream-id input.
- `frontend/src/app/components/stream/ViewModeToggle.tsx`
  - Reworked the view-mode switcher into the same compact stream cluster style.

Validation:

- `pnpm exec vitest run src/app/components/stream/StreamNavigationControls.test.tsx src/app/pages/HttpStreamChunks.test.ts src/app/pages/useRawStreamRouteSelection.test.tsx src/app/pages/useRawStreamPageLoader.test.tsx` passed.
- `pnpm run typecheck` passed.
- `pnpm run lint` passed.
- `pnpm run format:check` passed.
- `git diff --check` passed.
