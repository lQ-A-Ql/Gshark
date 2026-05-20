# Frontend Logo Control Form Boundary Dissolve

- Author: Codex
- Timestamp: 2026-05-20 21:55:29 +08:00

## Summary

Continued the global glass UI refinement by dissolving hard boundaries on logo marks, shared buttons, built-in inputs, selects, and form surfaces. The implementation keeps brand recognition and control affordance, but moves controls from visible boxed widgets toward low-contrast glass elements with soft focus glow.

Stream tracing pages remain structurally excluded. They only inherit minor shared-control softening from common primitives.

## Changed Areas

- `frontend/src/styles/theme.css`
  - Added shared control variables and utilities: `gshark-control`, `gshark-control-primary`, `gshark-control-ghost`, `gshark-field`, `gshark-form-surface`, and `gshark-brand-mark`.
  - Added soft focus glow rules and tiled-page fallback rules for inputs, textareas, and select triggers.
- `frontend/src/app/components/ui/{button,input,select}.tsx`
  - Migrated shared button, input, and select primitives to the new low-boundary glass control utilities.
  - Kept keyboard focus states visible through soft outer glow.
- `frontend/src/app/layouts/{MainHeader,MainFooter,MainSidebarNav}.tsx`
  - Softened header/footer/sidebar chrome.
  - Converted top logo to `gshark-brand-mark`.
  - Reduced hard badge, menu, tooltip, and settings-button framing.
- `frontend/src/app/components/CaptureWelcomePanel.tsx`
  - Converted welcome path input and actions to shared glass controls.
  - Softened the large background logo watermark and status/recent-file surfaces.
- `frontend/src/app/misc/modules/{GenericMiscFormFields,GenericMiscSelectField}.tsx`
  - Moved generic module forms to `gshark-form-surface` and `gshark-field`.
- High-impact control hotspots
  - Softened workspace file/filter/paging controls.
  - Softened USB tab/device controls, evidence filters, object export controls, vehicle DBC controls, and threat hunting config fields.

## Validation

- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run format:check` passed.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run boundary:check` passed.
- Targeted Vitest set passed:
  - `select.test.tsx`
  - `GenericMiscSelectField.test.tsx`
  - `AnalysisCockpit.test.tsx`
  - `Workspace.test.tsx`
  - `MiscTools.test.tsx`
  - `UsbAnalysis.test.tsx`
  - `C2Analysis.decrypt.test.tsx`
  - `EvidencePanel.test.tsx`
  - `ObjectExportPanels.test.tsx`
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
- `/evidence`
- `/objects`
- `/vehicle-analysis`
- `/updates`
- `/http-stream`
- `/tcp-stream`
- `/udp-stream`

Result:

- Logo remains recognizable but visually blends into the glass shell.
- Buttons, icon buttons, selects, and text fields no longer present as hard white boxes.
- Main analysis pages keep the no-card glass partition style.
- No horizontal overflow was observed in the checked screenshots.
- HTTP/TCP/UDP stream pages kept their stream workbench structure.

## Artifacts

Temporary Playwright screenshots were created under the system temp directory for visual review and removed after inspection. No samples, build outputs, or Playwright artifacts are intended for commit.
