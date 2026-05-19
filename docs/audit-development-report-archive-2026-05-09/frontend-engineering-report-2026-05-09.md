# Frontend Engineering Report - 2026-05-09

Author: Codex

Timestamp: 2026-05-09 15:04:13 +08:00

## Scope

Continue frontend engineering cleanup after the CI/package-manager hardening work. This round focused on shrinking a mixed-purpose stream decoder utility file without changing public component imports or user-facing behavior.

## Changes

- Split `StreamDecoderWorkbenchUtils.ts` into focused modules:
  - `StreamDecoderTypes.ts`: shared decoder settings, batch types, constants, and defaults.
  - `StreamDecoderHintUtils.ts`: decoder name normalization, hint merging, option building, and hint badges.
  - `StreamDecoderPayloadUtils.ts`: batch ordinal clamping, transport payload normalization, abort detection, and decoder input preparation.
  - `StreamDecoderSettingsStorage.ts`: localStorage read/write for decoder settings.
- Kept `StreamDecoderWorkbenchUtils.ts` as a compatibility export facade so existing imports remain stable.
- Added size-budget entries for the new modules and capped the compatibility facade at 40 lines to prevent it from becoming a mixed utility file again.

## Validation

```powershell
cd frontend; pnpm exec vitest run src/app/components/StreamDecoderWorkbenchUtils.test.ts scripts/check-size.test.mjs
cd frontend; pnpm run size:check
cd frontend; pnpm run typecheck
cd frontend; pnpm run lint
cd frontend; pnpm run format:check
cd frontend; pnpm run ci
```

All commands passed. Full frontend CI reported 90 test files and 294 tests passing.

## Notes

- No backend behavior changed.
- No samples, packet captures, or local reports should be staged or pushed.
- Next low-risk engineering candidates: split `StreamDecoderWorkbenchParts.tsx` into primitive controls versus payload pane, or continue reducing `SentinelContext.tsx` through internal hooks while preserving `useSentinel()` compatibility.

---

## Round 2 - Stream Decoder Parts Split

Author: Codex

Timestamp: 2026-05-09 15:10:29 +08:00

### Scope

Continue the stream decoder boundary cleanup by splitting the remaining mixed TSX parts file into focused UI primitives and payload rendering. Public imports from `StreamDecoderWorkbenchParts.tsx` remain compatible.

### Changes

- Replaced `StreamDecoderWorkbenchParts.tsx` with a compatibility export facade.
- Added `StreamDecoderControls.tsx` for decoder buttons, settings sections, labeled inputs/selects/toggles, and mode buttons.
- Added `StreamDecoderPayloadPane.tsx` for decoded payload display, warnings/signals tags, hex preview, copy, and export actions.
- Added size-budget entries for the new modules and capped the facade at 20 lines.

### Validation

```powershell
cd frontend; pnpm exec vitest run src/app/components/StreamDecoderToolbar.test.tsx src/app/components/StreamDecoderBatchPanel.test.tsx src/app/components/StreamDecoderWorkbenchUtils.test.ts scripts/check-size.test.mjs
cd frontend; pnpm run size:check
cd frontend; pnpm run typecheck
cd frontend; pnpm run ci
```

All commands passed. Full frontend CI reported 90 test files and 294 tests passing.

### Review

- This round keeps the compatibility layer thin and prevents `StreamDecoderWorkbenchParts.tsx` from regrowing mixed responsibilities.
- No samples, packet captures, or local reports should be staged or pushed.

---

## Round 3 - Runtime Settings Sidebar Boundary Split

Author: Codex

Timestamp: 2026-05-09 15:16:44 +08:00

### Scope

Continue frontend engineering cleanup by reducing `RuntimeSettingsSidebar.tsx` from a mixed state/rendering component into a small orchestration shell. No runtime settings behavior, form fields, labels, or backend calls changed.

### Changes

- Split header, refresh/save action bar, and footer notice chrome into `RuntimeSettingsShell.tsx`.
- Split capture, YARA, media, and speech dependency sections into `RuntimeSettingsSections.tsx`.
- Kept `RuntimeSettingsSidebar.tsx` responsible for state normalization, dirty detection, save/refresh actions, speech summary, and component composition.
- Tightened size budgets:
  - `RuntimeSettingsSidebar.tsx`: 350 -> 130 lines.
  - Added budgets for `RuntimeSettingsSections.tsx` and `RuntimeSettingsShell.tsx`.

### Validation

```powershell
cd frontend; pnpm run typecheck
cd frontend; pnpm run lint
cd frontend; pnpm run size:check
cd frontend; pnpm run format:check
cd frontend; pnpm exec vitest run src/app/components/RuntimeSettingsSidebarParts.test.tsx scripts/check-size.test.mjs
cd frontend; pnpm run ci
```

All commands passed. Full frontend CI reported 90 test files and 294 tests passing, then completed Vite production build.

### Review

- This split removes most JSX bulk from the runtime settings state owner while preserving `RuntimeSettingsSidebar` as the public component entry.
- The next good engineering target is another high-weight but already bounded component such as `CaptureMissionPanels.tsx`, `PacketVirtualTable.tsx`, or a remaining page-level orchestration file.
- No samples, packet captures, or local reports should be staged or pushed.

---

## Round 4 - Capture Mission Panels Split

Author: Codex

Timestamp: 2026-05-09 15:22:07 +08:00

### Scope

Continue frontend boundary cleanup by splitting the capture mission display panel collection into focused presentational modules. Public imports from `CaptureMissionPanels.tsx` remain compatible.

### Changes

- Replaced `CaptureMissionPanels.tsx` with a compatibility export facade.
- Added `CaptureMissionQuickFilters.tsx` for recommended filter chips.
- Added `CaptureMissionRecommendationPanels.tsx` for module recommendation cards and icons.
- Added `CaptureMissionThreatPanels.tsx` for priority hit list rendering and packet/stream actions.
- Added `CaptureMissionPayloadPanel.tsx` for selected packet context and MISC handoff.
- Tightened size budgets for the facade and added per-module budgets for the split files.

### Validation

```powershell
cd frontend; pnpm exec prettier --write src/app/components/CaptureMissionPanels.tsx src/app/components/CaptureMissionQuickFilters.tsx src/app/components/CaptureMissionRecommendationPanels.tsx src/app/components/CaptureMissionThreatPanels.tsx src/app/components/CaptureMissionPayloadPanel.tsx scripts/check-size.mjs
cd frontend; pnpm run size:check
cd frontend; pnpm run typecheck
cd frontend; pnpm run lint
cd frontend; pnpm run format:check
cd frontend; pnpm run ci
```

All commands passed. Full frontend CI reported 90 test files and 294 tests passing, then completed Vite production build.

### Review

- This round removes the last large mixed JSX block from `CaptureMissionPanels.tsx` while keeping `CaptureMissionControl.tsx` imports stable.
- Behavior, copy, props, and navigation callbacks were kept unchanged.
- No samples, packet captures, or local reports should be staged or pushed.

---

## Round 5 - Packet Virtual Table Parts Split

Author: Codex

Timestamp: 2026-05-09 15:28:22 +08:00

### Scope

Continue frontend component boundary cleanup by splitting the packet virtual table into orchestration plus focused presentational modules. `PacketVirtualTable.tsx` remains the public entry and behavior owner.

### Changes

- Kept `PacketVirtualTable.tsx` responsible for scroll state, viewport measurement, persisted column state, resize effects, context menu state, and load-more throttling.
- Added `PacketVirtualTableHeader.tsx` for column visibility controls, header rendering, and resize handles.
- Added `PacketVirtualTableRows.tsx` for row color classes, virtual row positioning, and cell rendering.
- Added `PacketVirtualTableMenu.tsx` for viewport-safe context menu rendering and follow-stream actions.
- Tightened packet table size budgets and added budgets for the split modules.

### Validation

```powershell
cd frontend; pnpm run size:check
cd frontend; pnpm run lint
cd frontend; pnpm exec vitest run src/app/components/PacketVirtualTable.test.tsx scripts/check-size.test.mjs
cd frontend; pnpm run typecheck
cd frontend; pnpm run format:check
cd frontend; pnpm run ci
```

All commands passed. Full frontend CI reported 90 test files and 294 tests passing, then completed Vite production build.

### Review

- This round reduces the packet table file from a mixed rendering/state component into a smaller table controller with reusable child modules.
- Public props, row selection behavior, column persistence, context menu role, and portal behavior were kept unchanged.
- No samples, packet captures, or local reports should be staged or pushed.

---

## Round 6 - Stream Decoder Candidate Card Split

Author: Codex

Timestamp: 2026-05-09 15:33:12 +08:00

### Scope

Continue frontend decoder workbench cleanup by moving candidate card rendering out of `StreamDecoderCandidatePanel.tsx`. The candidate panel remains the public component entry and owns inspection/apply-mode orchestration.

### Changes

- Added `StreamDecoderCandidateCard.tsx` for candidate badges, previews, decoder hint actions, and fingerprint tags.
- Kept `StreamDecoderCandidatePanel.tsx` focused on inspection summary, coverage strategy, loading/error states, and candidate grid composition.
- Preserved suggested decoder behavior through a shared `runSuggestedDecoder` helper exported by the card module.
- Tightened size budgets for the panel and added a budget for the card module.

### Validation

```powershell
cd frontend; pnpm exec prettier --write src/app/components/StreamDecoderCandidatePanel.tsx src/app/components/StreamDecoderCandidateCard.tsx scripts/check-size.mjs
cd frontend; pnpm run size:check
cd frontend; pnpm run typecheck
cd frontend; pnpm run lint
cd frontend; pnpm exec vitest run src/app/components/StreamDecoderToolbar.test.tsx src/app/components/StreamDecoderBatchPanel.test.tsx scripts/check-size.test.mjs
cd frontend; pnpm run format:check
cd frontend; pnpm run ci
```

All commands passed. Full frontend CI reported 90 test files and 294 tests passing, then completed Vite production build.

### Review

- This round removes another dense JSX block from the decoder workbench path without changing payload inspection, candidate selection, or decode actions.
- `StreamDecoderCandidatePanel.tsx` is now small enough to remain an orchestration component; the next useful target is either `StreamDecoderWorkbench.tsx` state flow or another page-level feature split.
- No samples, packet captures, or local reports should be staged or pushed.

---

## Round 7 - Stream Decoder Settings Sections Split

Author: Codex

Timestamp: 2026-05-09 15:37:48 +08:00

### Scope

Continue frontend decoder cleanup by moving Behinder, AntSword, and Godzilla settings form sections out of `StreamDecoderSettingsPanel.tsx`. The panel remains the public entry and only dispatches the active settings section.

### Changes

- Added `StreamDecoderSettingsSections.tsx` for webshell-specific decoder settings forms and local numeric clamping.
- Kept `StreamDecoderSettingsPanel.tsx` as a compact section selector for the active decoder settings kind.
- Preserved field labels, values, update callbacks, conditional Behinder CBC IV rendering, and close behavior.
- Tightened size budgets for the settings panel and added a budget for the extracted settings sections.

### Validation

```powershell
cd frontend; pnpm exec prettier --write src/app/components/StreamDecoderSettingsPanel.tsx src/app/components/StreamDecoderSettingsSections.tsx scripts/check-size.mjs
cd frontend; pnpm run size:check
cd frontend; pnpm run typecheck
cd frontend; pnpm run lint
cd frontend; pnpm exec vitest run src/app/components/StreamDecoderToolbar.test.tsx src/app/components/StreamDecoderBatchPanel.test.tsx scripts/check-size.test.mjs
cd frontend; pnpm run format:check
cd frontend; pnpm run ci
```

All commands passed. Full frontend CI reported 90 test files and 294 tests passing, then completed Vite production build.

### Review

- Behavior and public imports remain unchanged; the refactor only moves JSX and field update logic behind section components.
- The decoder settings panel now stays well under its size budget and is easier to audit for active-section routing.
- No samples, packet captures, or local reports should be staged or pushed.

---

## Round 8 - Stream Decoder Workbench Render Split

Author: Codex

Timestamp: 2026-05-09 15:43:59 +08:00

### Scope

Continue decoder workbench engineering by moving pure render composition out of `StreamDecoderWorkbench.tsx` while keeping decode orchestration, abort handling, candidate selection, and batch state in the existing public component.

### Changes

- Added `StreamDecoderPayloadGrid.tsx` for the raw/candidate payload pane and decode result pane composition.
- Added `StreamDecoderWorkbenchHeader.tsx` for the workbench title and toolbar wiring.
- Reduced `StreamDecoderWorkbench.tsx` from 396 lines to 370 lines without changing the exported component or decode flow.
- Tightened the workbench size budget from 405 lines to 375 lines and added budgets for the new render-only modules.

### Validation

```powershell
cd frontend; pnpm exec prettier --write src/app/components/StreamDecoderWorkbench.tsx src/app/components/StreamDecoderPayloadGrid.tsx src/app/components/StreamDecoderWorkbenchHeader.tsx scripts/check-size.mjs
cd frontend; pnpm run size:check
cd frontend; pnpm run typecheck
cd frontend; pnpm run lint
cd frontend; pnpm exec vitest run src/app/components/StreamDecoderToolbar.test.tsx src/app/components/StreamDecoderBatchPanel.test.tsx scripts/check-size.test.mjs
cd frontend; pnpm run format:check
cd frontend; pnpm run ci
```

All commands passed. Full frontend CI reported 90 test files and 294 tests passing, then completed Vite production build.

### Review

- The public `StreamDecoderWorkbench` API remains unchanged.
- Decode side effects remain centralized in the original workbench component; extracted modules are render-only and easier to review.
- No samples, packet captures, or local reports should be staged or pushed.

---

## Round 9 - Analysis Data Table Split

Author: Codex

Timestamp: 2026-05-09 15:53:24 +08:00

### Scope

Continue shared analysis UI engineering by moving the generic table renderer out of `AnalysisPrimitives.tsx` while preserving existing imports used by Evidence, C2, Industrial, USB, Vehicle, and related feature panels.

### Changes

- Added `AnalysisDataTable.tsx` for `AnalysisDataTable` and `AnalysisTableColumn`.
- Kept the compatibility export from `AnalysisPrimitives.tsx`, so existing call sites do not need churn.
- Reduced `AnalysisPrimitives.tsx` to cards, badges, empty states, callouts, charts, and lists.
- Added explicit size budgets for `AnalysisPrimitives.tsx` and the new table module.

### Validation

```powershell
cd frontend; pnpm exec prettier --write src/app/components/analysis/AnalysisPrimitives.tsx src/app/components/analysis/AnalysisDataTable.tsx scripts/check-size.mjs
cd frontend; pnpm run size:check
cd frontend; pnpm run typecheck
cd frontend; pnpm run lint
cd frontend; pnpm exec vitest run src/app/pages/EvidencePanel.test.tsx src/app/pages/C2Analysis.test.tsx src/app/pages/IndustrialAnalysis.test.tsx src/app/pages/UsbAnalysis.test.tsx scripts/check-size.test.mjs
cd frontend; pnpm run format:check
cd frontend; pnpm exec vitest run src/app/pages/MiscTools.sessions.test.tsx src/app/pages/MiscTools.test.tsx
cd frontend; pnpm run ci
```

All commands passed. A first full CI attempt hit two MISC timing failures; the affected MISC tests passed on direct rerun, and the final full frontend CI passed with 90 test files and 294 tests before Vite production build completed.

### Review

- Generic table rendering is now isolated from primitive analysis cards and chart helpers.
- Public imports remain stable through the re-export layer.
- No samples, packet captures, or local reports should be staged or pushed.

---

## Round 10 - VShell Decrypt Display Rules Split

Author: Codex

Timestamp: 2026-05-09 16:01:00 +08:00

### Scope

Continue C2 frontend engineering by moving VShell-specific decrypt preview cleanup and low-information record decisions out of the generic C2 decrypt display mapper. This round is a pure boundary split and keeps the existing display behavior unchanged.

### Changes

- Added `vshellDecryptDisplayRules.ts` for VShell preview decoding, ANSI/VT100 cleanup, timestamp-only hiding, best-effort hex text extraction, and short low-information frame checks.
- Kept `c2DecryptDisplayMapper.ts` focused on result-level normalization, hidden-record counting, and user-facing notes.
- Preserved the public `isLikelyVShellLowInfoControlRecord` export path through the mapper layer, so existing tests and call sites remain compatible.
- Added size budgets for both the C2 display mapper and the new VShell display rules module.

### Validation

```powershell
cd frontend; pnpm exec prettier --write scripts/check-size.mjs src/app/integrations/mappers/c2DecryptDisplayMapper.ts src/app/integrations/mappers/vshellDecryptDisplayRules.ts
cd frontend; pnpm run size:check
cd frontend; pnpm run typecheck
cd frontend; pnpm run lint
cd frontend; pnpm exec vitest run src/app/integrations/wailsBridge.test.ts scripts/check-size.test.mjs
cd frontend; pnpm run format:check
cd frontend; pnpm run ci
```

All commands passed. Full frontend CI passed with package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 90 Vitest files / 294 tests, and Vite production build.

### Review

- VShell-specific display noise rules are now isolated from the generic C2 result mapper.
- CS decrypt display behavior remains outside the VShell-only normalization path.
- No samples, packet captures, or local reports should be staged or pushed.

---

## Round 11 - Packet Byte Layout Split

Author: Codex

Timestamp: 2026-05-09 16:06:01 +08:00

### Scope

Continue core frontend engineering by moving pure packet byte layout and hex dump helpers out of `core/engine.ts`. This round keeps protocol tree rendering behavior and existing imports stable.

### Changes

- Added `packetByteLayout.ts` for `buildHexDump`, payload byte parsing, and packet byte range calculation.
- Updated `engine.ts` to consume the new pure helpers while preserving the existing `buildHexDump` re-export path.
- Reduced `engine.ts` to protocol tree construction and display formatting responsibilities.
- Added size budgets for the slimmer `engine.ts` and the new packet byte layout module.

### Validation

```powershell
cd frontend; pnpm exec prettier --write scripts/check-size.mjs src/app/core/engine.ts src/app/core/packetByteLayout.ts
cd frontend; pnpm run size:check
cd frontend; pnpm exec vitest run src/app/core/engine.test.ts scripts/check-size.test.mjs
cd frontend; pnpm run typecheck
cd frontend; pnpm run lint
cd frontend; pnpm run format:check
cd frontend; pnpm run ci
```

All commands passed. Full frontend CI passed with package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 90 Vitest files / 294 tests, and Vite production build.

### Review

- Packet byte layout is now a pure helper boundary instead of being coupled to protocol tree rendering.
- Protocol tree behavior is unchanged, and callers importing `buildHexDump` from `core/engine` remain compatible.
- No samples, packet captures, or local reports should be staged or pushed.

---

## Round 12 - USB Overview Panel Split

Author: Codex

Timestamp: 2026-05-09 16:10:02 +08:00

### Scope

Continue USB page engineering by moving the top-level summary cards, charts, notes, and primary domain navigation out of `UsbAnalysis.tsx` into a feature component. This round keeps USB tab state and analysis data flow unchanged.

### Changes

- Added `UsbOverviewPanel.tsx` for USB summary cards, protocol/transfer charts, analysis notes, and HID / Mass Storage / Other primary navigation.
- Exported `UsbPrimaryTab` and `USB_PROTOCOL_TAGS` from the new overview module so the page keeps a single source for tab and hero metadata.
- Reduced `UsbAnalysis.tsx` to data orchestration plus HID / Mass Storage / Other domain composition.
- Tightened the `UsbAnalysis.tsx` size budget and added a budget for the new overview component.

### Validation

```powershell
cd frontend; pnpm exec prettier --write scripts/check-size.mjs src/app/pages/UsbAnalysis.tsx src/app/features/usb/UsbOverviewPanel.tsx
cd frontend; pnpm run size:check
cd frontend; pnpm exec vitest run src/app/pages/UsbAnalysis.test.tsx scripts/check-size.test.mjs
cd frontend; pnpm run ci
```

All commands passed. Full frontend CI passed with package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 90 Vitest files / 294 tests, and Vite production build.

### Review

- USB overview rendering is now in the USB feature boundary instead of the page file.
- The page still owns state transitions and domain panel wiring, so behavior risk is low.
- No samples, packet captures, or local reports should be staged or pushed.

---

## Round 13 - Vehicle Overview Panel Split

Author: Codex

Timestamp: 2026-05-09 16:13:48 +08:00

### Scope

Continue vehicle page engineering by moving top-level vehicle overview rendering out of `VehicleAnalysis.tsx` into a feature component. This round keeps DBC import/removal, UDS filtering, detailed evidence tables, and analysis request flow unchanged.

### Changes

- Added `VehicleOverviewPanel.tsx` for vehicle summary cards, protocol distribution, conversation/bus highlights, and analysis guidance.
- Moved `VEHICLE_PROTOCOL_TAGS` into the vehicle overview feature module for reuse by the page.
- Reduced `VehicleAnalysis.tsx` to state orchestration and detailed vehicle panels.
- Tightened the `VehicleAnalysis.tsx` size budget and added a budget for the new overview component.

### Validation

```powershell
cd frontend; pnpm exec prettier --write scripts/check-size.mjs src/app/pages/VehicleAnalysis.tsx src/app/features/vehicle/VehicleOverviewPanel.tsx
cd frontend; pnpm run size:check
cd frontend; pnpm exec vitest run src/app/pages/VehicleAnalysis.test.ts scripts/check-size.test.mjs
cd frontend; pnpm run typecheck
cd frontend; pnpm run lint
cd frontend; pnpm run ci
```

All commands passed. Full frontend CI passed with package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 90 Vitest files / 294 tests, and Vite production build.

### Review

- Vehicle overview display is now separated from page-level orchestration.
- DBC / UDS / detailed record behavior is unchanged; this is a pure component boundary split.
- No samples, packet captures, or local reports should be staged or pushed.
## Round 14 - Raw TCP/UDP Stream Shared Helpers

Time: 2026-05-09 16:24:25 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by removing duplicated raw TCP/UDP stream formatting, search, export, and dialog metadata logic from the page components.
- Kept TCP/UDP stream page behavior and public routes unchanged.

### Changes

- Added `frontend/src/app/pages/RawStreamUtils.ts` as the shared pure helper module for raw stream pages.
- Added `frontend/src/app/pages/RawStreamUtils.test.ts` covering metadata formatting, hex detection, payload rendering, truncation, visible chunk mapping, search counts, export text, chips, and dialog metadata.
- Updated `TcpStream.tsx` and `UdpStream.tsx` to consume shared helpers for:
  - visible chunk keys and stream indexes;
  - search filtering and match counting;
  - direction labels;
  - export file content;
  - current chunk chips;
  - payload detail dialog metadata.
- Updated size budgets:
  - `TcpStream.tsx`: 350 lines under 370 budget.
  - `UdpStream.tsx`: 338 lines under 355 budget.
  - `RawStreamUtils.ts`: 130 lines under the new 140-line pure-helper budget.

### Validation

- `pnpm run size:check` - passed.
- `pnpm exec vitest run src/app/pages/RawStreamUtils.test.ts src/app/components/stream/StreamNavigationControls.test.tsx src/app/components/stream/StreamPayloadPanels.test.tsx scripts/check-size.test.mjs` - passed, 13 tests.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run format:check` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 91 Vitest files / 299 tests, and Vite build.

### Review

- This round is a behavior-preserving refactor: state ownership, route handling, lazy stream loading, visual tones, and MISC handoff remain inside the existing pages.
- The shared helper boundary is intentionally pure so future TCP/UDP page changes can be tested without rendering the full stream pages.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 15 - APT Attribution Panel Split

Time: 2026-05-09 16:32:11 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by moving APT attribution explanation, notes, missing-evidence reasoning, and evidence timeline rendering out of `AptAnalysis.tsx`.
- Kept APT analysis loading, actor selection, evidence tab filtering, and table behavior unchanged.

### Changes

- Added `frontend/src/app/features/apt/APTAttributionPanel.tsx` for attribution explanation, notes display, score-factor columns, and missing-evidence helpers.
- Added `frontend/src/app/features/apt/APTEvidenceTimeline.tsx` for timeline ordering and compact evidence rendering.
- Reduced `AptAnalysis.tsx` from 384 lines to 211 lines so it now focuses on page state orchestration and layout.
- Tightened APT size budgets:
  - `AptAnalysis.tsx`: 211 lines under 230 budget.
  - `APTAttributionPanel.tsx`: 229 lines under 250 budget.
  - `APTEvidenceTimeline.tsx`: 69 lines under 80 budget.

### Validation

- `pnpm run size:check` - passed.
- `pnpm exec vitest run src/app/pages/AptAnalysis.test.tsx scripts/check-size.test.mjs` - passed, 4 tests.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 91 Vitest files / 299 tests, and Vite build.

### Review

- This round is behavior-preserving: active actor state, evidence tab filtering, analysis cache key export, and evidence table wiring remain unchanged.
- APT attribution UI is now testable and bounded as feature-level presentation instead of page-local helper code.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 16 - Media Transcription Workflow Hook

Time: 2026-05-09 16:40:17 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by moving media playback, speech transcription, batch polling, dependency dialog, copy/export, and artifact download side effects out of `MediaAnalysis.tsx`.
- Kept media analysis loading, media session table display, batch transcription behavior, playback dialog wiring, and dependency warning behavior unchanged.

### Changes

- Added `frontend/src/app/features/media/useMediaTranscriptionWorkflow.ts` as the feature-level workflow hook for:
  - speech dependency checks;
  - single-session transcription;
  - batch transcription start/cancel/polling;
  - transcription progress timing;
  - playback URL lifecycle and ffmpeg dialog routing;
  - copy/export/download effects.
- Added `frontend/src/app/features/media/useMediaTranscriptionWorkflow.test.ts` for pure helper coverage:
  - batch transcription merge behavior;
  - empty batch text preservation;
  - dependency-error classification.
- Reduced `MediaAnalysis.tsx` from 365 lines to 126 lines so it now composes analysis state, workflow state, and display panels.
- Tightened media size budgets:
  - `MediaAnalysis.tsx`: 126 lines under 145 budget.
  - `useMediaTranscriptionWorkflow.ts`: 295 lines under 310 budget.
  - `useMediaTranscriptionWorkflow.test.ts`: under the new 120-line test budget.

### Validation

- `pnpm run size:check` - passed.
- `pnpm exec vitest run src/app/features/media/useMediaTranscriptionWorkflow.test.ts src/app/features/media/MediaSessionTableUtils.test.ts src/app/features/media/MediaSessionCells.test.tsx scripts/check-size.test.mjs` - passed, 13 tests.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 92 Vitest files / 302 tests, and Vite build.

### Review

- This round preserves UI shape while reducing page ownership of imperative workflow effects.
- Media feature behavior is now more testable: pure merge/classification rules are covered outside the page render path.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 17 - Update Center Feature Split

Time: 2026-05-09 16:54:31 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by moving Update Center display panels and release markdown rendering out of `UpdateCenter.tsx`.
- Kept update loading, update status refresh, installer progress, install action orchestration, and page routing behavior unchanged.

### Changes

- Added `frontend/src/app/features/update/UpdateCenterPanels.tsx` for the update status, installation actions, release metadata, changelog, and guide sections.
- Added `frontend/src/app/features/update/UpdateReleaseMarkdown.tsx` for release note and installation guide markdown rendering.
- Added `frontend/src/app/features/update/updateCenterUtils.ts` and focused tests for release time formatting.
- Reduced `UpdateCenter.tsx` from 333 lines to 101 lines so the page now focuses on state orchestration and backend calls.
- Tightened Update Center size budgets:
  - `UpdateCenter.tsx`: 101 lines under 130 budget.
  - `UpdateCenterPanels.tsx`: 240 lines under 260 budget.
  - `UpdateReleaseMarkdown.tsx`: 71 lines under 85 budget.
  - `updateCenterUtils.ts`: 7 lines under 15 budget.
  - `updateCenterUtils.test.ts`: 13 lines under 30 budget.

### Validation

- `pnpm run size:check` - passed.
- `pnpm exec vitest run src/app/features/update/updateCenterUtils.test.ts scripts/check-size.test.mjs` - passed, 4 tests.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 93 Vitest files / 304 tests, and Vite build.

### Review

- This round is behavior-preserving: update status fetch, install button state, installer progress display, and release detail rendering remain wired through the original page flow.
- Update Center now follows the same page-thin / feature-panel pattern used by the recent media and APT rounds.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 18 - Object Export Feature Split

Time: 2026-05-09 17:03:32 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by moving Object Export classification, grouping, toolbar, object grid, and export footer display out of `ObjectExport.tsx`.
- Kept object loading fallback, search/type filtering, selection state, group expansion, and ZIP download behavior unchanged.

### Changes

- Added `frontend/src/app/features/object/objectExportRules.ts` for pure object classification, magic-label mapping, filename/type filtering, and grouped sorting.
- Added `frontend/src/app/features/object/ObjectExportPanels.tsx` for the page hero, toolbar, group chips, grouped object grid, cards, and export footer.
- Added `frontend/src/app/features/object/objectExportRules.test.ts` for classification, filtering, and grouping coverage.
- Reduced `ObjectExport.tsx` from 277 lines to 75 lines so the page now focuses on state orchestration and bridge download calls.
- Added Object Export size budgets:
  - `ObjectExport.tsx`: 75 lines under 90 budget.
  - `ObjectExportPanels.tsx`: 239 lines under 250 budget.
  - `objectExportRules.ts`: 126 lines under 135 budget.
  - `objectExportRules.test.ts`: 50 lines under 55 budget.

### Validation

- `pnpm exec vitest run src/app/features/object/objectExportRules.test.ts scripts/check-size.test.mjs` - passed, 5 tests.
- `pnpm run size:check` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 94 Vitest files / 307 tests, and Vite build.

### Review

- This round is behavior-preserving: no backend API path, bridge method, object data shape, or route behavior changed.
- Object Export now follows the page-thin / feature-panel / pure-rules pattern used by C2, media, APT, update, USB, vehicle, and industrial rounds.
- No samples, generated PCAPs, or local report directories are intended for commit.
