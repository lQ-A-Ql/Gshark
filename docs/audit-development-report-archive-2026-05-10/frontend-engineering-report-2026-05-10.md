# Frontend Engineering Report - 2026-05-10

## Round 19 - Evidence Panel Feature Split

Time: 2026-05-10 19:19:44 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by moving Evidence Panel presentation sections and pure evidence rules out of `EvidencePanel.tsx`.
- Kept evidence loading, module filtering, severity filtering, search behavior, JSON export, CSV export, packet action wiring, and caveat display behavior unchanged.

### Changes

- Added `frontend/src/app/features/evidence/EvidencePanelSections.tsx` for the evidence hero, severity summary, toolbar, status message, evidence table, tags, and caveats.
- Added `frontend/src/app/features/evidence/evidencePanelRules.ts` for filtering, sorting, severity counts, CSV formatting, caveat deduplication, labels, tones, and confidence color rules.
- Added `frontend/src/app/features/evidence/evidencePanelRules.test.ts` for filtering, sorting, severity counting, CSV escaping, caveat dedupe, and module label coverage.
- Reduced `EvidencePanel.tsx` from 338 lines to 84 lines so the page now focuses on backend data loading, filter state, and export actions.
- Added Evidence Panel size budgets:
  - `EvidencePanel.tsx`: 84 lines under 85 budget.
  - `EvidencePanelSections.tsx`: 316 lines under 330 budget.
  - `evidencePanelRules.ts`: 124 lines under 130 budget.
  - `evidencePanelRules.test.ts`: 71 lines under 80 budget.

### Validation

- `pnpm exec vitest run src/app/pages/EvidencePanel.test.tsx src/app/features/evidence/evidencePanelRules.test.ts scripts/check-size.test.mjs` - passed, 7 tests.
- `pnpm run size:check` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- First `pnpm run ci` hit unrelated MISC test-run timing failures under full-suite concurrency; focused MISC rerun passed.
- Final `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 95 Vitest files / 310 tests, and Vite build.

### Review

- This round is behavior-preserving: no backend API path, bridge method, evidence schema, route, or export filename changed.
- Evidence Panel now follows the page-thin / feature-section / pure-rules pattern used by Object Export, Update Center, Media, APT, USB, Vehicle, Industrial, and C2-related feature areas.
- MISC tests remain relatively slow under full-suite concurrency; they passed after rerun and in the final CI pass, but remain a candidate for future stability work.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 20 - HTTP Stream Page Split

Time: 2026-05-10 19:26:12 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by moving HTTP stream chunk helpers and presentation sections out of `HttpStream.tsx`.
- Kept route-driven stream activation, selected-packet fallback, stream navigation, search cursor behavior, render-limit pagination, export text behavior, payload dialog behavior, and MISC handoff unchanged.

### Changes

- Added `frontend/src/app/pages/HttpStreamChunks.ts` for pure chunk normalization, fallback request/response chunk building, search filtering, match counting, and export text formatting.
- Added `frontend/src/app/pages/HttpStreamSections.tsx` for HTTP stream title bar, toolbar, payload grid, selected chunk panel, and payload detail dialog.
- Added `frontend/src/app/pages/HttpStreamChunks.test.ts` for fallback chunk creation, search filtering, match counting, and export formatting coverage.
- Reduced `HttpStream.tsx` from 367 lines to 154 lines so the page now focuses on route/state orchestration and stream switching actions.
- Added HTTP stream size budgets:
  - `HttpStream.tsx`: 154 lines under 180 budget.
  - `HttpStreamChunks.ts`: 78 lines under 80 budget.
  - `HttpStreamSections.tsx`: 365 lines under 380 budget.
  - `HttpStreamChunks.test.ts`: 50 lines under 60 budget.

### Validation

- `pnpm exec vitest run src/app/pages/HttpStreamUtils.test.ts src/app/pages/HttpStreamChunks.test.ts scripts/check-size.test.mjs` - passed, 11 tests.
- `pnpm run size:check` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 96 Vitest files / 313 tests, and Vite build.

### Review

- This round is behavior-preserving: no Sentinel stream state, backend bridge, route, export filename, or payload rendering semantics changed.
- HTTP stream now has a small page controller and isolated pure chunk helpers; `HttpStreamSections.tsx` remains a possible future split target if dialog/grid rendering grows further.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 21 - Raw TCP/UDP Stream Shared Sections

Time: 2026-05-10 19:31:49 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by extracting shared TCP/UDP raw stream presentation into a reusable section module.
- Kept TCP and UDP stream state ownership, route-driven stream activation, selected-packet fallback, pagination/loading-more behavior, search cursor behavior, export text behavior, payload dialog behavior, and MISC handoff unchanged.

### Changes

- Added `frontend/src/app/pages/RawStreamSections.tsx` for shared raw stream title bar, payload grid, selected payload panel, control bar, dialog, TCP/UDP tone constants, and MISC action.
- Reduced `TcpStream.tsx` from 350 lines to 256 lines.
- Reduced `UdpStream.tsx` from 338 lines to 249 lines.
- Updated size budgets:
  - `TcpStream.tsx`: 256 lines under 280 budget.
  - `UdpStream.tsx`: 249 lines under 270 budget.
  - `RawStreamSections.tsx`: 422 lines under 430 budget.

### Validation

- `pnpm exec vitest run src/app/pages/RawStreamUtils.test.ts scripts/check-size.test.mjs` - passed, 7 tests.
- `pnpm run size:check` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 96 Vitest files / 313 tests, and Vite build.

### Review

- This round is behavior-preserving: TCP and UDP still own their own stream source, pagination cursor, load error, search, and selected chunk state.
- Raw stream presentation duplication is now centralized; `RawStreamSections.tsx` is intentionally larger because it replaces two duplicated page-level render trees and carries protocol-specific tone variants.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 22 - C2 Decrypt Workbench Split

Time: 2026-05-10 19:41:44 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by moving C2 decrypt form state and C2-specific display fragments out of `C2Analysis.tsx`.
- Kept CS/VShell tab switching, decrypt request shape, raw-key guidance text, VShell salt/vkey validation, CS key modes, transform modes, result table display, and candidate/aggregate rendering behavior unchanged.

### Changes

- Added `frontend/src/app/features/c2/C2DecryptWorkbench.tsx` for decrypt state, request construction, error handling, and result-panel composition.
- Added `frontend/src/app/features/c2/C2DecryptFormControls.tsx` for VShell fields, CS key material controls, raw-key guidance, RSA PEM textarea, select wrappers, and key-mode hints.
- Added `frontend/src/app/features/c2/C2BeaconPatternList.tsx` for Beacon / Heartbeat pattern rendering.
- Reduced `C2Analysis.tsx` from 384 lines at round start to 235 lines; the page now focuses on analysis loading, family tabs, and feature-section composition.
- Updated size budgets:
  - `C2Analysis.tsx`: 235 lines under 250 budget.
  - `C2DecryptWorkbench.tsx`: 155 lines under 175 budget.
  - `C2DecryptFormControls.tsx`: 233 lines under 250 budget.
  - `C2BeaconPatternList.tsx`: 37 lines under 45 budget.

### Validation

- `pnpm exec vitest run src/app/pages/C2Analysis.test.tsx src/app/pages/C2Analysis.decrypt.test.tsx src/app/pages/C2Analysis.vshell.test.tsx src/app/pages/C2Analysis.candidates.test.tsx scripts/check-size.test.mjs` - passed, 15 tests.
- `pnpm run size:check` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 96 Vitest files / 313 tests, and Vite build.

### Review

- This round is behavior-preserving: no backend API, bridge method, C2 decrypt payload shape, labels used by existing tests, or result filtering semantics changed.
- C2 decrypt UI now follows the same page-thin / feature-workbench / form-controls pattern used in earlier engineering rounds.
- `C2Analysis.tsx` is no longer a 300+ line page, but C2 aggregate display remains a future candidate for smaller per-section composition if the C2 page grows again.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 23 - Raw Stream Control and Dialog Split

Time: 2026-05-10 19:47:00 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by splitting raw TCP/UDP shared stream controls and expanded payload dialog out of `RawStreamSections.tsx`.
- Kept TCP/UDP page imports compatible through `RawStreamSections.tsx`, so route state, stream switching, pagination, search, export, and MISC handoff behavior remained unchanged.

### Changes

- Added `frontend/src/app/pages/RawStreamControlBar.tsx` for stream metrics, view mode toggle, stream navigation, search controls, loaded counter, and export button.
- Added `frontend/src/app/pages/RawStreamDialog.tsx` for expanded payload display, dialog metadata, filename generation, highlight behavior, and MISC workbench handoff.
- Reduced `RawStreamSections.tsx` from 422 lines at the previous round to 268 lines.
- Updated size budgets:
  - `RawStreamSections.tsx`: 268 lines under 285 budget.
  - `RawStreamControlBar.tsx`: 118 lines under 130 budget.
  - `RawStreamDialog.tsx`: 56 lines under 65 budget.

### Validation

- `pnpm exec vitest run src/app/pages/RawStreamUtils.test.ts scripts/check-size.test.mjs` - passed, 7 tests.
- `pnpm run size:check` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 96 Vitest files / 313 tests, and Vite build.

### Review

- This round is behavior-preserving: no TCP/UDP state ownership, bridge method, payload rendering helper, download filename pattern, or MISC handoff semantics changed.
- Raw TCP/UDP presentation now has clearer ownership: layout/grid in `RawStreamSections.tsx`, controls in `RawStreamControlBar.tsx`, dialog in `RawStreamDialog.tsx`, pure helpers in `RawStreamUtils.ts`.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 24 - USB HID State and Panel Split

Time: 2026-05-10 20:03:11 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by moving USB HID keyboard/mouse state, filtering, stats, replay cursor, and child rendering out of `UsbAnalysis.tsx`.
- Kept USB analysis loading, primary domain tab selection, Mass Storage filters, Other USB subpages, HID replay behavior, mouse visualization behavior, and existing table labels unchanged.

### Changes

- Added `frontend/src/app/features/usb/useUsbHidState.ts` for HID keyboard/mouse device selection, filtered event lists, replay cursor/play timer, keyboard text previews, keyboard stats, and mouse stats.
- Added `frontend/src/app/features/usb/UsbHidPanel.tsx` for HID secondary tabs, keyboard replay/text/table/notes presentation, and mouse trajectory/heatmap/table presentation.
- Reduced `UsbAnalysis.tsx` from 426 lines to 187 lines; it now composes analysis loading plus the three primary USB domains.
- Updated size budgets:
  - `UsbAnalysis.tsx`: 187 lines under 205 budget.
  - `UsbHidPanel.tsx`: 119 lines under 135 budget.
  - `useUsbHidState.ts`: 175 lines under 190 budget.
  - `UsbHidPanels.tsx`: existing primitive budget added at 289 lines under 305 budget.

### Validation

- `pnpm exec vitest run src/app/pages/UsbAnalysis.test.tsx src/app/features/usb/UsbTablesSplit.test.tsx scripts/check-size.test.mjs` - passed, 9 tests.
- `pnpm run size:check` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 96 Vitest files / 313 tests, and Vite build.

### Review

- This round is behavior-preserving: no backend bridge call, USB data shape, visible labels, Mass Storage filter semantics, or Other USB table behavior changed.
- USB page is now aligned with the feature-panel pattern used by Evidence, Object Export, Update Center, Media, C2, and raw stream pages.
- Remaining USB-specific future work is optional: Mass Storage page-side filter state could move to a domain hook later, but the current page is already under a strict orchestration budget.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 25 - Main Layout Chrome Split

Time: 2026-05-10 20:09:35 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by moving global header menus, sidebar navigation, settings chrome, and footer status out of `MainLayout.tsx`.
- Kept routing, Sentinel state ownership, packet export actions, copy selected packet action, stream-follow navigation, HTTP filter shortcut, TLS dialog state, settings sidebar state, drag guard, and route background transition behavior unchanged.

### Changes

- Added `frontend/src/app/layouts/MainLayoutChrome.tsx` for:
  - top menu groups and menu items,
  - header status/action pills,
  - left icon sidebar navigation,
  - settings sidebar overlay/chrome,
  - bottom engine/capture/TLS status footer.
- Reduced `MainLayout.tsx` from 422 lines to 227 lines; it now owns route shell state, Sentinel-derived actions, keyboard shortcuts, and background transitions.
- Exported `PageTheme` from `mainLayoutConfig.ts` so chrome components can type the active route theme without duplicating theme shape.
- Updated size budgets:
  - `MainLayout.tsx`: 227 lines under 245 budget.
  - `MainLayoutChrome.tsx`: 315 lines under 330 budget.

### Validation

- `pnpm exec vitest run src/app/layouts/MainLayout.test.ts scripts/check-size.test.mjs` - passed, 6 tests.
- `pnpm run size:check` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 96 Vitest files / 313 tests, and Vite build.

### Review

- This round is behavior-preserving: route paths, menu labels, keyboard shortcuts, capture/open/export handlers, and TLS/settings entry points remain the same.
- Main layout now has a clearer boundary: shell state and effects in `MainLayout.tsx`, chrome rendering in `MainLayoutChrome.tsx`, static route/theme data in `mainLayoutConfig.ts`.
- `MainLayoutChrome.tsx` is still a large presentation module, but it carries static menu/sidebar/footer rendering and has a strict budget to prevent further growth.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 26 - Vehicle Analysis Panels Split

Time: 2026-05-10 20:15:25 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by moving Vehicle page protocol summaries, security notes, and detail tables out of `VehicleAnalysis.tsx`.
- Kept Vehicle analysis loading, DBC profile import/remove flow, UDS transaction filtering, CAN/J1939/DoIP/UDS labels, table contents, and route behavior unchanged.

### Changes

- Added `frontend/src/app/features/vehicle/VehicleProtocolPanels.tsx` for CAN/J1939/DoIP/UDS summary cards, distribution charts, and security notes.
- Added `frontend/src/app/features/vehicle/VehicleDetailPanels.tsx` for CAN frame preview, CAN payload records, CAN ID data board, DBC decoded tables, DoIP messages, and UDS messages.
- Reduced `VehicleAnalysis.tsx` from 361 lines to 134 lines; it now owns page-level bridge state, DBC profile mutations, UDS filter state, and feature-section composition.
- Updated size budgets:
  - `VehicleAnalysis.tsx`: 134 lines under 160 budget.
  - `VehicleProtocolPanels.tsx`: 117 lines under 135 budget.
  - `VehicleDetailPanels.tsx`: 160 lines under 180 budget.

### Validation

- `pnpm run size:check` - passed.
- `pnpm exec vitest run src/app/pages/VehicleAnalysis.test.ts scripts/check-size.test.mjs` - passed, 4 tests.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 96 Vitest files / 313 tests, and Vite build.

### Review

- This round is behavior-preserving: no backend endpoint, bridge call, analysis data shape, DBC operation, or visible table semantics changed.
- Vehicle page now follows the same thin-page pattern as Evidence, Object Export, Update Center, Media, C2, USB, and Main Layout.
- Remaining Vehicle work is not urgent; if the domain grows, UDS transaction filter state can be moved into a small hook without touching the page again.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 27 - C2 Aggregate Table Split

Time: 2026-05-10 20:19:49 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by splitting CS DNS aggregate and VShell stream aggregate rendering out of the C2 aggregate compatibility barrel.
- Kept existing imports from `features/c2/C2AggregateTables`, C2 page tabs, DNS row expansion, VShell stream row expansion, evidence actions, and filter actions unchanged.

### Changes

- Added `frontend/src/app/features/c2/CSDNSAggregates.tsx` for DNS Beacon aggregate rows, DNS shape columns, packet evidence, and expansion panel wiring.
- Added `frontend/src/app/features/c2/VShellStreamAggregates.tsx` for VShell stream-level aggregate rows, short/long packet shape, heartbeat display, listener hints, and expansion panel wiring.
- Reduced `C2AggregateTables.tsx` from 316 lines to a 3-line compatibility export layer.
- Updated size budgets:
  - `C2AggregateTables.tsx`: 3 lines under 20 budget.
  - `CSDNSAggregates.tsx`: 166 lines under 185 budget.
  - `VShellStreamAggregates.tsx`: 167 lines under 185 budget.

### Validation

- `pnpm run size:check` - passed.
- `pnpm exec vitest run src/app/pages/C2Analysis.test.tsx src/app/pages/C2Analysis.vshell.test.tsx src/app/features/c2/CSHostURIAggregates.test.tsx scripts/check-size.test.mjs` - passed, 12 tests.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 96 Vitest files / 313 tests, and Vite build.

### Review

- This round is behavior-preserving: the public C2 aggregate exports remain stable and no backend bridge/API shape changed.
- C2 aggregate ownership is now clearer: Host/URI, DNS, and VShell stream aggregate tables live in separate files; shared details and table style constants remain shared.
- Remaining C2 size pressure is now mostly in `C2CandidateTable.tsx`; it can be split next without changing page behavior.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 28 - C2 Candidate Table Split

Time: 2026-05-10 20:24:05 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by separating C2 candidate table orchestration from expanded detail rendering, filter actions, and pure record rules.
- Kept C2 candidate table columns, row keys, expand/collapse behavior, packet/stream evidence actions, display filter generation, and typed preview content unchanged.

### Changes

- Added `frontend/src/app/features/c2/C2CandidateTableRules.ts` for candidate row keys, tag aggregation, tag compaction, preview record shaping, and preferred protocol selection.
- Added `frontend/src/app/features/c2/C2CandidateTableDetails.tsx` for expanded evidence context, tag chips, and typed record preview.
- Added `frontend/src/app/features/c2/C2CandidateActions.tsx` for DNS/TCP/HTTP display filter action routing.
- Reduced `C2CandidateTable.tsx` from 287 lines to 140 lines; it now owns only table state, columns, and composition.
- Updated size budgets:
  - `C2CandidateTable.tsx`: 140 lines under 160 budget.
  - `C2CandidateTableDetails.tsx`: 63 lines under 80 budget.
  - `C2CandidateTableRules.ts`: 67 lines under 85 budget.
  - `C2CandidateActions.tsx`: 29 lines under 45 budget.

### Validation

- `pnpm run size:check` - passed.
- `pnpm exec vitest run src/app/pages/C2Analysis.candidates.test.tsx scripts/check-size.test.mjs` - passed, 5 tests.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 96 Vitest files / 313 tests, and Vite build.

### Review

- This round is behavior-preserving: C2 page imports, table data shape, user-visible labels, expansion assertions, and filter-copy workflows remain stable.
- C2 feature modules now have clearer boundaries: aggregate tables, candidate table, candidate details, candidate actions, and pure candidate rules are separated.
- Remaining large C2 files are test files and decrypt result/workbench components, which are lower priority unless new C2 UI behavior is added.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 29 - HTTP Stream Section Split

Time: 2026-05-10 20:27:57 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by splitting HTTP stream presentation sections into title/toolbar, payload grid, and dialog modules.
- Kept `HttpStream.tsx` state orchestration, stream switching, search, rendering limits, chunk selection, export behavior, and MISC handoff unchanged.

### Changes

- Added `frontend/src/app/pages/HttpStreamTitleBar.tsx` for stream navigator, view-mode toggle, switch metrics, search toolbar, load metadata, and export button.
- Added `frontend/src/app/pages/HttpStreamPayloadGrid.tsx` for chunk cards, selected chunk preview, direction badges, truncation checks, and load-more button.
- Added `frontend/src/app/pages/HttpStreamDialog.tsx` for expanded payload dialog metadata and MISC workbench action.
- Reduced `HttpStreamSections.tsx` from 344 lines to a 3-line compatibility export layer.
- Updated size budgets:
  - `HttpStreamSections.tsx`: 3 lines under 20 budget.
  - `HttpStreamTitleBar.tsx`: 145 lines under 165 budget.
  - `HttpStreamPayloadGrid.tsx`: 148 lines under 170 budget.
  - `HttpStreamDialog.tsx`: 59 lines under 75 budget.

### Validation

- `pnpm run size:check` - passed.
- `pnpm exec vitest run src/app/pages/HttpStreamUtils.test.ts src/app/pages/HttpStreamChunks.test.ts scripts/check-size.test.mjs` - passed, 11 tests.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 96 Vitest files / 313 tests, and Vite build.

### Review

- This round is behavior-preserving: no stream state, URL routing, chunk parsing, HTTP rendering, or export semantics changed.
- HTTP stream page now mirrors the raw stream split pattern: state in the page, presentation sections in small sibling modules, barrel kept for compatibility.
- The next HTTP-specific target is optional; remaining pressure is mostly in tested pure utilities and shared stream components.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 30 - Threat Hunting Workbench Split

Time: 2026-05-10 20:34:15 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by splitting Threat Hunting category/progress summaries and workbench internals into smaller feature sections.
- Kept threat hunting runtime config loading/saving, rerun behavior, hit selection, packet定位, related stream navigation, labels, and data shape unchanged.

### Changes

- Added `frontend/src/app/features/hunting/ThreatHuntingSummaryPanels.tsx` for progress and category summary presentation.
- Added `frontend/src/app/features/hunting/ThreatHuntingWorkbenchSections.tsx` for runtime config form, hit table, and selected hit detail panel.
- Reduced `ThreatHuntingPanels.tsx` from 333 lines to about 107 lines; it now keeps exported types and workbench composition.
- Updated size budgets:
  - `ThreatHuntingPanels.tsx`: about 107 lines under 125 budget.
  - `ThreatHuntingSummaryPanels.tsx`: about 101 lines under 120 budget.
  - `ThreatHuntingWorkbenchSections.tsx`: about 262 lines under 285 budget.

### Validation

- `pnpm run size:check` - passed.
- `pnpm exec vitest run src/app/pages/AptAnalysis.test.tsx scripts/check-size.test.mjs` - passed, 4 tests.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 96 Vitest files / 313 tests, and Vite build.

### Review

- This round is behavior-preserving: no backend bridge/API call, hunting config shape, hit selection, or route navigation changed.
- Threat Hunting display ownership is now clearer: top-level panel exports/types, summary panels, and workbench sections are separated.
- Next engineering targets should remain low-risk presentation or pure-rule splits before attempting `SentinelContext.tsx`.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 31 - Stream Payload Panel Split

Time: 2026-05-10 20:46:05 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by splitting shared stream payload presentation into focused modules.
- Kept all public imports through `components/stream/StreamWorkbench`, highlight behavior, selected chunk display, chunk card selection/open behavior, dialog metadata filtering, copy, and export unchanged.

### Changes

- Added `frontend/src/app/components/stream/StreamPayloadHighlight.tsx` for payload text highlighting.
- Added `frontend/src/app/components/stream/StreamCurrentChunkPanel.tsx` for selected/current chunk display.
- Added `frontend/src/app/components/stream/StreamChunkCard.tsx` for stream chunk preview cards.
- Added `frontend/src/app/components/stream/StreamPayloadDialog.tsx` for full payload dialog, metadata, copy, and export actions.
- Reduced `StreamPayloadPanels.tsx` from 262 lines to a 4-line compatibility export layer.
- Updated size budgets:
  - `StreamPayloadPanels.tsx`: 4 lines under 20 budget.
  - `StreamPayloadHighlight.tsx`: 33 lines under 45 budget.
  - `StreamCurrentChunkPanel.tsx`: 80 lines under 95 budget.
  - `StreamChunkCard.tsx`: 63 lines under 80 budget.
  - `StreamPayloadDialog.tsx`: 93 lines under 110 budget.
- Stabilized `MiscTools.testFixtures.ts` by increasing shared module-content wait timeout from 10s to 15s; full concurrent Vitest runs repeatedly pushed the payload decoder workbench just past the old 10s bound while the same test passed in isolation.

### Validation

- `pnpm exec vitest run src/app/components/stream/StreamPayloadPanels.test.tsx src/app/pages/MiscTools.test.tsx scripts/check-size.test.mjs` - passed, 11 tests.
- `pnpm run size:check` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 96 Vitest files / 313 tests, and Vite build.

### Review

- This round is behavior-preserving for raw stream, HTTP stream, and shared stream workbench imports.
- The split removes a mixed-purpose shared file and gives each stream payload display unit its own size budget.
- The MISC test helper timeout change is test-only and reflects observed full-suite concurrency timing rather than a product behavior change.
- Next low-risk targets remain presentation-heavy modules such as `CaptureMissionControl.tsx` or media display panels.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 32 - Capture Mission Header Split

Time: 2026-05-10 20:51:52 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by separating Analysis Cockpit header/stat presentation from capture mission orchestration.
- Kept overview loading/cache behavior, recommendation routing, quick filters, suspicious hit packet/stream actions, selected packet payload shortcut, and MISC handoff unchanged.

### Changes

- Added `frontend/src/app/components/CaptureMissionOverviewHeader.tsx` for cockpit heading, protocol chips, action buttons, and metric cards.
- Reduced `CaptureMissionControl.tsx` from 262 lines to about 204 lines; it now focuses on overview bundle loading, memoized overview construction, and navigation callbacks.
- Updated size budgets:
  - `CaptureMissionControl.tsx`: about 222 script-counted lines under 230 budget.
  - `CaptureMissionOverviewHeader.tsx`: about 142 lines under 160 budget.

### Validation

- `pnpm exec vitest run scripts/check-size.test.mjs src/app/layouts/MainLayout.test.ts` - passed, 6 tests.
- `pnpm run size:check` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 96 Vitest files / 313 tests, and Vite build.

### Review

- This round is behavior-preserving: no Sentinel state contract, bridge call, route target, display filter action, or panel child contract changed.
- Analysis Cockpit now has a clearer boundary: `CaptureMissionControl` owns data and navigation, while `CaptureMissionOverviewHeader` owns header/stat rendering.
- The remaining sizeable modules are now higher-risk state or broad primitive files; next rounds should continue choosing tested presentation modules before touching `SentinelContext.tsx`.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 33 - Media Display Panel Split

Time: 2026-05-10 20:57:11 +08:00  
Author: Codex

### Scope

- Continued frontend engineering cleanup by splitting media display panels into progress, batch status, playback, and dependency dialog modules.
- Kept `MediaAnalysis.tsx` imports compatible through `MediaDisplayPanels.tsx`; no playback URL handling, batch status shape, dependency dialog behavior, or transcription workflow changed.

### Changes

- Added `frontend/src/app/features/media/MediaAnalysisProgressPanel.tsx` for media scan/rebuild progress display.
- Added `frontend/src/app/features/media/BatchTranscriptionStatusPanel.tsx` for batch transcription task progress.
- Added `frontend/src/app/features/media/MediaPlaybackDialog.tsx` for audio/video playback dialog.
- Added `frontend/src/app/features/media/MediaDependencyDialogs.tsx` for ffmpeg and speech dependency alert dialogs.
- Reduced `MediaDisplayPanels.tsx` from 257 lines to a 4-line compatibility export layer.
- Updated size budgets:
  - `MediaDisplayPanels.tsx`: 4 lines under 20 budget.
  - `MediaAnalysisProgressPanel.tsx`: 77 lines under 95 budget.
  - `BatchTranscriptionStatusPanel.tsx`: 48 lines under 65 budget.
  - `MediaPlaybackDialog.tsx`: 68 lines under 85 budget.
  - `MediaDependencyDialogs.tsx`: 62 lines under 80 budget.

### Validation

- `pnpm exec vitest run src/app/pages/MediaAnalysis.test.tsx src/app/features/media/MediaOverviewPanels.test.tsx src/app/features/media/MediaSessionCells.test.tsx src/app/features/media/useMediaTranscriptionWorkflow.test.ts scripts/check-size.test.mjs` - passed, 12 tests.
- `pnpm run size:check` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 96 Vitest files / 313 tests, and Vite build.

### Review

- This round is behavior-preserving and only changes media display module ownership.
- Media feature display boundaries are now clearer: page orchestration, overview panels, session table/cells, transcription summary, progress/status panels, playback dialog, and dependency dialogs are separated.
- Remaining major frontend engineering risk is concentrated in `SentinelContext.tsx`, `sidebar.tsx`, `core/*`, `MiscToolsShell.tsx`, `Workspace.tsx`, and broad page/feature panels.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 34 - Evidence Panel Section Split

Time: 2026-05-10 21:08:30 +08:00  
Author: Codex

### Scope

- Continued Phase 2 frontend engineering cleanup by splitting the unified Evidence page presentation layer.
- Kept `EvidencePanel.tsx` imports compatible through `EvidencePanelSections.tsx`; no Evidence query, module filter, severity filter, export, table action, or MISC exclusion behavior changed.

### Changes

- Added `frontend/src/app/features/evidence/EvidenceHero.tsx` for the Evidence page heading, description, and module chips.
- Added `frontend/src/app/features/evidence/EvidenceFilters.tsx` for severity filters, module chips, search, and export controls.
- Added `frontend/src/app/features/evidence/EvidenceResults.tsx` for loading/error status, evidence table columns, packet actions, and tag cells.
- Added `frontend/src/app/features/evidence/EvidenceCaveats.tsx` for deduplicated evidence caveat display.
- Reduced `EvidencePanelSections.tsx` from about 315 lines to a 4-line compatibility export layer.
- Updated size budgets:
  - `EvidencePanelSections.tsx`: 4 lines under 20 budget.
  - `EvidenceHero.tsx`: 37 lines under 55 budget.
  - `EvidenceFilters.tsx`: 124 lines under 150 budget.
  - `EvidenceResults.tsx`: 112 lines under 140 budget.
  - `EvidenceCaveats.tsx`: 19 lines under 35 budget.

### Validation

- `pnpm exec vitest run src/app/features/evidence/evidencePanelRules.test.ts scripts/check-size.test.mjs` - passed, 5 tests.
- `pnpm run size:check` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 96 Vitest files / 313 tests, and Vite build.

### Review

- This round is behavior-preserving and only changes Evidence presentation module ownership.
- Unified Evidence still excludes MISC from module filters, preserving the mainline evidence boundary.
- The next low-risk Phase 2 targets remain `IndustrialModbusPanels.tsx`, `UsbHidPanels.tsx`, `AnalysisPrimitives.tsx`, `MiscToolsShell.tsx`, `Workspace.tsx`, and `MainLayoutChrome.tsx`.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 35 - Industrial Modbus Panel Split

Time: 2026-05-10 21:25:53 +08:00  
Author: Codex

### Scope

- Continued Phase 2 frontend engineering cleanup by splitting Industrial Modbus presentation into focused display modules.
- Kept `IndustrialModbusPanels.tsx` as the compatible composition entry; no Modbus analysis data shape, filter behavior, packet action, UTF-8 decoded input rendering, or transaction table behavior changed.

### Changes

- Added `frontend/src/app/features/industrial/ModbusSuspiciousWritesPanel.tsx` for suspicious write aggregation display.
- Added `frontend/src/app/features/industrial/ModbusDecodedInputsPanel.tsx` for reconstructed ASCII/UTF-8 input display.
- Added `frontend/src/app/features/industrial/ModbusTransactionsPanel.tsx` for Unit/function filters, transaction table columns, and transaction summary cells.
- Reduced `IndustrialModbusPanels.tsx` from about 268 lines to 42 lines; it now only composes the focused Modbus panels.
- Updated size budgets:
  - `IndustrialModbusPanels.tsx`: 42 lines under 60 budget.
  - `ModbusSuspiciousWritesPanel.tsx`: 101 lines under 125 budget.
  - `ModbusDecodedInputsPanel.tsx`: 73 lines under 95 budget.
  - `ModbusTransactionsPanel.tsx`: 192 lines under 220 budget.

### Validation

- `pnpm exec vitest run src/app/pages/IndustrialAnalysis.test.tsx scripts/check-size.test.mjs` - passed, 3 tests.
- `pnpm run size:check` - passed.
- `pnpm run typecheck` - passed.
- `pnpm exec vitest run src/app/pages/MiscTools.smb3.test.tsx src/app/pages/MiscTools.sessions.test.tsx src/app/pages/MiscTools.payloadHints.test.tsx src/app/pages/MiscTools.test.tsx` - passed, 17 tests after the first full-suite run exposed a transient MISC concurrency timeout.
- `pnpm run ci` - passed on rerun, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 96 Vitest files / 313 tests, and Vite build.

### Review

- This round is behavior-preserving and only changes Industrial Modbus presentation ownership.
- The Modbus UTF-8 decoded input surface remains covered by `IndustrialAnalysis.test.tsx`.
- A first full CI attempt hit unrelated MISC full-suite timing timeouts; the focused MISC rerun passed and the full CI rerun passed, so no product code or test timeout change was made.
- Next low-risk Phase 2 targets remain `UsbHidPanels.tsx`, `AnalysisPrimitives.tsx`, `MiscToolsShell.tsx`, `Workspace.tsx`, and `MainLayoutChrome.tsx`.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 36 - USB HID Panel Split

Time: 2026-05-10 21:29:23 +08:00  
Author: Codex

### Scope

- Continued Phase 2 frontend engineering cleanup by splitting USB HID replay and mouse visualizations into focused modules.
- Kept `UsbHidPanels.tsx` as the compatible export entry; no HID tab behavior, replay cursor behavior, text preview, mouse trajectory, heatmap, behavior list, or USB analysis data shape changed.

### Changes

- Added `frontend/src/app/features/usb/UsbKeyboardReplay.tsx` for keyboard replay controls and current event presentation.
- Added `frontend/src/app/features/usb/UsbMouseTrajectory.tsx` for mouse path rendering and legend.
- Added `frontend/src/app/features/usb/UsbMouseHeatmap.tsx` for density and click hotspot rendering.
- Added `frontend/src/app/features/usb/UsbMouseBehaviorList.tsx` for compact recent mouse behavior display.
- Added `frontend/src/app/features/usb/UsbHidEmptyState.tsx` for shared HID empty states.
- Added `frontend/src/app/features/usb/usbHidRules.ts` for pure replay-token, mouse badge, and coordinate normalization helpers.
- Updated `useUsbHidState.ts` to import `keyboardReplayToken` from the pure rules file instead of the display barrel.
- Reduced `UsbHidPanels.tsx` from about 269 lines to a 5-line compatibility export layer.
- Updated size budgets:
  - `UsbHidPanels.tsx`: 5 lines under 20 budget.
  - `UsbKeyboardReplay.tsx`: 124 lines under 150 budget.
  - `UsbMouseTrajectory.tsx`: 51 lines under 70 budget.
  - `UsbMouseHeatmap.tsx`: 69 lines under 95 budget.
  - `UsbMouseBehaviorList.tsx`: 33 lines under 45 budget.
  - `UsbHidEmptyState.tsx`: 9 lines under 15 budget.
  - `usbHidRules.ts`: 35 lines under 45 budget.

### Validation

- `pnpm exec vitest run src/app/pages/UsbAnalysis.test.tsx src/app/features/usb/UsbTablesSplit.test.tsx scripts/check-size.test.mjs` - passed, 9 tests.
- `pnpm run size:check` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 96 Vitest files / 313 tests, and Vite build.

### Review

- This round is behavior-preserving and only changes USB HID presentation ownership plus one hook import to a pure rules module.
- USB HID now has clearer boundaries between state, keyboard replay, mouse path, heatmap, behavior list, and pure coordinate/badge rules.
- Next low-risk Phase 2 targets remain `AnalysisPrimitives.tsx`, `MiscToolsShell.tsx`, `Workspace.tsx`, and `MainLayoutChrome.tsx`; state-heavy files remain deferred.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 37 - Desktop Transport Split And Backend Reuse Hardening

Time: 2026-05-10 22:05:21 +08:00  
Author: Codex

### Scope

- Implemented the first transport migration round for the desktop app by splitting frontend bridge transport selection and moving the desktop control plane onto Wails IPC-compatible bindings.
- Hardened backend reuse detection so the desktop shell no longer trusts raw loopback port occupancy alone.
- Kept browser/dev mode on `HTTP + SSE`, and intentionally left bulk read/download data paths on HTTP for this round.

### Changes

- Added frontend transport split modules:
  - `frontend/src/app/integrations/bridgeTypes.ts`
  - `frontend/src/app/integrations/httpBridge.ts`
  - `frontend/src/app/integrations/desktopBridge.ts`
  - `frontend/src/app/integrations/bridgeFactory.ts`
- Reduced `frontend/src/app/integrations/wailsBridge.ts` to a stable facade that still exports the same `bridge` contract for existing pages, hooks, and tests.
- Added desktop-side loopback proxy helpers:
  - `desktop_backend_proxy.go`
  - `desktop_backend_probe.go`
- Added desktop Wails binding methods for:
  - backend readiness
  - tool runtime snapshot/config updates
  - tshark path save
  - capture lifecycle control
  - TLS config read/write
- Replaced the desktop startup reuse gate from raw TCP-only detection to reusable backend probing with:
  - loopback port reachability
  - `/health`
  - `/api/runtime/identity`
- Added backend runtime identity endpoint at `/api/runtime/identity`.
- Added regression tests for:
  - bridge selection in frontend transport factory
  - desktop reusable backend identity probe
  - desktop proxy auth/header + error normalization
  - backend runtime identity HTTP handler

### Validation

- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm exec vitest run src/app/integrations/bridgeFactory.test.ts src/app/state/hooks/useBackendLifecycle.test.tsx` - passed, 8 tests.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `cd backend && go test ./internal/transport` - passed.
- `cd backend && go test ./...` - passed.
- `go test -tags dev ./...` - passed.

### Review

- This round intentionally migrates only the desktop control plane; packet/stream pagination, analysis reads, downloads, blob playback, and event SSE remain on HTTP.
- The main user-facing gain is that desktop runtime config and capture lifecycle operations no longer depend on browser fetch reaching a possibly stale or incompatible loopback backend instance.
- The new `/api/runtime/identity` response is currently minimal and hard-coded to `version=dev`; if release-aware reuse validation becomes necessary later, it should be extended with real build metadata rather than introducing a second identity format.
- Desktop event flow still uses `/api/events` in this round; if future evidence shows desktop SSE instability, the next migration step should move desktop events to Wails runtime events without changing browser/dev transport.
- No samples, generated PCAPs, or local report directories are intended for commit.

---

## Round 38 - Workspace Data Plane Failure Diagnostics

Time: 2026-05-10 22:24:22 +08:00  
Author: Codex

### Scope

- Continued the mixed-transport desktop stabilization work without moving bulk packet reads to Wails IPC.
- Closed the main UX gap where packet-page HTTP failures could leave the main shell visible but make the workspace look like an empty packet list.
- Kept packet pagination, stream pagination, analysis reads, downloads, blob playback, and `/api/events` on HTTP.

### Changes

- Added explicit packet-page failure state to `SentinelContext`:
  - `packetPageError`
  - `retryPacketPage`
- Added `frontend/src/app/state/packetPageStatus.ts` for stable packet-page error and retry status messages.
- Added `frontend/src/app/components/workspace/WorkspacePacketErrorPanel.tsx` so workspace packet-read failures render a visible diagnostic panel with:
  - backend/data-plane error detail
  - current capture name
  - current display filter
  - retry-current-page action
- Updated `Workspace.tsx` and `WorkspacePanels.tsx` to prioritize packet-page errors over empty-table rendering and filter-loading blank states.
- Adjusted filter apply/clear completion so a failed packet-page request does not overwrite the data-plane error with a misleading "filter applied" or "filter cleared" success status.
- Tightened desktop backend proxy errors:
  - backend JSON error messages now use ordinary error values instead of format strings.
  - reusable-backend probe now reports auth mismatch as `backend requires a matching GSHARK_BACKEND_TOKEN` instead of a generic incompatible-instance detail.
- Added focused tests for:
  - packet-page status message formatting
  - workspace diagnostic panel rendering and retry action
  - desktop proxy normalized backend error text
  - reusable backend auth-mismatch reporting
- Added size budgets for the new workspace diagnostic component and packet-page status helpers/tests.

### Validation

- `cd frontend && pnpm exec vitest run src/app/components/workspace/WorkspacePanels.test.tsx src/app/state/packetPageStatus.test.ts scripts/check-size.test.mjs` - passed, 7 tests.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `cd frontend && pnpm run ci` - passed, including package-manager check, typecheck, ESLint, scoped Prettier format check, size budgets, 99 Vitest files / 320 tests, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- This round does not require full Wails IPC migration. It keeps the selected architecture intact: control plane on desktop IPC, data plane on HTTP, event plane on HTTP/SSE for now.
- The user-visible behavior for "main panel still visible but workspace cannot show packets" is now clearer: HTTP packet-page failure is rendered as an actionable data-plane diagnostic instead of looking like a valid empty capture or empty filter result.
- The remaining HTTP data-plane risk is now observable rather than silent. If packet-page failures continue in desktop mode, the next decision can be based on concrete error messages rather than treating all empty workspaces as the same symptom.
- `docs/audit-development-report-archive-2026-05-10/` is ignored locally; the report was updated on disk for audit continuity but is not expected to appear in normal `git status`.

---

## Round 39 - Release Bootstrap And Capture Transaction Hardening

Time: 2026-05-10 23:04:38 +08:00  
Author: Codex

### Scope

- Closed the two primary stability gaps left after the desktop control-plane split:
  - release desktop backend bootstrap still falling back to source-tree resolution,
  - capture open / replacement still destroying active UI state before new capture validity was confirmed.
- Kept the mixed transport architecture unchanged:
  - desktop control plane on Wails IPC,
  - data plane on HTTP,
  - events on HTTP/SSE.

### Changes

- Hardened desktop packaged bootstrap in `app.go`:
  - distinguish packaged runtime from source checkout before attempting `go run` fallback,
  - stop masking bundled-backend failures behind `backend directory not found`,
  - add bundled backend candidate / extraction diagnostics,
  - extract backend and bundled YARA rules into hash-scoped temp directories with atomic file promotion,
  - add release smoke-check mode via `GSHARK_RELEASE_SMOKE_CHECK=1`.
- Hardened release packaging scripts:
  - fail fast if `frontend/dist/sentinel-backend.exe` is missing,
  - fail fast if bundled default YARA rule is missing,
  - run a post-package smoke check against the produced desktop exe.
- Transactionalized backend capture replacement in `backend/internal/engine/service.go`:
  - parse into a fresh temporary `packetStore`,
  - keep current capture active until the new capture has valid packets,
  - only commit `pcap`, packet store, stream index, caches, analysis snapshots, and media/object/YARA runtime state after successful parse commit,
  - discard temporary parse results on failure, cancel, or zero-packet completion.
- Added backend packet store swap helper in `packet_store.go` so active capture state can be replaced atomically without leaking old temp DB files.
- Introduced frontend capture transaction state in `SentinelContext.tsx`:
  - `idle`,
  - `pending`,
  - `failed`.
- Changed frontend capture open semantics:
  - opening or replacing a capture now keeps the previous active capture visible until first-page validation succeeds,
  - capture failure no longer reuses packet-page data-plane error state,
  - first-open failure returns to a dedicated failure card,
  - replacement failure keeps the previous capture and shows a banner with retry / choose-another-file actions.
- Added frontend helpers/components:
  - `captureTransactionStatus.ts`
  - `CaptureTransactionErrorPanel.tsx`
  - `CaptureTransactionBanner.tsx`
  - `workspaceStatus.ts`
- Kept `packetPageError` as the dedicated HTTP packet-page diagnostic path; it now coexists with the new capture transaction failure model instead of carrying both semantics.

### Validation

- `go test -tags dev ./...` - passed.
- `cd backend && go test ./internal/engine -run "TestLoadPCAPFailureKeepsPreviousCaptureActive|TestLoadPCAPZeroPacketsKeepsPreviousCaptureActive|TestLoadPCAPReplacementCancelsPreviousLoad|TestClearCaptureResetsPacketStore|TestPendingLoadRunHonorsCloseBeforeGoroutineStarts"` - passed.
- `cd backend && go test ./internal/transport` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm exec vitest run src/app/components/workspace/WorkspacePanels.test.tsx src/app/state/packetPageStatus.test.ts src/app/state/capturePreloadStatus.test.ts src/app/state/captureOpenState.test.ts` - passed, 14 tests.

### Review

- This round fixes root behavior rather than adding another UI-only patch:
  - packaged desktop runtime now treats missing bundled backend as a real bootstrap failure,
  - replacement parse no longer destroys a valid active capture before new capture validity is proven.
- The remaining release-side gap is metadata depth:
  - `/api/runtime/identity` still returns minimal build information,
  - release-aware backend reuse compatibility can be tightened further later with real version / commit metadata.
- The remaining architecture risk remains intentional:
  - packet and stream data reads still depend on HTTP loopback,
  - but failure domains are now separated between capture transaction failures and data-plane page-read failures.

---

## Round 40 - Analysis Cockpit Capture Open Navigation Fix

Time: 2026-05-10 23:21:16 +08:00  
Author: Codex

### Scope

- Investigated the user-reported issue where importing a capture from the Analysis Cockpit welcome state completed capture open work but did not transition into the traffic workspace.
- Kept the capture transaction model from Round 39 intact: capture open still commits only after first-page validation succeeds, and failed opens stay on the failure path.

### Root Cause

- `AnalysisCockpit.tsx` reused `CaptureWelcomePanel` when no capture was active.
- `CaptureWelcomePanel` called `openCapture()` but had no success signal or navigation callback.
- `openCapture()` previously returned `Promise<void>`, so callers could not distinguish a committed capture from an open failure, cancellation, or preload timeout.
- Result: importing from `/analysis-cockpit` updated global capture state after success, then the same route naturally rendered the cockpit content; no code requested navigation back to `/` workspace.

### Changes

- Changed `openCapture()` / internal `startCapture()` to return `Promise<boolean>`:
  - `true` only after the new capture is committed, first-page validation has passed, stream index refresh has run, and transaction state returns to idle.
  - `false` for disconnected backend, abort/cancel, failed open, preload timeout, empty parse, stale capture sequence, or superseded task.
- Added an optional `onCaptureOpened` callback to `CaptureWelcomePanel`.
- Updated `AnalysisCockpit.tsx` so importing from its welcome state navigates to `/` only when `openCapture()` reports success.
- Added `AnalysisCockpit.test.tsx` covering:
  - successful capture open navigates to the workspace,
  - failed capture open stays on the cockpit welcome state.

### Validation

- `pnpm exec vitest run src/app/pages/AnalysisCockpit.test.tsx src/app/components/TLSDecryptionDialog.test.tsx` - passed, 4 tests.
- `pnpm run typecheck` - passed.
- `pnpm run lint` - passed.
- `pnpm run size:check` - passed.

### Review

- The bug was a frontend route-orchestration gap, not a backend parse deadlock.
- The fix avoids unconditional navigation: failed capture opens, empty parses, and preload timeouts do not move the user into the workspace.
- Existing workspace and TLS reload callers can ignore the boolean result without behavior change, while future callers can now gate follow-up UI transitions on a real committed capture.

---
