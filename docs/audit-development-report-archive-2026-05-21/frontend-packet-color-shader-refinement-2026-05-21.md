# Frontend Packet Color Shader Refinement

- Author: Codex
- Timestamp: 2026-05-21 00:41:38 +08:00

## Scope

This round refined the packet table color shader after permission was granted to edit shader output while preserving packet coloring intuition.

No backend API, route, storage key, parser, matcher, or Wireshark coloring rule text was changed.

## Latest Document Review

Reviewed the newest frontend development report before implementation:

- `docs/audit-development-report-archive-2026-05-21/frontend-workspace-packet-table-and-menu-refinement-2026-05-21.md`

Review conclusion:

- The table already had a dedicated low-boundary packet surface layer.
- `packetColor.backgroundGradient` and `packetColor.color` remained the source of packet-colored row rendering.
- This pass could safely focus on `getPacketColorStyle` output and a tiny `gshark-packet-row-colored` visual adjustment.

## Changes

- Updated `frontend/src/app/core/packetColoring.ts`.
  - Converted `backgroundGradient` from a single hard linear gradient into a layered background image.
  - Each layer is still derived only from the matched rule's original `matched.bg` color.
  - Added a left identification strip, soft radial mist, horizontal fade, and light white highlight.
  - Kept text color as `rgb(0, 0, 0)`.
- Updated `frontend/src/styles/theme.css`.
  - Added a subtle `filter: saturate(1.02)` for colored rows.
  - Did not add any overlay background that would change protocol hue.
- Updated `frontend/src/app/core/packetColoring.test.ts`.
  - Locked Bad TCP priority and the softened rgba output.
  - Locked HTTP/ARP rule intuition and expected base color conversion.

## Explicitly Preserved

- `frontend/src/app/core/packetColoringRules.ts` was not edited.
- `frontend/src/app/core/packetColoringParser.ts` was not edited.
- `frontend/src/app/core/packetColoringMatchers.ts` was not edited.
- `frontend/src/app/core/packetColoringColors.ts` was not edited.
- `WIRESHARK_COLORING_TEXT` and rule order were not changed.
- Virtual row height, column config, right-click menu behavior, and HTTP double-click behavior were not changed.

## Validation

Passed:

```powershell
cd frontend
pnpm exec vitest run src/app/core/packetColoring.test.ts src/app/components/PacketVirtualTable.test.tsx
pnpm exec prettier --check src/app/core/packetColoring.ts src/app/core/packetColoringColors.ts src/app/components/PacketVirtualTableRows.tsx src/styles/theme.css
pnpm exec eslint src/app/core/packetColoring.ts src/app/components/PacketVirtualTableRows.tsx
pnpm run typecheck
pnpm run ci
```

Also passed:

```powershell
git diff --check
```

Test result:

- Targeted validation: 2 test files passed, 8 tests passed.
- Full frontend CI: 225 test files passed, 693 tests passed, Vite production build passed.

CI note:

- The first full CI attempt caught `src/app/core/packetColoring.test.ts` over its 45-line budget.
- The test helper was compacted without reducing assertions, then `pnpm run ci` passed.

## Browser QA Notes

Vite responded at `http://127.0.0.1:5174/`, but the backend health endpoint at `127.0.0.1:17891` refused the connection during this pass. Because of that, live capture-table visual QA was not completed.

The implementation is covered by unit and component tests, and the shader output is constrained to the original matched rule colors.

## Self Review

- The new shader should feel softer and less detached from the glass table surface while preserving Wireshark-like protocol color intuition.
- The strongest behavior guard is that the rule source, matcher, parser, and RGB conversion remained unchanged.
- A future live QA pass should check HTTP/TCP/UDP/ARP/Bad TCP rows with a loaded capture once the backend is available.
