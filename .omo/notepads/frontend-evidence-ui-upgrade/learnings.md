# Learnings

## 2026-06-04 Session start
- Plan: `.omo/plans/frontend-evidence-ui-upgrade.md`.
- Evidence route must remain existing `EvidencePanel` route; no new top-level route.
- Missing backend fields/API must show explicit unavailable/partial states, never fake data.

## 2026-06-04 Optional-contract fixture tests
- Current frontend evidence contract can already lock JA3, JA3S, webshell, china chopper, DNP3, IOC, playbook, and rule rows using existing fields only: `sourceType`, `family`, `value`, `tags`, `summary`, and module normalization.
- Sparse evidence summaries can legitimately render in both the investigation report and the table, so panel tests should assert safe presence instead of single-instance uniqueness.
- Empty-state and sparse-state tests should avoid cached evidence bleed by changing `captureRevision`, because `useEvidence` caches by `captureRevision + filePath + totalPackets + modules`.

## 2026-06-05 Task 4 WebShell family/version UI
- Frontend can safely surface WebShell family, decoder, confidence, role, and version without backend changes by normalizing existing `familyHint`, `decoderHints`, and `decoderOptionsHint` metadata in shared helpers.
- China Chopper aliases should be normalized from family hints, decoder hints, and decoder-option metadata into a single clear label: `菜刀 / China Chopper`.
- Version must stay honest: render the provided `decoderOptionsHint.versionHint` when present, otherwise show explicit unavailable text (`未提供`) rather than fabricating a family/version guess.
- The current StreamDecoder toolbar still exposes only Base64, Behinder, AntSword, Godzilla, and Auto buttons, so China Chopper should be shown as metadata/hinting only instead of implying a new dedicated frontend decode button.

## 2026-06-06 DNP3 industrial section
- The industrial page can surface a first-class DNP3 panel without backend changes by matching `detail.name`, `controlCommand.protocol`, and `ruleHit.rule` for `dnp3`, then reusing existing `operation` / `target` / `result` / `summary` fields for focused charts and a compact table.
- Because the new DNP3 panel intentionally coexists with unchanged generic control-command and protocol-detail panels, populated fixtures will repeat some DNP3 summaries and evidence strings; tests should assert presence, not uniqueness.

## 2026-06-05 Evidence model extension
- Frontend evidence records now carry optional rich fields for feature/entity, protocol/version, display name, rule, playbook, IOC, JA3/JA3S, and typed flat metadata while preserving older sparse payloads.
- Evidence module normalization should explicitly retain `media` and `misc`; unknown/unmatched module names continue mapping to `unknown` instead of being folded into a coarse bucket.
- Search and CSV export should read the rich fields directly, so future Evidence center widgets can use backend-provided fields without inventing unavailable metadata.

## 2026-06-06 Task 7 targeted test alignment
- `EvidencePanel.test.tsx` must track the investigation-center toolbar placeholder from `EvidenceFilters.tsx`; after the search scope expanded to IOC/rule/host/URI terms, the targeted search/export test needed the new placeholder string to keep exercising real toolbar behavior instead of failing before filter/export assertions ran.

## 2026-06-06 Task 8 label/action polish
- Evidence detail rendering is the right place to normalize newly exposed cross-feature labels without changing backend contracts: shared helpers can map `ja3/ja3s`, `china_chopper`, `webshell`, `dnp3`, `ioc`, `playbook`, and `rule` into consistent user-facing labels while still exposing honest unavailable states like `未提供`, `IOC API unavailable`, and `Playbook 未提供`.
- Packet and stream actions need separate validity gates. A record with only `packetId` should still allow packet jump while hiding stream navigation; a record with neither valid `packetId` nor `streamId` should show an explicit no-action message instead of disabled buttons that imply navigable context.

## 2026-06-06 Task 8 stable EvidencePanel selectors
- `EvidencePanel.test.tsx` needs to scope row selection to the actual Evidence results table, not global duplicate summary text that also appears in the investigation report. The stable approach is: find the `调查摘要` column header, walk to that table, then use `within(table)` to locate the summary cell and click its parent `tr`.
- Action-guard assertions are most reliable when scoped to the selected detail panel's `Actions` section via `within(...)`; page-wide button queries are brittle because other surfaces can legitimately expose the same packet/stream controls.

## 2026-06-05 Task 9 full frontend verification
- Full frontend gates passed after scoped verification fixes: `pnpm run test:run`, `pnpm run typecheck`, `pnpm run lint`, `pnpm run format:check`, and `pnpm run build`.
- `format:check` reports touched files incrementally in this repo, so Task 9 needed repeated file-scoped Prettier runs until the scoped baseline was clean.
- DNS C2 aggregate records do not currently expose stream IDs, so DNS evidence actions should remain packet-only unless a backend contract adds stream context.
