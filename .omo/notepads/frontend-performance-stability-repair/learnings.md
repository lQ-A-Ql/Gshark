# Learnings

## 2026-06-05 Task: session-start
- No prior notepad existed for this plan.
- Key inherited findings are in `.omo/plans/frontend-performance-stability-repair.md` and the analysis session.
- Preserve `top_talkers`; add explicit `top_conversations`.
- Evidence typed IPC timeout is app wrapper policy, not Wails default.

## 2026-06-05 Task 1: backend traffic contract
- Backend `GlobalTrafficStats` now preserves endpoint-oriented `top_talkers` and adds explicit directional `top_conversations` records shaped as `{src,dst,count}`.
- `top_conversations` is accumulated separately from `talkerMap`, skips incomplete src/dst rows, sorts by count desc then src/dst asc, and is capped at 200 edges.
- Verification passed: `go test ./internal/tshark -run TestGlobalTrafficStats -count=1 -v` and `go test ./internal/transport -run TestGlobalTrafficStatsContract -count=1 -v` from `backend`.

## 2026-06-05 Task: 3 Evidence typed IPC and collector timings
- Evidence typed IPC now uses an explicit 30000ms timeout constant only for `getEvidence` and `getEvidenceWithFilter`; `DEFAULT_TYPED_IPC_TIMEOUT_MS` remains 10000ms.
- `GatherEvidence` now emits `__evidence_timing__:<module>:<duration_ms>:<records>:<status>` for each attempted collector, including `canceled` for pre-canceled contexts.
- Verification passed: `pnpm run test:run -- desktopBridge` and `go test ./internal/engine -run TestGatherEvidence -count=1 -v`; full outputs are in `.omo/evidence/task-3-evidence-ipc.txt`.

## 2026-06-05 Task 2: frontend explicit traffic conversations
- Frontend `GlobalTrafficStats` now carries explicit `topConversations` alongside endpoint-oriented `topTalkers`; topology rendering must consume only `topConversations`.
- `asGlobalTrafficStats()` trims `top_conversations[*].src` and `.dst`, coerces `count` to a number, and drops malformed rows with an empty endpoint so backend DTO noise cannot fabricate edges.
- Packet-list fallback now computes endpoint buckets for `topTalkers` and directional pairs for `topConversations`, preserving compatibility when `/api/stats/traffic/global` is unavailable.
- `TrafficGraphPanels` memoizes `timelinePoints`, `topologyEdges`, and `chartPanels`, and tests now lock the rule that endpoint-only `topTalkers` never produce topology edges.
- Verification passed: `pnpm run test:run -- trafficMapper TrafficGraph` and `pnpm run typecheck`; summary is in `.omo/evidence/task-2-traffic-ui.txt`.

## 2026-06-05 Task 6: backend cold analysis singleflight
- Added a stdlib in-flight analysis group scoped by capture path plus operation/options key for global traffic stats, industrial, vehicle, non-force media, USB normalized options, and C2 same-capture analysis.
- Waiters use their own context while the shared builder continues for other callers; failed builders delete their in-flight entry and allow retry without caching failure results.
- USB analysis singleflight keys include normalized HID source and event limit, so different option keys remain isolated while identical cold requests coalesce.
- Verification passed: `go test ./internal/engine -run "Test.*Singleflight|TestUSBAnalysisWithOptions" -count=1 -v` and `go test ./internal/engine -run "TestGatherEvidence|Test.*Singleflight|TestUSBAnalysisWithOptions|Test.*Analysis" -count=1 -v`; summary is in `.omo/evidence/task-6-singleflight.txt`.

## 2026-06-05 Task 6 follow-up: singleflight completion ordering
- `analysisInFlightGroup.do` now assigns result/error, deletes the in-flight entry, and closes `done` under the group mutex; waiters still unblock, but new callers after completion cannot join a stale failed call.
- Verification passed: `TestAnalysisSingleflightFailureDoesNotPoisonCache -count=10`, focused Task 6 subset, broader regex twice, and exact broader regex once. Updated summary is in `.omo/evidence/task-6-singleflight.txt`.

## 2026-06-05 Task 4: evidence page-limited rendering
- Evidence panel now keeps all filtering, facets, metrics, report generation, and export semantics over the full fetched `sorted` record set while rendering only `visibleRecords` in 200-row pages.
- The visible cap resets whenever the fetched evidence set or local search/severity/facet inputs change, and selection now falls back to the first visible record if the prior selection is paged out or filtered away.
- Verification passed: `pnpm run test:run -- EvidencePanel evidencePanelRules` and `pnpm run typecheck`; command summary is in `.omo/evidence/task-4-evidence-render.txt`.

## 2026-06-05 Task 5: route transition jank
- `MainLayout` now keeps the route `<Outlet />` wrapper mounted across pathname changes by removing the pathname-derived route key; route motion direction still updates through `data-route-motion`.
- Route transition/background fade CSS no longer uses `filter`, `blur`, or route transition `backdrop-filter`; route motion remains opacity/transform based.
- Static `MainLayout` tests now lock both constraints: no pathname-keyed route wrapper and no filter/blur/backdrop-filter in `meow-route-in` or `.meow-route-transition`.
- Verification passed: `pnpm run test:run -- MainLayout` and `pnpm run lint`; summary is in `.omo/evidence/task-5-route-jank.txt`.

## 2026-06-05 Task 7: final verification
- Required targeted backend tests passed for traffic stats, transport contract, evidence gathering, singleflight, and USB options.
- Required frontend targeted regression command passed with 9 test files and 64 tests, covering traffic mapper/graph, evidence panel/rules, main layout, and desktop bridge.
- Required frontend gates passed: `typecheck`, `lint`, `format:check`, and `build`; backend broad `go test ./...` also passed.
- Full `./scripts/check-all.ps1` was practical and ran, but failed on root desktop update URL expectations and a backend gofmt finding in `internal\engine\ioc_import_test.go`; final command evidence is in `.omo/evidence/final-verification.md`.

## 2026-06-05 Task 8: traffic mixed-timestamp test fix
- `trafficTimeline.ts` remains UTC-deterministic for epoch-like timestamps; the focused Traffic Graph failure was a bad test fixture, not a normalization bug.
- Updated `TrafficGraph.test.ts` to use the UTC epoch for `12:00:02Z` (`1717588802000`) so mixed epoch and clock labels still sort deterministically as `12:00:00`, then `12:00:02`.
- Verification passed: `pnpm run test:run -- TrafficGraph trafficMapper` from `frontend`.

## 2026-06-05 Task 9: traffic trend rendering and topology navigation
- `TrafficAreaChart` now re-normalizes incoming timeline points, drops malformed labels and non-finite counts, uses monotonic linear segments to avoid spike overshoot, and renders a valid single-point line/area instead of emitting an empty or invalid path.
- `TrafficGraphPanels` now normalizes timeline buckets before passing them into the chart, and the topology graph keeps all edges, labels, and nodes inside a transformed `<g>` so wheel zoom and left-drag pan apply uniformly without breaking `marker-end="url(#topo-arrow)"` coverage.
- Verification commands: `pnpm run test:run -- TrafficGraph trafficMapper`, `pnpm run typecheck`.

## 2026-06-05 Task 10: traffic trend chart distortion repair
- `TrafficAreaChart` no longer uses `preserveAspectRatio="none"`; it measures the panel width, builds the SVG `viewBox` from that live width, and preserves aspect with `xMinYMin meet` so the trend line keeps sane vertical amplitude instead of being stretched across a tiny 100-unit canvas.
- The chart now uses left/right chart padding and width-aware x-label sampling, which keeps the first/last points away from the edges and avoids dumping unreadable labels in narrow side panels.
- Verification commands: `pnpm run test:run -- TrafficGraph trafficMapper`, `pnpm run typecheck`.

## 2026-06-05 Task 11: traffic timeline interaction surface
- `TrafficGraph` now owns `TrafficTimelineSelection` page state (`hoveredLabel`, `lockedLabel`, `selectedRange`) so the trend panel can expose future cross-card linkage without pretending other cards are already window-filtered.
- `TrafficAreaChart` keeps normalized/sanitized SVG rendering, adds hover, click-lock, and same-SVG brush range selection with `traffic-area-locked-point` and `traffic-area-selected-range` test hooks; `TrafficTimelineTrack` and `TrafficTimelineSummary` compose the new `流量时间线` panel around generated peak/burst events.
- Non-trend cards now show the scoped global-data warning when a timeline point/window is selected, while topology still derives edges only from `topConversations`.
- Verification results: `pnpm run test:run -- TrafficGraph trafficTimeline trafficMapper` passed (8 files, 27 tests), `pnpm run typecheck` passed, `pnpm run lint` passed, and grep over changed traffic files found no `@ts-ignore`, `@ts-expect-error`, `as any`, `TODO`, `FIXME`, or `HACK`.
