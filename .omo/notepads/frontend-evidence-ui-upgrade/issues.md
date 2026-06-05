# Issues

## 2026-06-04 Session start
- Known backend/UI gaps: IOC has no clear HTTP API; WebShell unified version is not HTTP-exposed; JA3/JA3S frontend seam must be discovered before coding.

## 2026-06-04 Test-surface issue
- `useEvidence` shares an LRU cache across panel tests, so `EvidencePanel` tests that swap mocked evidence payloads must vary `captureRevision` or clear the cache seam; otherwise later tests can read stale records and miss empty-state/sparse-state assertions.

## 2026-06-05 Task 4 verification note
- TypeScript LSP diagnostics could not run in this environment because `typescript-language-server` is not installed; verification fell back to the repo's targeted Vitest suite for the touched WebShell/StreamDecoder surfaces.

## 2026-06-06 DNP3 panel test note
- Industrial DNP3 fixtures naturally duplicate summaries/evidence across the new focused DNP3 panel and the unchanged generic industrial panels, so exact-singleton text assertions are brittle and should be avoided in future tests.

## 2026-06-05 Evidence model follow-up
- The frontend contract now accepts richer optional evidence fields, but backend producers still need to populate them consistently for Tasks 7/8 to show complete protocol, IOC, rule, playbook, and hash details instead of partial/unavailable states.

## 2026-06-06 Task 3 verification cleanup
- Temporary Playbook QA harness files were removed during Atlas verification cleanup because they were scope-creep artifacts, not production/test infrastructure: `frontend/qa-playbook-harness.html`, `frontend/src/qa-playbook-harness.tsx`.

## 2026-06-05 Task 9 scope note
- Final scope still includes ambient state/cache churn present in the handoff context: `.omo/boulder.json`, `.omo/run-continuation/*`, `docs/knowledge/.obsidian/workspace.json`, and `frontend/package.json.md5`. These were documented rather than reverted because they are not proven disposable Task 9 artifacts.
