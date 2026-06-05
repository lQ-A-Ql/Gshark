# Issues

## 2026-06-05 Task: session-start
- Worktree has existing uncommitted OMO/status/tool artifacts from prior sessions. Do not include them in final source commit unless user explicitly requests.
- Current plan file is also untracked because it was just created for this work session.

## 2026-06-05 Task 6 follow-up: singleflight failure retry race
- Verification found a race in `analysisInFlightGroup.do`: `done` was closed before the in-flight map entry was deleted, so an immediate retry could join a completed failed call and return stale `boom`.

## 2026-06-05 Task 7: final verification check-all blockers
- `./scripts/check-all.ps1` failed in root desktop dev/prod tag tests: `TestResolveUpdateManifestURLBuildsRawGitHubURL` expected `https://raw.githubusercontent.com/lQ-A-Ql/meow-traffic/release/version.json`, but resolver returned `https://raw.githubusercontent.com/lQ-A-Ql/Gshark/release/version.json`.
- `./scripts/check-all.ps1` also failed the backend fmt check because `internal\engine\ioc_import_test.go` is reported by `gofmt -l`; this file was not part of the Task 1-6 repair scope, so it was documented rather than changed.
