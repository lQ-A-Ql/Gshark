# Changelog

This project follows a lightweight Keep a Changelog style from the current governance period onward. Historical round-by-round audit notes remain in `docs/audit-development-report-archive-*` when present, but current facts should be reflected in versioned documents.

## Unreleased

### Added

- Added backend architecture gates for engine root ownership, large-file exceptions, pure-logic subpackage dependencies, explicit service controller composition, and controller state grouping.
- Added frontend type governance checks for new raw `as any`, open core enum `| string` unions, and wide wire DTO inheritance.
- Added shared analysis resource cache and usable capture guards for analysis hooks.
- Added ignored tracked file check to local and CI gates.
- Added `CONTRIBUTING.md` and this changelog.

### Changed

- Split frontend `pnpm run ci` into `ci:quality`, `ci:boundaries`, `ci:desktop`, and `ci:test-build` while preserving the top-level aggregate command.
- Kept `engine.Service` as the public facade while moving state behind explicit controllers and moving WebShell payload inspection into `engine/payloadinspect`.
- Reduced the Sentinel provider body by moving domain context value assembly into dedicated hooks while keeping the legacy context shape unchanged.

### Fixed

- Corrected YARA scan waiting so concurrent callers wait on the actual scan completion signal.
- Wrapped high-frequency YARA cancellation and timeout errors with standard context causes.
- Removed accidentally tracked ignored root `package-lock.json` from the index.
