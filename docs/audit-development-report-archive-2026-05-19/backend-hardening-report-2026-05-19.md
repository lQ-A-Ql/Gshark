# Backend Hardening Report - 2026-05-19

Author: Codex

Timestamp: 2026-05-19 18:48:03 +08:00

## Scope

- Remove the unauthenticated `wails.localhost` origin bypass when a backend auth token is configured.
- Add hard upload size enforcement for `/api/capture/upload`.
- Limit MISC package `manifest.json` reads during zip import.

## Changes

- `backend/internal/transport/http_server.go`
  - Kept `/health` unauthenticated.
  - Kept Bearer, `X-GShark-Auth`, and query `access_token` authentication.
  - Removed trusted desktop Origin as an authentication bypass.

- `backend/internal/transport/http_capture.go`
  - Added a 2GB package-level upload limit.
  - Wrapped upload bodies with `http.MaxBytesReader`.
  - Reduced multipart memory budget to 64MB.
  - Added a limited copy helper so disk writes cannot exceed the configured cap.
  - Return `413 Request Entity Too Large` on upload limit violations and remove partial temp files.

- `backend/internal/miscpkg/manager.go`
  - Read `manifest.json` through `io.LimitReader(maxModuleZipFileBytes+1)`.
  - Return a clear manifest size-limit error before JSON parsing.

## Tests

- Updated auth test so `http://wails.localhost` without token returns `401`, and with Bearer token returns `200`.
- Added capture upload tests for small-file success and oversize rejection/temp cleanup.
- Added MISC package test for oversized `manifest.json`.

Validation:

```powershell
cd backend
go test ./internal/transport -run "TestWithAuthRequiresTokenForTrustedDesktopOrigin|TestWithAuthRequiresMatchingToken|TestHandlerAllowsEventStreamAccessTokenAndRejectsWrongToken|TestHandleCaptureUpload" -count=1
go test ./internal/miscpkg -run "TestImportZipBytesRejectsOversizedManifest|TestImportZipBytesRejectsOversizedFile" -count=1
go test ./internal/transport ./internal/miscpkg -count=1
gofmt -l internal\transport\http_server.go internal\transport\http_server_test.go internal\transport\http_capture.go internal\transport\http_capture_test.go internal\miscpkg\manager.go internal\miscpkg\manager_test.go
```

All focused validations passed. `gofmt -l` returned no files.

## Documentation Review

- `docs/backend-engineering-audit-spec-2026-05-14.md` remains aligned with this work: the changes strengthen transport auth, upload handling, and MISC import boundaries without introducing new framework or route ownership changes.
- `docs/misc-module-interface.md` already documents MISC zip modules as a local trusted extension point rather than a strong sandbox. The manifest read limit complements that stated boundary and does not require interface changes.

## Residual Risk

- Upload limits are enforced per request body and per file copy, but multipart envelope overhead means a payload just below the body cap may contain a file slightly smaller than 2GB. This is acceptable for the current hard request cap.
- MISC module code execution remains a trusted local extension model, as documented; this change only bounds manifest reading.
