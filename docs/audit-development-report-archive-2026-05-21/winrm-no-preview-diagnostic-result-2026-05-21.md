# WinRM No Preview Diagnostic Result

- Author: Codex
- Timestamp: 2026-05-21 02:30:55 +08:00

## Scope

This round fixed the MISC WinRM decrypt page reporting a Wails IPC data-plane failure when the backend completed analysis but did not extract previewable WinRM plaintext.

This report was later extended after the user clarified that the tshark field compatibility issue must not be treated as WinRM-only.

## Latest Document Review

Reviewed the newest development reports before implementation:

- `docs/audit-development-report-archive-2026-05-21/frontend-packet-color-shader-refinement-2026-05-21.md`
- `docs/audit-development-report-archive-2026-05-21/frontend-workspace-packet-table-and-menu-refinement-2026-05-21.md`

Review conclusion:

- The newest frontend work only changed packet table and chrome visual layers.
- No WinRM tool API or MISC module behavior had been intentionally changed in those reports.
- This fix could remain scoped to WinRM backend result handling plus a small result-summary message display.

## Changes

- Updated `backend/internal/engine/tool_winrm.go`.
  - `RunWinRMDecryptWithContext` no longer returns an error solely because decrypted preview text is empty.
  - Empty-preview runs now produce a normal `WinRMDecryptResult` with diagnostic preview text and an exportable TXT result.
  - Kept real validation, missing capture, scan, context cancellation, and decryption errors as errors.
  - Added a diagnostic builder that explains whether no rows matched, no NTLM context was completed, decrypt/signature failed, or decrypted frames had no command/output extraction.
  - Fixed the WinRM field fallback path when local tshark lacks `mime_multipart.data`.
  - If the first field scan projects rows but every payload column is empty, WinRM now continues to `http.file_data` / `data.data` instead of treating the empty projection as a successful scan.
- Updated `backend/internal/tshark/analysis_helpers.go`.
  - Added `FieldScanFallback` and `ScanFieldRowsWithFallbacks`.
  - The new helper supports multiple candidate field layouts and required-non-empty output columns.
  - This prevents missing optional fields from being projected as empty values and accepted as successful body extraction.
- Updated `backend/internal/engine/c2_decrypt.go`.
  - Cobalt Strike HTTP payload collection now uses the same fallback scanner.
  - Added `http.body.reassembled.data` and `http.body.segment` ahead of `http.file_data` / `data.data` so HTTP body extraction is less version-specific.
- Updated `frontend/src/app/misc/modules/WinRMResultSummary.tsx`.
  - Shows non-`ok` WinRM result messages as a small warning note under the summary chips.
  - Leaves the existing preview, copy, and export actions available for the diagnostic result.
- Updated `backend/internal/engine/tool_misc_test.go`.
  - Added regression coverage for the empty-preview path returning success and persisting the diagnostic export.
  - Added regression coverage for `mime_multipart.data` projecting empty payloads and falling through to `http.file_data`.
- Updated `backend/internal/tshark/analysis_helpers_test.go`.
  - Added generic fallback coverage for empty required projections.
- Updated `backend/internal/engine/c2_decrypt_test.go`.
  - Confirmed CS HTTP candidate projection uses the new stable HTTP body field layout.

## Web Research Notes

Checked official Wireshark material for 4.6.4 / 4.6.5 field compatibility:

- Wireshark 4.6.5 release notes do not list `mime_multipart.data` as a new or stabilized field.
- Official Display Filter Reference for MIME multipart lists `mime_multipart.part`, not `mime_multipart.data`.
- Official HTTP Display Filter Reference includes stable HTTP body-related fields such as `http.file_data`, `http.body.reassembled.data`, and `http.body.segment`.

Conclusion:

- The bug should not be treated as a 4.6.5-only WinRM special case.
- Payload extraction should be capability- and content-driven: try several official/stable fields, require the payload column to be populated, and only then accept the scan result.

## Sample Root Cause

The uploaded sample `C:\Users\QAQ\Downloads\新建文件夹 (3)\新建文件夹\1-pth.pcapng` contains valid WinRM over HTTP traffic on TCP 5985.

Manual tshark triage showed:

- Three NTLM WinRM conversations on `10.10.10.80 -> 10.10.10.201:5985`.
- NTLM Type1/Type2/Type3 handshakes are present.
- User/domain is `pc\administrator`.
- Password `pass@word1` derives a valid NTLM key for the captured traffic.
- Encrypted multipart payload is available through `http.file_data` on this Wireshark build.

The project failed because this host's tshark does not expose `mime_multipart.data`. The generic field planner downgraded that missing optional field to an empty projected column, so `scanWinRMRowsWithContext` received 51 rows and returned early before trying the `http.file_data` fallback. The decryptor therefore saw NTLM headers but no encrypted payload, reported `frameCount=0`, and never reached RC4 unwrap.

After the fallback fix, the same sample decrypts successfully:

- `message=ok`
- `frameCount=38`
- `errorFrameCount=5`
- `extractedFrameCount=15`
- Preview includes decrypted WinRM XML, `"cmd"`, `whoami`, and Windows stdout.

## Explicitly Preserved

- `/api/tools/winrm-decrypt` route and JSON field names were not changed.
- `WinRMDecryptRequest` and `WinRMDecryptResult` shape were not changed.
- NTLM token parsing, RC4 unwrap, signing checks, tshark field fallback, and command/stdout/stderr extraction rules were not changed.
- Frontend MISC module layout and action flow were not changed.
- C2 decrypt public API and storage formats were not changed.

## Validation

Passed:

```powershell
cd backend
go test ./internal/engine -run "TestRunWinRMDecrypt|TestDecryptWinRMRows|TestExtractWinRM|TestAppendWinRM|TestWinRMSecurityContext|TestExplainWinRM|TestScanWinRM"
go test ./internal/tshark -run "TestScanFieldRowsWithFallbacks|TestPlanFieldScan|TestAppendPlanned|TestBuildPlanned|TestScanFieldRowsWithOptions"
go test ./internal/engine -run "TestScanWinRMRows|TestRunWinRMDecrypt|TestAppendCSHTTPFieldCandidates|TestC2Decrypt"
go test ./...
```

Sample reproduction was also run with a temporary local-only test against:

```text
C:\Users\QAQ\Downloads\新建文件夹 (3)\新建文件夹\1-pth.pcapng
```

The temporary sample test was removed after confirming the portable regression tests cover the defect.

Passed:

```powershell
cd frontend
pnpm exec prettier --check src/app/misc/modules/WinRMResultSummary.tsx
pnpm exec eslint src/app/misc/modules/WinRMResultSummary.tsx
pnpm run typecheck
pnpm exec vitest run src/app/pages/MiscTools.test.tsx src/app/integrations/clients/toolClient.test.ts src/app/integrations/mappers/toolMapper.test.ts
```

## Self Review

- The reported string `未提取到可预览的 WinRM 明文` is now a business diagnostic in the result payload, not a thrown backend error that gets wrapped as Wails IPC unavailable.
- This gives the analyst actionable context without hiding true failures such as bad input, missing capture, canceled request, tshark scan failure, or actual decrypt errors.
- The uploaded sample confirmed a second defect: optional-field projection could produce rows without payload and suppress the intended field fallback.
- The broader fix now lives in the tshark scan layer and is reused by both WinRM and C2 HTTP payload collection.
- Remaining risk is limited to modules with domain-specific body fields not yet routed through `ScanFieldRowsWithFallbacks`; those should be migrated when they gain candidate field sets.
- A future live QA pass should load the same WinRM capture through the MISC page and confirm the preview/export surface shows decrypted command and stdout content instead of the previous empty diagnostic.
