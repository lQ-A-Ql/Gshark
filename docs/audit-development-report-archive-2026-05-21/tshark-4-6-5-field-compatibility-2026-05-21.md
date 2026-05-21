# TShark 4.6.5 Field Compatibility

- Author: Codex
- Timestamp: 2026-05-21 15:23:49 +08:00

## Scope

This round compared TShark/Wireshark 4.6.4 and 4.6.5 display-filter field registries, then fixed the only project-facing compatibility gap found in the current backend field capability set.

## Latest Document Review

Reviewed the newest development reports before implementation:

- `docs/audit-development-report-archive-2026-05-21/winrm-no-preview-diagnostic-result-2026-05-21.md`
- `docs/audit-development-report-archive-2026-05-21/frontend-packet-color-shader-refinement-2026-05-21.md`
- `docs/audit-development-report-archive-2026-05-21/frontend-workspace-packet-table-and-menu-refinement-2026-05-21.md`

Review conclusion:

- The latest WinRM report correctly generalized the field problem into the TShark scan/fallback layer instead of treating it as a WinRM-only defect.
- The latest frontend reports only touched packet table/menu visual surfaces and did not change backend TShark field contracts.
- This round could stay scoped to backend TShark capability aliases, tests, README wording, and field-diff documentation.

## Field Diff Method

Used official Wireshark/TShark artifacts and the local installed 4.6.5 binary:

- 4.6.4: downloaded `WiresharkPortable64_4.6.4.paf.exe` from Wireshark official all-versions download path and extracted `App\Wireshark\tshark.exe`.
- 4.6.5: used local `C:\Program Files\Wireshark\tshark.exe`.
- Ran `tshark -G fields` for both versions, parsed `F` records by field abbreviation, sorted unique field names, then compared sets.
- Official references checked:
  - Wireshark download page: https://www.wireshark.org/download.html
  - Wireshark 4.6.5 release notes: https://www.wireshark.org/docs/relnotes/wireshark-4.6.5.html
  - TShark man page: https://www.wireshark.org/docs/man-pages/tshark.html
  - SCSI Display Filter Reference: https://www.wireshark.org/docs/dfref/s/scsi.html
  - UDS Display Filter Reference: https://www.wireshark.org/docs/dfref/u/uds.html

The TShark man page documents `-G fields[,prefix]` as the display-filter field registration dump, with field abbreviation in the third tab-delimited column.

## Diff Result

Observed versions:

- `TShark (Wireshark) 4.6.4 (v4.6.4-0-g93282876538d).`
- `TShark (Wireshark) 4.6.5 (v4.6.5-0-gb40c46f83867).`

Counts:

- 4.6.4 unique fields: 268133
- 4.6.5 unique fields: 267752
- Added in 4.6.5: 3
- Removed in 4.6.5: 384

Added fields:

- `dect_nr.dlc.routing.sn`
- `dlms.compact_array.bad`
- `uds.length.invalid`

Removed fields are concentrated in Stratoshark/Falco/cloud telemetry families, not in fields currently requested by GShark's packet, USB, C2, WinRM, media, vehicle, or industrial scanners:

- `proc.*`: 112
- `evt.*`: 68
- `ct.*`: 54
- `ka.*`: 39
- `fd.*`: 36
- `gcp.*`: 27
- `thread.*`: 14
- Smaller removed groups include `fdlist.*`, `fs.*`, `user.*`, `s3.*`, `iam.*`, `ec2.*`, `ecr.*`, `falcoevents.*`, `group.*`, and two `ieee17221.*` fields.

## Project Compatibility Finding

The current project compatibility list still named `usbms.scsi.opcode` as an optional USB Mass Storage field. On both 4.6.4 and 4.6.5:

- `usbms.scsi.opcode` is absent.
- `scsi.spc.opcode` is present.

The USB analysis scanner already requests `scsi.spc.opcode`, so packet analysis itself was using the stable field. The runtime capability probe, however, could still show `usbms.scsi.opcode` as missing and incorrectly mark the TShark profile as `compat`.

## Changes

- Updated `backend/internal/tshark/capabilities.go`.
  - Added `usbms.scsi.opcode -> scsi.spc.opcode` to `capabilityFieldAliases`.
  - 4.6.5 no longer reports a false optional-field degradation when the stable SCSI opcode field is present.
- Updated `backend/internal/tshark/capabilities_test.go`.
  - Added runtime capability coverage proving `scsi.spc.opcode` satisfies the legacy `usbms.scsi.opcode` capability name.
- Updated `backend/internal/tshark/analysis_helpers_test.go`.
  - Added field-scan planner coverage proving requested `usbms.scsi.opcode` resolves to emitted `scsi.spc.opcode` and projects back into the caller layout.
- Updated `README.md`.
  - Replaced the old `usbms.scsi.opcode` degradation example with an explicit note that 4.6.5 uses `scsi.spc.opcode` and the backend aliases the legacy request name.

## Validation

Passed:

```powershell
cd backend
go test ./internal/tshark -run "TestCurrentCapabilitiesAccepts|TestPlanFieldScanByCapabilitiesUses|TestBuildCapabilities_OptionalFieldDegradation"
```

Manual 4.6.5 probe confirmed:

- `usbms.scsi.opcode`: absent
- `scsi.spc.opcode`: present
- `dect_nr.dlc.routing.sn`: present
- `dlms.compact_array.bad`: present
- `uds.length.invalid`: present

## Self Review

- The compatibility fix is intentionally an alias in the generic capability layer, not a USB-analysis special case.
- No scanner output schema, API route, frontend mapper, or UI behavior was changed.
- The 4.6.5 added fields are documented but not added to scanners because no current feature requests them.
- The removed 4.6.5 fields do not overlap current backend-requested field sets; no extra degradation rules were needed.
- The previous WinRM fallback work remains correct: `mime_multipart.data` is absent on these builds, so HTTP body extraction must continue using stable fallback fields and non-empty payload checks.
