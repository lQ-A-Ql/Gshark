# Public Sample Corpus - 2026-05-06

Author: Codex

Timestamp: 2026-05-06 20:36:55 +08:00

## Goal

Collect a modest, reproducible public PCAP set for blue-team validation of the current GShark analysis modules without downloading malware binaries or large research datasets. This corpus is meant to supplement the user's local CS, VShell, WebShell, Modbus, CAN, HTTP, and object samples.

## Collection Policy

- Download small PCAP/PCAPNG/CAP files only.
- Prefer stable public teaching captures with clear protocol intent.
- Avoid password-protected malware archives and executable payload bundles.
- Keep C2/malware public datasets as references unless a later validation task explicitly requires them.
- Treat licensing/provenance as source-specific; do not package or redistribute the corpus before reviewing each source's terms.

## Downloaded Local Corpus

Root: `samples/public-pcaps/`

Source used for the downloaded files: Wireshark SampleCaptures, https://wiki.wireshark.org/SampleCaptures

| Module focus | Local files | What they cover |
| --- | --- | --- |
| USB | `usb/usb_memory_stick.pcap`, `usb/usb_memory_stick_create_file.pcap`, `usb/usb_memory_stick_delete_file.pcap` | USB Mass Storage mount, create/write, delete. Useful for USB evidence write-path checks and benign USB baseline. |
| Industrial | `industrial/s7comm_downloading_block_db1.pcap`, `industrial/s7comm_reading_setting_plc_time.pcap`, `industrial/dnp3_select_operate.pcap`, `industrial/dnp3_write.pcap` | S7COMM and DNP3 operations. Useful for protocol parsing, write/select-operate detection, and severity calibration. |
| Object / HTTP | `object/http_gzip.cap`, `object/http_with_jpegs.cap.gz`, `object/tftp_wrq.pcap` | HTTP gzip, HTTP JPEG transfer, and TFTP write request. Useful for object extraction, MIME/magic reconciliation, and transfer direction checks. |
| Benign baseline | `benign/http.cap`, `benign/smtp.pcap`, `benign/mysql_complete.pcap` | Small ordinary HTTP, SMTP, and MySQL sessions for false-positive pressure. |
| Vehicle baseline | `vehicle/caneth.pcapng` | CAN-ETH sample for parser smoke testing. This is not a UDS/DoIP diagnostic sample. |

Detailed frame counts, protocols, and SHA256 hashes are recorded in `samples/public-pcaps/README.md`.

## External Sources Worth Tracking

| Source | URL | Use | Current decision |
| --- | --- | --- | --- |
| Wireshark SampleCaptures | https://wiki.wireshark.org/SampleCaptures | Small protocol teaching captures across USB, HTTP, ICS, CAN, SMTP, MySQL, TFTP | Downloaded selected small files. |
| Netresec public PCAP index | https://www.netresec.com/?page=PcapFiles | Curated links to many public traffic datasets | Reference only for now; some datasets are large or malware-oriented. |
| Malware-Traffic-Analysis.net | https://www.malware-traffic-analysis.net/ | Malware/C2 traffic exercises, including some Cobalt Strike cases | Do not auto-download now; password-protected archives and malware-lab provenance require explicit scope. |

## Threat Corpus

Root: `samples/threat-pcaps/`

Manifest: `samples/threat-pcaps/manifest.json`

Current state:

- CS: one public Cobalt Strike-related PCAP downloaded from Malware-Traffic-Analysis.net and verified locally. Manifest entry: `mta-2021-06-15-hancitor-ficker-cobalt-strike`.
- VShell: no stable public direct-download PCAP identified yet; manifest keeps a pending slot and falls back to the user's authorized local VShell sample for regression.

Manifest fields:

- `family`
- `sourceUrl`
- `localPath`
- `sha256`
- `bytes`
- `status`
- `skippedReason`
- `licenseNote`
- `knownKeys`
- `expected`

Download policy:

- ZIP sources allowed only when archive entries are PCAP/CAP/PCAPNG.
- Executable and script entries are rejected.
- Samples are never executed.

## Coverage Against Current Gaps

Resolved or improved:

- Benign baseline: covered by small HTTP, SMTP, MySQL captures.
- USB Mass Storage: covered by mount/create/delete captures.
- Industrial non-Modbus breadth: covered by S7COMM and DNP3 captures.
- Object/HTTP extraction: covered by gzip, JPEG, and TFTP transfer captures.
- Vehicle parser baseline: covered by CAN-ETH capture.
- CS threat corpus: one public CS PCAP is now staged under `samples/threat-pcaps/cs/` for regression use.

Still missing:

- Vehicle UDS/DoIP diagnostic PCAP with `0x10`, `0x27`, negative responses, request-only transactions, and orphan responses.
- Object masquerade PCAPs such as `.txt` carrying PE, `.bin` carrying PDF/ZIP, or HTTP upload/download with mismatched extension and magic bytes.
- Public VShell PCAP with stable direct download.
- Additional benign baseline with large normal web browsing or mixed enterprise traffic if false-positive pressure needs to be stronger.

## Suggested Harness Mapping

Use environment-variable-gated tests rather than hardcoding the downloaded files:

| Env var | Suggested local value | Assertion style |
| --- | --- | --- |
| `GSHARK_PUBLIC_USB_CREATE` | `samples/public-pcaps/usb/usb_memory_stick_create_file.pcap` | USB analysis identifies Mass Storage write activity; Evidence does not overpromote mount-only traffic. |
| `GSHARK_PUBLIC_USB_DELETE` | `samples/public-pcaps/usb/usb_memory_stick_delete_file.pcap` | Delete baseline parses cleanly without being reported as a write exfil signal. |
| `GSHARK_PUBLIC_S7_BLOCK_DOWNLOAD` | `samples/public-pcaps/industrial/s7comm_downloading_block_db1.pcap` | Industrial analysis parses S7COMM and assigns bounded severity. |
| `GSHARK_PUBLIC_DNP3_WRITE` | `samples/public-pcaps/industrial/dnp3_write.pcap` | Industrial analysis recognizes DNP3 write semantics without marking all traffic critical. |
| `GSHARK_PUBLIC_HTTP_JPEG` | `samples/public-pcaps/object/http_with_jpegs.cap.gz` | Object extraction surfaces image content and MIME/magic consistency. |
| `GSHARK_PUBLIC_BENIGN_HTTP` | `samples/public-pcaps/benign/http.cap` | C2/WebShell/Object heuristics should stay low-noise on ordinary HTTP. |
| `GSHARK_PUBLIC_CANETH` | `samples/public-pcaps/vehicle/caneth.pcapng` | Vehicle analysis runs without false UDS/DoIP high-risk evidence. |

## Validation Performed

Local tooling:

```powershell
capinfos -c -M <file>
tshark -r <file> -T fields -e _ws.col.Protocol -c 80
Get-FileHash -Algorithm SHA256 <file>
```

Result: all 14 downloaded files were readable with Wireshark/tshark 4.6.4. No business logic tests were added in this collection-only pass.

## Next Step

Add an optional backend real-sample test file that reads the `GSHARK_PUBLIC_*` variables above, skips when absent, and records module-specific assertions. Keep MISC WebShell tests outside unified Evidence unless the user explicitly changes that boundary.
