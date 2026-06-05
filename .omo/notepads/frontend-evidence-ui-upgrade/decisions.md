# Decisions

## 2026-06-04 Session start
- Use light-theme, high-density investigation UI.
- Treat Task 1 contract fixtures as the gate before Evidence model/UI expansion.
- Specialty features should be embedded widgets/sections in existing pages, not new routes.

## 2026-06-04 Task 6 JA3 seam
- Chosen seam: surface JA3 / JA3S in the existing workspace selected-packet detail pane (`HexAsciiPanel`) instead of C2 aggregate pages or the TLS decryption dialog.
- Rationale: backend already exposes packet-level `tls_fingerprint`; the workspace packet detail panel is the only existing frontend surface that always has the selected packet model, uses established tile/chip/status primitives, and avoids inventing a new route or implying TLS decryption is required.
- Empty behavior: only render fingerprint values when present; for TLS / HTTPS packets without fingerprint material, show a clear availability note that the current packet did not expose JA3 / JA3S data.
