# Backend Engineering Audit Spec - 2026-05-14

Author: OpenCode

Timestamp: 2026-05-14 23:07:29 +08:00

## 1. Background

GShark-Sentinel backend has moved from rapid feature accumulation into an engineering-governance phase. Current versioned documentation says the project direction remains offline traffic analysis, protocol-specific investigation, dangerous-application triage, and evidence-chain workbench delivery.

This spec audits the current backend engineering position and defines the next executable task plan. It treats `docs/README.md`, `docs/governance-defect-register.json`, and interface documents as current facts. Historical `docs/audit-development-report-archive-*` reports are used only as local evidence trails.

## 2. Current Facts

- Backend is a separate Go module under `backend/`, module path `github.com/gshark/sentinel/backend`, Go `1.25.0`.
- HTTP transport uses `net/http.ServeMux` in `backend/internal/transport/http_server.go`.
- Transport already depends on focused service interfaces in `backend/internal/transport/services.go` instead of a single direct engine surface.
- Core runtime state remains concentrated in `backend/internal/engine/service.go`.
- Shared model, domain, wire, tool, plugin, and MISC types remain concentrated in `backend/internal/model/types.go`.
- Architecture checks exist in `backend/internal/architecture/boundary_test.go`.
- Governance register checks exist in `backend/internal/governance/defect_register.go` and related tests.
- TShark capability degradation, field-scan cache key determinism, and LRU behavior are covered by focused tests and property tests.
- Plugin local execution requires `exec.local` capability in `backend/internal/plugin`.
- MISC packages support JavaScript and Python backends through `backend/internal/miscpkg`, with zip size limits, path validation, execution timeout, and host bridge support.
- The canonical governance register currently keeps `P2-6` open: mapper schema/codegen feasibility after WireDTO gates.

## 3. Engineering Assessment

| Dimension | Score | Assessment |
|---|---:|---|
| Architecture boundaries | 78/100 | Good guardrails exist for model imports, transport/tshark separation, report purity, evidence ownership, and report metadata ownership. Large service and transport files remain the main complexity risk. |
| Testability | 86/100 | Backend has focused tests across engine, transport, governance, plugin, miscpkg, tshark, YARA, public samples, and property tests. Missing area is stable response-contract coverage for core HTTP payloads. |
| Runtime reliability | 80/100 | Capture run IDs, cancellation, field degradation, cache eviction, and external command contexts are present. Some collectors and wrappers still need clearer context-boundary policy. |
| Security boundaries | 76/100 | Plugin `exec.local` is a strong boundary. MISC script execution has practical limits but still needs an explicit trust model and permission roadmap. |
| API contract maturity | 70/100 | Frontend WireDTO gates improved consumer-side safety. Backend still lacks schema/snapshot contract gates that anchor JSON shapes at the producer side. |
| Maintainability | 74/100 | Focused interface split and helper extraction reduced some risk. `engine.Service`, `transport.Server`, and `model/types.go` still carry broad responsibilities. |
| Overall | 78/100 | Backend governance is real and test-backed. Next work should focus on API contracts, context gates, and small ownership slices rather than broad rewrites. |

## 4. Primary Risks

### 4.1 API/domain/wire type mixing

`backend/internal/model/types.go` contains domain values, HTTP response shapes, runtime config, plugin/MISC contracts, and dynamic payload fields. This makes frontend WireDTO alignment depend heavily on manual discipline.

Risk indicators:

- `P2-6` remains open in `docs/governance-defect-register.json`.
- Backend response shapes do not yet have a broad contract snapshot/schema gate.
- Dynamic `any` and `map[string]any` boundaries exist for packet layers, decoded payloads, and plugin/MISC outputs.

### 4.2 Wide engine service ownership

`engine.Service` owns capture lifecycle, packet storage, display-filter cache, stream cache, traffic analysis, protocol analysis, media, speech, YARA, C2/APT, plugin, MISC-facing state, tool runtime config, and export paths.

Risk indicators:

- New features can easily add more state to the same struct.
- Lock ownership is hard to reason about globally.
- Focused tests exist, but internal state ownership is not consistently isolated by domain.

### 4.3 Wide transport implementation

`transport.Server` already has focused service interfaces, but `http_server.go` still mixes routing, auth, audit, uploads, events, capture, packet/stream, tools, media, plugin, MISC, and analysis handlers.

Risk indicators:

- Route behavior is easy to accidentally change while editing unrelated handlers.
- Handler-level context requirements are not machine-enforced yet.

### 4.4 Context propagation policy is partially social

Important HTTP paths already use context-aware calls. The rule that new HTTP handlers must call `WithContext` variants for long-running operations is documented, but not yet fully enforced by architecture tests.

Risk indicators:

- Future handlers can regress to no-context engine methods.
- Desktop synchronous wrappers legitimately use `context.Background()`, so exceptions need clear naming or comments.

### 4.5 Script execution governance needs a single model

Plugin execution has explicit `exec.local`. MISC packages have practical execution controls, but their trust boundary is not yet stated as a unified governance model.

Risk indicators:

- MISC JavaScript/Python backends are local code execution.
- Host bridge methods expose selected backend capabilities.
- Documentation should avoid implying a strong sandbox.

## 5. Goals

- Add backend-side API contract baselines for core HTTP responses.
- Make context/cancellation rules enforceable for HTTP handlers.
- Reduce transport and engine complexity through small, behavior-preserving slices.
- Clarify model/wire/domain ownership without a large package migration.
- Clarify Plugin and MISC script execution trust boundaries.
- Keep mainline analysis correctness and false-positive calibration ahead of pure structural cleanup.

## 6. Non-Goals

- Do not replace `net/http.ServeMux`.
- Do not introduce a large backend framework.
- Do not rewrite `engine.Service` in one pass.
- Do not change MISC vs unified Evidence product boundary without explicit product direction.
- Do not add backward compatibility code unless concrete persisted data, external consumers, shipped behavior, or explicit user requirements demand it.
- Do not treat historical local archive reports as canonical current facts.

## 7. Task Plan

### Epic 0: Spec and report baseline

| Task | Title | Deliverable | Acceptance |
|---|---|---|---|
| SPEC-0.1 | Create backend engineering audit spec | `docs/backend-engineering-audit-spec-2026-05-14.md` | Includes background, current facts, assessment, risks, task plan, and validation rules. |
| SPEC-0.2 | Align with governance register | Same spec | Calls out `P2-6` as the current open contract/schema/codegen item. |
| SPEC-0.3 | Define non-goals | Same spec | Prevents framework swap, broad rewrites, and MISC/Evidence boundary drift. |
| SPEC-0.4 | Add score and risk matrix | Same spec | Backend score maps to concrete files and follow-up tasks. |
| REPORT-0.1 | Append first backend report | `docs/audit-development-report-archive-2026-05-14/backend-engineering-report-2026-05-14.md` | Records changes, validation, self-review, score, and next step. |

### Epic 1: Backend API contract baseline

| Task | Title | Primary Files | Acceptance |
|---|---|---|---|
| BE-CONTRACT-1.1 | Inventory core endpoint response shapes | `backend/internal/transport/http_server.go`, `backend/internal/model/types.go` | Lists first-wave endpoints and response models. |
| BE-CONTRACT-1.2 | Choose contract test strategy | `backend/internal/transport/*_test.go` | Documents whether first wave uses JSON key assertions, snapshots, schema-like assertions, or generated schema. |
| BE-CONTRACT-1.3 | Add capture/packet contract tests | Transport tests | Covers `/api/capture/status`, `/api/packets/page`, `/api/packet`. |
| BE-CONTRACT-1.4 | Add stream contract tests | Transport tests | Covers `/api/streams/index`, `/api/packet/raw`, `/api/packet/layers`. |
| BE-CONTRACT-1.5 | Add evidence contract tests | Transport or engine tests | Covers `/api/evidence` records, total, notes, and module filtering. |
| BE-CONTRACT-1.6 | Add analysis contract tests | Transport or engine tests | Covers industrial, vehicle, USB, and C2 sample high-value fields. |
| BE-CONTRACT-1.7 | Register dynamic response boundaries | Model or contract test helper | Explicitly permits packet layers, decoder options, parsed payloads, and plugin/MISC outputs where dynamic JSON is intentional. |
| BE-CONTRACT-1.8 | Record schema/codegen decision | This spec or follow-up doc | Recommends handwritten DTO, JSON Schema, OpenAPI, or TypeScript generation path for `P2-6`. |

### Epic 2: Transport complexity reduction

| Task | Title | Primary Files | Acceptance |
|---|---|---|---|
| BE-TRANSPORT-2.1 | Add route behavior baseline | `backend/internal/transport/http_server_test.go` | Key routes, methods, auth, and audit behavior remain stable. |
| BE-TRANSPORT-2.2 | Move capture handlers | New `capture_handlers.go` | Behavior unchanged; `go test ./internal/transport -count=1` passes. |
| BE-TRANSPORT-2.3 | Move packet/stream handlers | New `packet_stream_handlers.go` | Raw/page/decode/inspect/payload routes unchanged. |
| BE-TRANSPORT-2.4 | Move analysis handlers | New `analysis_handlers.go` | Industrial, vehicle, USB, C2, APT, and evidence routes unchanged. |
| BE-TRANSPORT-2.5 | Move tool handlers | New `tool_handlers.go` | Runtime, TShark, FFmpeg, TLS, NTLM, SMTP, MySQL, Shiro routes unchanged. |
| BE-TRANSPORT-2.6 | Move media handlers | New `media_handlers.go` | Media export/play/transcribe/batch routes unchanged. |
| BE-TRANSPORT-2.7 | Review plugin/MISC handler boundary | Existing or new plugin/misc files | Plugin and MISC tests pass; no route drift. |

### Epic 3: Context and cancellation gate

| Task | Title | Primary Files | Acceptance |
|---|---|---|---|
| BE-CONTEXT-3.1 | Audit current handler context usage | `backend/internal/transport` | Produces list of long-running calls and accepted exceptions. |
| BE-CONTEXT-3.2 | Add architecture context boundary test | `backend/internal/architecture/boundary_test.go` | Fails if HTTP handlers call known long-running no-context methods. |
| BE-CONTEXT-3.3 | Strengthen evidence collector cancellation | `backend/internal/engine/evidence*.go` | Long loops or expensive collectors check `ctx.Done()`. |
| BE-CONTEXT-3.4 | Classify tool analysis context needs | `backend/internal/engine/tool_*.go` | Identifies which tools need `WithContext` variants. |
| BE-CONTEXT-3.5 | Mark desktop wrapper exceptions | Engine wrapper methods | `context.Background()` remains only in short probes or desktop synchronous wrappers. |
| BE-CONTEXT-3.6 | Add cancellation regression tests | Engine or transport tests | Request cancellation does not block replacement or long-running media/tool paths. |

### Epic 4: Engine state ownership

| Task | Title | Primary Files | Acceptance |
|---|---|---|---|
| BE-ENGINE-4.1 | Document service state groups | `backend/internal/engine/service.go` or spec follow-up | Fields grouped by owner: capture, packet store, stream, analysis cache, media, speech, tool runtime, hunting/YARA. |
| BE-ENGINE-4.2 | Isolate capture load owner helpers | `service.go` capture load methods | Existing capture load and cancellation tests pass. |
| BE-ENGINE-4.3 | Isolate stream cache owner helpers | Stream cache methods | Stream cache update and limit behavior remains covered. |
| BE-ENGINE-4.4 | Complete tool runtime owner tests | `tool_runtime.go` | Config round-trip and env consistency remain stable. |
| BE-ENGINE-4.5 | Isolate media speech batch owner | `speech_to_text.go` | Batch start/cancel/export tests pass. |
| BE-ENGINE-4.6 | Isolate hunting/YARA config owner | Hunting/YARA files | Config and scan tests pass. |

### Epic 5: Model and wire ownership

| Task | Title | Primary Files | Acceptance |
|---|---|---|---|
| BE-MODEL-5.1 | Classify model types | `backend/internal/model/types.go` | Types are classified as domain, wire response, config, plugin/MISC, or dynamic. |
| BE-MODEL-5.2 | Split model file by domain | `backend/internal/model/*.go` | Package remains `model`; public names and JSON behavior unchanged. |
| BE-MODEL-5.3 | Centralize dynamic payload comments | Model dynamic sections | `any` positions are explained and tied to contract tests. |
| BE-MODEL-5.4 | Evaluate separate wire package | Follow-up doc or spike | Decision recorded before any package migration. |
| BE-MODEL-5.5 | Add JSON tag consistency checks | Model tests | Core response structs have expected JSON names. |

### Epic 6: TShark reliability guardrails

| Task | Title | Primary Files | Acceptance |
|---|---|---|---|
| BE-TSHARK-6.1 | Audit field-plan usage | `backend/internal/tshark` | New scan paths use existing planning/degradation helpers. |
| BE-TSHARK-6.2 | Expand capability matrix tests | `capabilities*_test.go` | Required, optional, and display fields keep expected profile severity. |
| BE-TSHARK-6.3 | Review cache observability | `field_scan_cache.go` | Cache behavior remains bounded and explainable. |
| BE-TSHARK-6.4 | Stress LRU properties | `cache_capacity_property_test.go` | Random access and eviction maintain map/list consistency. |

### Epic 7: Script execution governance

| Task | Title | Primary Files | Acceptance |
|---|---|---|---|
| BE-SCRIPT-7.1 | Document script execution trust model | `docs/misc-module-interface.md` or follow-up doc | States Plugin/MISC are local trusted extension points, not strong sandboxes. |
| BE-SCRIPT-7.2 | Design MISC permission model | `docs/misc-module-interface.md` | Candidate permissions include `exec.local`, `capture.read`, and `field.scan`. |
| BE-SCRIPT-7.3 | Add host bridge method registry test | `backend/internal/miscpkg/manager_test.go` | Unknown host bridge methods fail; known methods remain covered. |
| BE-SCRIPT-7.4 | Strengthen MISC import safety tests | `backend/internal/miscpkg/manager_test.go` | Zip slip, invalid ID, too many files, and oversize payloads fail. |
| BE-SCRIPT-7.5 | Keep plugin permission parity tests | `backend/internal/plugin/manager_test.go` | JS/Python execution remains blocked without `exec.local`. |

### Epic 8: Real sample and false-positive baselines

| Task | Title | Primary Files | Acceptance |
|---|---|---|---|
| BE-SAMPLE-8.1 | Align public sample matrix | `docs/public-sample-corpus-2026-05-06.md`, engine tests | Each public sample has an explicit assertion or opt-in reason. |
| BE-SAMPLE-8.2 | Add HTTP/Object benign baselines | Engine public sample tests | Benign object/HTTP traces do not escalate to high/critical evidence. |
| BE-SAMPLE-8.3 | Add USB false-positive baselines | USB tests | Mount, delete, and write paths remain distinguishable. |
| BE-SAMPLE-8.4 | Add Industrial/Vehicle richer baselines | TShark/engine tests | UDS, DoIP, Modbus, and CAN rules avoid over-triggering. |
| BE-SAMPLE-8.5 | Keep true threat samples opt-in | `real_sample_validation_test.go` | Local sensitive samples run only through environment variables. |

## 8. Recommended Implementation Order

1. Finish Epic 0 so later work has a stable spec and report baseline.
2. Start Epic 1 with `BE-CONTRACT-1.1` through `BE-CONTRACT-1.5` to address the backend side of `P2-6`.
3. Add `BE-CONTEXT-3.1` and `BE-CONTEXT-3.2` before more handler work.
4. Perform transport file splitting only after route and contract baselines exist.
5. Document script execution trust before changing MISC package schema.
6. Split `model/types.go` only after first-wave contract tests identify stable wire/domain seams.
7. Defer broad engine state ownership work until the API contract and context gates are stable.

## 9. Validation Policy

Use focused commands for each task, then broader commands at phase boundaries.

- `cd backend && gofmt -l .`
- `cd backend && go test ./internal/architecture -count=1`
- `cd backend && go test ./internal/governance -count=1`
- `cd backend && go test ./internal/transport -count=1`
- `cd backend && go test ./internal/engine -count=1`
- `cd backend && go test ./...`
- `./scripts/check-all.ps1` at phase completion

Documentation-only rounds should at minimum run `git diff --check` before handoff.

## 10. Reporting Rule

Every implementation round must append to `docs/audit-development-report-archive-2026-05-14/backend-engineering-report-2026-05-14.md` or the current actual-date backend engineering report.

Each entry must include:

- Round goal.
- Files changed.
- Validation commands and results.
- Self-review findings.
- Remaining risks.
- Next recommended task.
- Engineering score.

## 11. First Executable Slice

The first slice is documentation-only:

- `SPEC-0.1`
- `SPEC-0.2`
- `SPEC-0.3`
- `SPEC-0.4`
- `REPORT-0.1`

No backend code should change in this slice.

## 12. Core Endpoint Contract Inventory

Status: `BE-CONTRACT-1.1` completed on 2026-05-14 23:17:13 +08:00.

This inventory records the first-wave backend HTTP responses that should receive contract tests before broader transport or model refactoring. It intentionally starts with mainline capture, packet, stream, evidence, and protocol-analysis paths because these are the surfaces most likely to drift against frontend WireDTOs.

| Endpoint | Handler | Method Policy | Success Response Source | Contract Priority | Notes |
|---|---|---|---|---|---|
| `/api/capture/status` | `handleCaptureStatus` | GET only | `model.CaptureStatus` | P0 | Small stable response; good first contract test. |
| `/api/packets` | `handlePackets` | Currently no explicit method gate | `[]model.Packet` | P1 | Legacy full-list endpoint; lower priority than paged path. |
| `/api/packets/page` | `handlePacketsPage` | Currently no explicit method gate | `packetsPageResponse` with `[]model.Packet` | P0 | Core packet-table contract: `items`, `next_cursor`, `total`, `has_more`, `filtering`. |
| `/api/packets/locate` | `handlePacketLocate` | Currently no explicit method gate | inline object: `packet_id`, `cursor`, `total`, `found` | P0 | Inline shape should become a named response type or contract fixture. |
| `/api/packet` | `handlePacket` | Currently no explicit method gate | `model.Packet` | P0 | Core packet detail response. |
| `/api/packet/raw` | `handlePacketRaw` | Currently no explicit method gate | inline object: `packet_id`, `raw_hex` | P0 | Inline shape should be covered directly because frontend already has a WireDTO for it. |
| `/api/packet/layers` | `handlePacketLayers` | Currently no explicit method gate | inline object: `packet_id`, `layers` | P0 | `layers` is intentionally dynamic JSON from packet dissection; whitelist as dynamic boundary. |
| `/api/streams/index` | `handleStreamIndex` | Currently no explicit method gate; validates protocol query | inline object: `protocol`, `total`, `ids` | P0 | Small stable response; validates HTTP/TCP/UDP only. |
| `/api/evidence` | `handleEvidence` | Currently no explicit method gate | `model.EvidenceResponse` | P0 | Main evidence contract; supports `modules` query filter. |
| `/api/analysis/industrial` | `handleIndustrialAnalysis` | Currently no explicit method gate | `model.IndustrialAnalysis` | P1 | Mainline report/evidence-adjacent response; large nested shape. |
| `/api/analysis/vehicle` | `handleVehicleAnalysis` | Currently no explicit method gate | `model.VehicleAnalysis` | P1 | Mainline vehicle response; large nested shape. |
| `/api/analysis/usb` | `handleUSBAnalysis` | Currently no explicit method gate | `model.USBAnalysis` | P1 | Mainline USB response with report payload. |
| `/api/c2-analysis` | `handleC2Analysis` | Currently no explicit method gate; uses request context | `model.C2SampleAnalysis` | P1 | Context-aware and mainline threat-analysis response. |

### First-Wave Contract Test Targets

The first backend contract test slice should cover these endpoints in order:

1. `/api/capture/status`
2. `/api/packets/page`
3. `/api/packet`
4. `/api/packets/locate`
5. `/api/packet/raw`
6. `/api/packet/layers`
7. `/api/streams/index`
8. `/api/evidence`

The first slice should prefer focused JSON-key and type assertions over full golden snapshots. These endpoints are small enough to assert required top-level keys without locking unrelated nested payload details too early.

### Dynamic JSON Boundaries

The following dynamic response fields are intentional and must be whitelisted before adding broad no-`any` gates:

- `/api/packet/layers`: response field `layers`, sourced from `CaptureService.PacketLayers(packetID) (map[string]any, error)`.
- Stream payload candidates and sources: `decoder_options_hint map[string]any`, used for decoder-specific options.
- C2 decrypt records: `parsed map[string]any`, used for family-specific parsed plaintext.
- Plugin and MISC outputs: `model.Plugin`, `model.MiscModuleRunResult`, and MISC table/details outputs can carry user-defined script results.

### Contract Gaps Found During Inventory

- Several read endpoints do not explicitly reject non-GET methods. This is current behavior and should not be changed during the first contract test slice unless a separate transport behavior task is opened.
- `packetsPageResponse` is named, but locate/raw/layers/stream-index responses are inline `map[string]any`; tests should lock their JSON keys before any optional named-type cleanup.
- Large analysis responses should not be snapshot-locked in full yet. Their contract tests should first assert stable top-level fields and the shared `report` field where present.

## 13. First-Wave Contract Test Strategy

Status: `BE-CONTRACT-1.2` completed on 2026-05-14 23:20:03 +08:00.

Existing transport tests in `backend/internal/transport/http_server_test.go` already use direct handler invocation with `httptest.NewRequest`, `httptest.NewRecorder`, and JSON decoding into either concrete model structs or `map[string]any`. The first-wave contract tests should extend this style instead of introducing a new framework or golden snapshot system.

### Chosen Strategy

- Use direct handler tests for small, stable endpoints.
- Decode response bodies into `map[string]any` for inline response shapes.
- Decode response bodies into concrete `model.*` structs only when the endpoint already returns a named model type and the test is checking semantic defaults.
- Assert required top-level JSON keys, key types, and key presence.
- Do not full-snapshot large nested analysis responses in the first wave.
- Do not change method behavior while adding contract tests; method-policy changes belong in separate transport behavior tasks.

### Helper Shape

If repeated assertions grow, add small local helpers in `http_server_test.go` or a dedicated transport contract test file:

- `decodeJSONMap(t, rec) map[string]any`
- `requireJSONKeys(t, payload, keys...)`
- `requireJSONNumber(t, payload, key)` for JSON-decoded numbers (`float64` when decoded into `map[string]any`)
- `requireJSONArray(t, payload, key)`

Keep helpers test-local. Do not add production abstractions for test convenience.

### First Test File Recommendation

Add a focused file:

- `backend/internal/transport/http_contract_test.go`

Rationale:

- Avoid growing the existing broad `http_server_test.go` further.
- Keep endpoint shape tests grouped and easy to audit.
- Reuse `NewServer(engine.NewService(nil, nil), NewHub())` for empty-capture/default-state contracts.

### First Test Cases

| Test | Endpoint | Assertions |
|---|---|---|
| `TestCaptureStatusContract` | `/api/capture/status` | Status 200; keys `file_path`, `has_capture`, `packet_count`; method rejection remains covered by existing test. |
| `TestPacketsPageContract` | `/api/packets/page` | Status 200; keys `items`, `next_cursor`, `total`, `has_more`, `filtering`; `items` is array. |
| `TestPacketLocateContractRejectsInvalidID` | `/api/packets/locate` | Invalid id returns 400 with `error`; do not require loaded capture. |
| `TestStreamIndexContract` | `/api/streams/index?protocol=tcp` | Status 200; `protocol` is `TCP`; `total` numeric; `ids` array. |
| `TestPacketRawContractRejectsInvalidID` | `/api/packet/raw` | Invalid id returns 400 with `error`; success requires a loaded packet and should be added later with fixture setup. |
| `TestPacketLayersContractRejectsInvalidID` | `/api/packet/layers` | Invalid id returns 400 with `error`; success dynamic `layers` contract waits for packet fixture setup. |
| `TestEvidenceContractEmptyCapture` | `/api/evidence` | Status 200; keys `records`, `total`; `records` array; `notes` may be omitted. |

### Deferred Contract Tests

- Successful `/api/packet`, `/api/packet/raw`, and `/api/packet/layers` responses need a deterministic packet fixture or in-memory service stub.
- Large protocol-analysis responses should first get top-level key tests after the small endpoints land.
- Route-level auth/CORS/audit behavior should remain in existing tests unless contract tests start using `Server.Handler()` instead of direct handler invocation.

### Acceptance for `BE-CONTRACT-1.2`

- Strategy is documented.
- First test file and helper style are named.
- No production code is changed.
- Follow-up `BE-CONTRACT-1.3` can start with capture/packet page/evidence/stream-index tests.

## 14. First Contract Test Slice

Status: `BE-CONTRACT-1.3` first slice completed on 2026-05-14 23:24:45 +08:00.

The first executable contract-test slice adds backend transport JSON-shape tests for endpoints that do not need a loaded PCAP fixture.

Implemented test file:

- `backend/internal/transport/http_contract_test.go`

Covered contracts:

- `/api/capture/status`: success response contains `file_path`, `has_capture`, `packet_count` with expected JSON types.
- `/api/packets/page`: success response contains `items`, `next_cursor`, `total`, `has_more`, `filtering` with expected JSON types.
- `/api/streams/index?protocol=tcp`: success response normalizes protocol to `TCP` and contains `total` plus `ids`.
- `/api/evidence`: empty-capture success response contains `records` as an array and `total` as a number.
- `/api/packets/locate`, `/api/packet/raw`, `/api/packet/layers`: invalid IDs return a JSON error object.

Behavioral fix discovered by the contract tests:

- `backend/internal/engine/evidence.go` now initializes `records` as an empty slice so empty evidence responses encode `records: []` instead of `records: null`.

Validation:

- `cd backend && gofmt -l .` — PASS.
- `cd backend && go test ./internal/transport -run "Test.*Contract" -count=1` — PASS.
- `cd backend && go test ./internal/transport -count=1` — PASS.
- `cd backend && go test ./internal/engine -run TestGatherEvidence -count=1` — PASS.

Remaining deferred contract work:

- Large protocol analysis responses still need top-level shape tests.
- Method-policy behavior for read endpoints is still current behavior and remains out of scope for this contract slice.

## 15. Packet Inline Success Contract Slice

Status: `BE-CONTRACT-1.3/1.4` packet success slice completed on 2026-05-14 23:29:48 +08:00.

The second executable contract-test slice expands `backend/internal/transport/http_contract_test.go` with a minimal fake `CaptureService`. This avoids real PCAP files and TShark dependency while locking handler-level JSON response shapes.

New covered contracts:

- `/api/packet?id=7`: success response contains packet identity, addressing, protocol, length, info, payload, and stream fields.
- `/api/packets/locate?id=7&limit=50`: success response contains `packet_id`, `cursor`, `total`, and `found`.
- `/api/packet/raw?id=7`: success response contains `packet_id` and `raw_hex`.
- `/api/packet/layers?id=7`: success response contains `packet_id` and dynamic object `layers`.

Test approach:

- Use `contractCaptureService`, a test-local implementation of `CaptureService`.
- Keep the fake narrow and deterministic.
- Do not introduce production abstractions or sample fixtures for this slice.

Validation:

- `cd backend && gofmt -l "internal/transport/http_contract_test.go"` — PASS.
- `cd backend && go test ./internal/transport -run "Test.*Contract" -count=1` — PASS.
- `cd backend && go test ./internal/transport -count=1` — PASS.
- `cd backend && gofmt -l .` — PASS.

Remaining deferred contract work:

- Route-level method-policy behavior is still not changed by contract work.
- Future contract tests should avoid growing `contractCaptureService` into a broad mock; add smaller focused fakes for other service interfaces when needed.

## 16. Analysis Top-Level Contract Slice

Status: `BE-CONTRACT-1.6` first slice completed on 2026-05-14 23:36:37 +08:00.

This slice expands `backend/internal/transport/http_contract_test.go` with top-level contract tests for large analysis endpoints. It uses a separate `contractAnalysisService` fake so analysis contracts do not grow the packet/capture fake.

Covered contracts:

- `/api/analysis/industrial`: asserts top-level packet count, protocol/conversation arrays, `modbus`, `details`, `notes`, and `report` object.
- `/api/analysis/vehicle`: asserts top-level packet count, protocol/conversation arrays, `can`, `j1939`, `doip`, `uds`, `recommendations`, and `report` object.
- `/api/analysis/usb`: asserts top-level packet counters, protocol/record arrays, `hid`, `mass_storage`, `other`, `notes`, and `report` object.
- `/api/c2-analysis`: asserts top-level packet count, family/conversation arrays, `cs`, `vshell`, and `notes`.

Test approach:

- Use `contractAnalysisService`, a test-local implementation of `AnalysisService`.
- Assert only stable top-level shape for large responses.
- Do not snapshot nested protocol details yet.

Validation:

- `cd backend && gofmt -w "internal/transport/http_contract_test.go"` — applied formatting.
- `cd backend && go test ./internal/transport -run "Test.*Contract" -count=1` — PASS.
- `cd backend && go test ./internal/transport -count=1` — PASS.
- `cd backend && gofmt -l .` — PASS.
- `cd backend && go test ./internal/engine -run TestGatherEvidence -count=1` — PASS.

Remaining deferred contract work:

- Tool-analysis endpoints such as HTTP login, SMTP, MySQL, Shiro, and NTLM are not covered by first-wave mainline tests.
- Method-policy behavior is still not changed by contract work.
- Broader full backend tests should run before closing a phase.

## 17. Contract Phase Validation Status

Status: first backend contract phase validated on 2026-05-14 23:39:53 +08:00.

Validated scope:

- Contract tests for capture, packet page, packet detail, packet locate, packet raw, packet layers, stream index, evidence, industrial analysis, vehicle analysis, USB analysis, and C2 analysis.
- Evidence empty-list JSON behavior fixed and covered.
- Architecture and governance packages still pass after contract test additions.

Validation commands:

- `cd backend && gofmt -l .` — PASS.
- `cd backend && go test ./internal/transport ./internal/engine ./internal/architecture ./internal/governance -count=1` — PASS.
- `cd backend && go test ./...` — PASS.

Updated `BE-CONTRACT` status:

| Task | Status | Notes |
|---|---|---|
| `BE-CONTRACT-1.1` | Complete | Core endpoint inventory recorded in this spec. |
| `BE-CONTRACT-1.2` | Complete | First-wave direct handler + JSON key/type assertion strategy recorded. |
| `BE-CONTRACT-1.3` | Mostly complete | Capture, packet page, packet detail, locate, raw, and layers contracts covered. |
| `BE-CONTRACT-1.4` | Complete for listed first-wave endpoints | Stream index, packet raw, and packet layers contracts covered at handler level. |
| `BE-CONTRACT-1.5` | Complete for empty-capture baseline | Evidence response top-level contract covered; non-empty module-filter shape remains future enhancement. |
| `BE-CONTRACT-1.6` | First slice complete | Industrial, vehicle, USB, and C2 top-level response contracts covered. |
| `BE-CONTRACT-1.7` | Partially complete | Dynamic boundaries documented; no automated no-`any` backend gate yet. |
| `BE-CONTRACT-1.8` | Open | Schema/codegen decision still pending. |

Recommended next epic:

- Move to `BE-CONTEXT-3.1` and `BE-CONTEXT-3.2` before transport file splitting. Context gates reduce behavioral risk for future handler movement.

## 18. HTTP Handler Context Audit

Status: `BE-CONTEXT-3.1` completed on 2026-05-14 23:42:20 +08:00.

Audit scope:

- `backend/internal/transport/http_server.go`
- `backend/internal/transport/misc_package_handlers.go`
- `backend/internal/transport/services.go`

### Context-Aware Paths Already Correct

| Handler area | Calls | Assessment |
|---|---|---|
| Capture load | `BeginCaptureLoad(context.WithoutCancel(r.Context()))`, `LoadPCAPWithRun(loadCtx, ...)` | Intentional: capture load survives the upload/start request while remaining cancellable through replacement/close. |
| Threat hunting | `ThreatHuntWithContext(r.Context(), ...)` | Correct. |
| Object listing/export | `ObjectsWithContext(r.Context())`; export loop checks `r.Context().Err()` | Correct. |
| C2/APT/evidence | `C2SampleAnalysis(r.Context())`, `C2Decrypt(r.Context(), ...)`, `APTAnalysis(r.Context())`, `GatherEvidence(r.Context(), ...)` | Correct. |
| Media playback | `MediaPlaybackWithContext(r.Context(), ...)` | Correct. |
| Stream read/update | `HTTPStream`, `RawStream`, `RawStreamPage`, `UpdateStreamPayloads` use `r.Context()` | Correct. |
| Protocol tool analysis | HTTP login, SMTP, MySQL, Shiro use `r.Context()` | Correct. |
| MISC package invoke | `miscPkgMgr.Invoke(r.Context(), ...)` | Correct. |

### Context Gaps or Accepted Exceptions

| Handler area | Current calls | Classification | Follow-up |
|---|---|---|---|
| Global traffic stats | `GlobalTrafficStats()` | Gap candidate | Should gain `GlobalTrafficStatsWithContext(ctx)` or be explicitly classified as cache/short operation. |
| Industrial analysis | `IndustrialAnalysis()` | Gap candidate | Should gain context-aware variant before transport handler splitting. |
| Vehicle analysis | `VehicleAnalysis()` | Gap candidate | Should gain context-aware variant before transport handler splitting. |
| USB analysis | `USBAnalysis()` | Gap candidate | Should gain context-aware variant before transport handler splitting. |
| WinRM decrypt | `RunWinRMDecrypt(req)` | Gap candidate | Should gain context-aware variant if it runs external commands or long file scans. |
| NTLM session materials | `ListNTLMSessionMaterials()` | Review needed | May be fast enough, but should be classified. |
| SMB3 session candidates / random key | `ListSMB3SessionCandidates()`, `GenerateSMB3RandomSessionKey(req)` | Review needed | Key generation is likely short; candidate listing may scan capture data. |
| Media export/transcription/batch | `MediaArtifact`, `TranscribeMediaArtifact`, batch start/status/export/cancel | Mixed | Playback is context-aware; transcription wrapper should be reviewed separately because engine has internal context support. |
| Plugin CRUD/runtime config | plugin and tool runtime config methods | Accepted short/config operations | No context gate needed unless implementation becomes long-running. |
| `http.Server.Shutdown(context.Background())` | server shutdown goroutine | Accepted exception | Context is already triggered by parent cancellation; shutdown timeout may be a future hardening task but not an HTTP handler violation. |

### Recommended Architecture Gate Shape

`BE-CONTEXT-3.2` should add a focused architecture test that scans `backend/internal/transport/http_server.go` and fails on direct calls to known long-running no-context service methods inside handlers.

Initial disallowed call patterns:

- `.GlobalTrafficStats()`
- `.IndustrialAnalysis()`
- `.VehicleAnalysis()`
- `.USBAnalysis()`
- `.RunWinRMDecrypt(`

Initial allowed exceptions:

- Method declarations in `services.go` until context-aware variants are introduced.
- Test fakes in `http_contract_test.go`.
- Short/config operations such as `CaptureStatus`, `TSharkStatus`, `ToolRuntimeSnapshot`, plugin list/toggle, and audit log retrieval.

Recommended implementation order:

1. Add architecture test in report-only mode is not useful; it should fail only after code is migrated or use a documented skip list for current gaps.
2. Prefer adding context-aware service interface methods first for industrial, vehicle, USB, global stats, and WinRM.
3. Then add the architecture test to prevent regression.

This means `BE-CONTEXT-3.2` should likely be split into two slices: add `WithContext` variants and handler migration first, then add the hard gate.

## 19. Context-Aware Analysis Handler Migration

Status: `BE-CONTEXT-3.2a` completed on 2026-05-14 23:47:40 +08:00.

This slice adds context-aware variants for the first set of analysis handlers identified by the context audit, then migrates HTTP handlers to pass `r.Context()`.

Changed backend contracts:

- `AnalysisService.GlobalTrafficStatsWithContext(ctx context.Context)`
- `AnalysisService.IndustrialAnalysisWithContext(ctx context.Context)`
- `AnalysisService.VehicleAnalysisWithContext(ctx context.Context)`
- `AnalysisService.USBAnalysisWithContext(ctx context.Context)`

Engine behavior:

- Existing no-context methods remain as wrappers using `context.Background()` for desktop/legacy synchronous callers.
- New `WithContext` methods check `ctx.Err()` before expensive work and after field-cache warmup.
- Existing analysis output behavior is otherwise unchanged.

Transport behavior:

- `/api/stats/traffic/global` now calls `GlobalTrafficStatsWithContext(r.Context())`.
- `/api/analysis/industrial` now calls `IndustrialAnalysisWithContext(r.Context())`.
- `/api/analysis/vehicle` now calls `VehicleAnalysisWithContext(r.Context())`.
- `/api/analysis/usb` now calls `USBAnalysisWithContext(r.Context())`.

Validation:

- `cd backend && gofmt -w "internal/transport/services.go" "internal/transport/http_server.go" "internal/engine/service.go" "internal/transport/http_contract_test.go"` — PASS.
- `cd backend && go test ./internal/transport -run "Test.*Contract" -count=1` — PASS.
- `cd backend && go test ./internal/transport ./internal/engine -count=1` — PASS.
- `cd backend && gofmt -l .` — PASS.
- `cd backend && go test ./internal/architecture ./internal/governance -count=1` — PASS.

Remaining context gaps:

- `ListNTLMSessionMaterials()` and `ListSMB3SessionCandidates()` still need classification.
- Media transcription wrappers still need a focused review.
- Hard architecture context gate should wait until WinRM and classification gaps are resolved or explicitly allowlisted.

## 20. WinRM Context-Aware Migration

Status: `BE-CONTEXT-3.2b` completed on 2026-05-14 23:57:11 +08:00.

This slice migrates WinRM decrypt transport execution to a context-aware service path.

Changed backend contracts:

- `ToolAnalysisService.RunWinRMDecryptWithContext(ctx context.Context, req model.WinRMDecryptRequest)`

Engine behavior:

- Existing `RunWinRMDecrypt(req)` remains as a `context.Background()` wrapper for legacy synchronous callers.
- New `RunWinRMDecryptWithContext` checks `ctx.Err()` before validation/scanning and before decrypting scanned rows.
- `scanWinRMRowsWithContext` checks `ctx.Err()` before each field-set fallback attempt.
- The underlying `tshark.ScanFieldRowsWithDisplayFilter` helper still has no context parameter, so cancellation cannot interrupt an already-running field-scan subprocess yet.

Transport behavior:

- `/api/tools/winrm-decrypt` now calls `RunWinRMDecryptWithContext(r.Context(), req)`.

Validation:

- `cd backend && gofmt -l "internal/transport/services.go" "internal/transport/http_server.go" "internal/engine/tool_winrm.go"` — PASS.
- `cd backend && go test ./internal/transport ./internal/engine -count=1` — PASS.
- `cd backend && go test ./internal/architecture ./internal/governance -count=1` — PASS.
- `cd backend && gofmt -l .` — PASS.

Remaining context gaps:

- `ListNTLMSessionMaterials()` and `ListSMB3SessionCandidates()` still need classification.
- Media transcription wrappers still need a focused review.
- A deeper TShark field-scan context migration would require adding context-aware variants under `backend/internal/tshark/analysis_helpers.go`.
- Hard architecture context gate can now target the migrated analysis/WinRM call names and leave classified short operations allowlisted.

## 21. Context Boundary Regression Gate

Status: `BE-CONTEXT-3.2c` completed on 2026-05-15 00:02:00 +08:00.

This slice adds an architecture regression test that prevents migrated long-running transport handlers from calling the old no-context service methods.

Implemented gate:

- `backend/internal/architecture/boundary_test.go`
- Subtest: `transport handlers use context-aware long running service calls`

Forbidden call patterns in `backend/internal/transport/http_server.go`:

- `s.analysis.GlobalTrafficStats()`
- `s.analysis.IndustrialAnalysis()`
- `s.analysis.VehicleAnalysis()`
- `s.analysis.USBAnalysis()`
- `s.toolAnalysis.RunWinRMDecrypt(req)`

Validation:

- `cd backend && gofmt -l "internal/architecture/boundary_test.go"` — PASS.
- `cd backend && go test ./internal/architecture -run TestBackendArchitectureBoundaries -count=1 -v` — PASS.
- `cd backend && go test ./internal/transport ./internal/engine ./internal/architecture ./internal/governance -count=1` — PASS.
- `cd backend && gofmt -l .` — PASS.

Remaining context work:

- Consider future TShark field-scan context variants for subprocess interruption.

## 22. NTLM/SMB3 and Media Short-Operation Context Lift

Status: `BE-CONTEXT-3.2d` completed on 2026-05-15 00:28:32 +08:00.

This slice finishes the remaining transport-owned long-running helpers that still called no-context wrappers, then extends the architecture gate to cover them.

Changed backend contracts:

- `ToolAnalysisService.ListNTLMSessionMaterialsWithContext(ctx context.Context)`
- `ToolAnalysisService.ListSMB3SessionCandidatesWithContext(ctx context.Context)`
- `MediaService.TranscribeMediaArtifactWithContext(ctx context.Context, token string, force bool)`

Engine behavior:

- `ListNTLMSessionMaterials()` and `ListSMB3SessionCandidates()` remain as `context.Background()` wrappers for legacy synchronous callers.
- `scanNTLMSessionMaterials` and `scanSMB3SessionCandidates` now check `ctx.Err()` before scan setup and before each NTLM field-set fallback attempt.
- `TranscribeMediaArtifact()` now delegates to `TranscribeMediaArtifactWithContext(context.Background(), ...)`.
- Media transcription retains the existing capture-task tracking and cancellation checks inside the shared context-aware path.

Transport behavior:

- `/api/tools/ntlm-sessions` now calls `ListNTLMSessionMaterialsWithContext(r.Context())`.
- `/api/tools/smb3-sessions` now calls `ListSMB3SessionCandidatesWithContext(r.Context())`.
- `/api/analysis/media/transcribe` now calls `TranscribeMediaArtifactWithContext(r.Context(), ...)`.

Architecture gate:

- `backend/internal/architecture/boundary_test.go` now also forbids the old NTLM, SMB3, and media transcription no-context call sites in `http_server.go`.

Validation:

- `cd backend && gofmt -w internal/engine/tool_ntlm.go internal/engine/tool_smb3.go internal/engine/speech_to_text.go internal/transport/services.go internal/transport/http_server.go internal/architecture/boundary_test.go` — PASS.
- `cd backend && gofmt -l internal/engine/tool_ntlm.go internal/engine/tool_smb3.go internal/engine/speech_to_text.go internal/transport/services.go internal/transport/http_server.go internal/architecture/boundary_test.go` — PASS.
- `cd backend && go test ./internal/engine -run "TestListSMB3SessionCandidates|TestSpeech" -count=1` — PASS.
- `cd backend && go test ./internal/architecture -run TestBackendArchitectureBoundaries -count=1 -v` — PASS.
- `cd backend && go test ./internal/transport -count=1` — PASS.

Remaining context work:

- A deeper TShark field-scan context migration would still be needed to interrupt an already-running subprocess earlier in `backend/internal/tshark/analysis_helpers.go`.
