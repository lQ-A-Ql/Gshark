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

## 23. Script Execution Trust Model

Status: `BE-SCRIPT-7.1` completed on 2026-05-15 01:20:55 +08:00.

This documentation-only slice clarifies that Plugin and MISC script execution are local trusted extension points, not strong sandboxes.

Updated docs:

- `docs/misc-module-interface.md`
- `docs/plugin-interface.md`

Trust model now stated explicitly:

- MISC zip modules run local `backend.js` or `backend.py` logic under the current user context after import.
- Plugin execution requires `exec.local`, but that capability is an explicit local execution consent marker, not an isolation guarantee.
- Zip/import validation, host bridge scoping, unified forms, and `exec.local` permission checks are engineering guardrails, not malicious-code containment.
- Unknown-source modules/plugins should not be imported or enabled.
- Untrusted code execution requires external isolation such as an OS sandbox, VM, or separate process policy outside the current Plugin/MISC model.

Validation:

- `git diff --check` — PASS.

Remaining script governance work:

- `BE-SCRIPT-7.2`: design a candidate MISC permission model such as `exec.local`, `capture.read`, and `field.scan`.
- `BE-SCRIPT-7.3`: add host bridge method registry tests.
- `BE-SCRIPT-7.4`: strengthen MISC import safety tests.
- `BE-SCRIPT-7.5`: keep plugin permission parity tests aligned with `exec.local`.

## 24. MISC Permission Model Design

Status: `BE-SCRIPT-7.2` completed on 2026-05-15 01:28:11 +08:00.

This documentation-only slice defines a backward-compatible MISC `permissions` field model without changing runtime behavior.

Updated doc:

- `docs/misc-module-interface.md`

Candidate permissions:

- `exec.local`: allows running the local module backend script.
- `capture.read`: allows reading current capture path/context or capture-derived data.
- `field.scan`: allows host-backed field scans, including JavaScript `ctx.scanFields()` and Python `scan_fields()`.
- `host.bridge`: allows Python host bridge helper exposure.

Compatibility decisions:

- Missing `permissions` keeps current v3 behavior so installed modules are not broken.
- `host_bridge: true` is treated as requiring `host.bridge` in future gates.
- `requires_capture: true` is treated as requiring `capture.read` in future gates.
- Field scan usage should declare `field.scan`.
- Future enforcement should start with warnings before hard failures.
- `permissions` is capability exposure governance, not sandboxing.

Validation:

- `git diff --check -- docs/misc-module-interface.md docs/backend-engineering-audit-spec-2026-05-14.md` — PASS.

Remaining script governance work:

- `BE-SCRIPT-7.3`: add host bridge method registry tests.
- `BE-SCRIPT-7.4`: strengthen MISC import safety tests.
- `BE-SCRIPT-7.5`: keep plugin permission parity tests aligned with `exec.local`.

## 25. Host Bridge Unknown-Method Regression Test

Status: `BE-SCRIPT-7.3` first slice completed on 2026-05-15 01:31:55 +08:00.

This slice adds a direct regression test for the Python MISC host bridge method registry behavior.

Changed file:

- `backend/internal/miscpkg/manager_test.go`

Coverage added:

- `TestPythonHostBridgeRejectsUnknownMethod` calls `handlePythonHostCall` directly with an unsupported method name.
- The test verifies the response envelope remains a `host_response` with the original request id.
- The test verifies the error names the unsupported method.
- The test verifies unknown methods do not call the field-scan callback.

Validation:

- `cd backend && gofmt -w internal/miscpkg/manager_test.go` — PASS.
- `cd backend && gofmt -l internal/miscpkg/manager_test.go` — PASS.
- `cd backend && go test ./internal/miscpkg -run "TestPythonHostBridgeRejectsUnknownMethod|TestInvokePythonHostBridgeUsesContextAwareScanFields" -count=1 -v` — PASS.

Remaining script governance work:

- `BE-SCRIPT-7.3`: a later hardening slice can promote the implicit method switch into a named registry if more bridge methods are added.
- `BE-SCRIPT-7.4`: strengthen MISC import safety tests.
- `BE-SCRIPT-7.5`: keep plugin permission parity tests aligned with `exec.local`.

## 26. MISC Import Safety Test Gaps

Status: `BE-SCRIPT-7.4` completed on 2026-05-15 01:36:31 +08:00.

This slice audits and strengthens MISC zip import safety tests.

Existing coverage before this slice:

- Too many files.
- Oversized single file.
- Oversized total uncompressed content.

New coverage:

- `TestImportZipBytesRejectsInvalidModuleID`: rejects traversal-style module IDs such as `../bad` before extraction.
- `TestImportZipBytesRejectsZipSlipPath`: rejects zip entries that escape the managed module directory during extraction and removes partial module directories after failed import.

Changed file:

- `backend/internal/miscpkg/manager_test.go`

Validation:

- `cd backend && gofmt -w internal/miscpkg/manager_test.go` — PASS.
- `cd backend && go test ./internal/miscpkg -run "TestImportZipBytesRejects" -count=1 -v` — PASS.
- `cd backend && go test ./internal/miscpkg -count=1` — PASS.

Remaining script governance work:

- `BE-SCRIPT-7.5`: keep plugin permission parity tests aligned with `exec.local`.
- Optional future hardening: named host bridge registry if more bridge methods are added.

## 27. Plugin `exec.local` Permission Parity

Status: `BE-SCRIPT-7.5` completed on 2026-05-15 01:39:36 +08:00.

This slice verifies plugin permission behavior remains aligned with the documented local execution trust boundary.

Changed file:

- `backend/internal/plugin/manager_test.go`

Coverage added:

- `TestDefaultCapabilitiesDeclareLocalExec` verifies `exec.local` remains in the allowed plugin capability set.
- The same test verifies default plugin capabilities include `exec.local`, matching the current compatibility behavior for plugins without explicit capability lists.

Existing coverage preserved:

- `TestRunEnabledPacketPluginsRequiresExecLocalCapability` verifies plugins that explicitly omit `exec.local` do not execute local code and surface a warning.

Validation:

- `cd backend && gofmt -w internal/plugin/manager_test.go` — PASS.
- `cd backend && gofmt -l internal/plugin/manager_test.go` — PASS.
- `cd backend && go test ./internal/plugin -run "TestDefaultCapabilitiesDeclareLocalExec|TestRunEnabledPacketPluginsRequiresExecLocalCapability" -count=1 -v` — PASS.
- `cd backend && go test ./internal/plugin -count=1` — PASS.

Script governance status:

- `BE-SCRIPT-7.1` complete: trust model documented.
- `BE-SCRIPT-7.2` complete: MISC permission model designed.
- `BE-SCRIPT-7.3` first slice complete: host bridge unknown-method regression covered.
- `BE-SCRIPT-7.4` complete: MISC import safety tests strengthened.
- `BE-SCRIPT-7.5` complete: plugin `exec.local` parity tests aligned.

Recommended next backend epic:

- Move to `BE-MODEL-5.1` for model type classification, or `BE-CONTRACT-1.8` for backend-only schema/codegen decision notes.

## 28. Model Type Classification

Status: `BE-MODEL-5.1` completed on 2026-05-15 01:52:45 +08:00.

This documentation-only slice classifies `backend/internal/model/types.go` before any package/file split. No Go model types were moved or renamed.

Classification rule:

- `domain`: value types used internally by engine/tshark/plugin logic and also often serialized.
- `wire response`: HTTP-facing response/request DTOs whose JSON shape is part of the frontend contract.
- `runtime config`: persisted or runtime tool configuration/status values.
- `plugin/misc contract`: extension API and host bridge data shapes.
- `dynamic boundary`: intentionally dynamic JSON payload positions that should remain explicit rather than hidden.

Current groups in `types.go`:

| Lines | Representative Types | Classification | Notes |
|---:|---|---|---|
| 3-64 | `Packet`, `PacketColorFeatures` | domain + wire response | Packet rows are engine domain values and exported API payloads; JSON tags are contract-sensitive. |
| 66-157 | `TLSConfig`, `HuntingRuntimeConfig`, `YaraConfig`, `ToolRuntimeConfig`, `*ToolStatus`, `ToolRuntimeSnapshot`, `CaptureStatus` | runtime config + wire response | Tool/runtime surfaces should keep stable JSON tags; `YaraConfig` has no JSON tags and is internal config. |
| 159-543 | WinRM, SMB3, NTLM, HTTP login, SMTP, MySQL, Shiro, MISC package result types | wire response + plugin/misc contract | Tool workbench DTOs are protocol-specific wire contracts; MISC package types are extension API contracts. |
| 545-587 | `ObjectFile`, `Plugin`, `PluginSource`, `AuditEntry` | wire response + plugin contract | `ObjectFile.Path` is intentionally `json:"-"`; plugin capability fields are governance-sensitive. |
| 589-679 | `ParseOptions`, stream chunks, stream payload candidates/sources/inspection | domain + wire response + dynamic boundary | `DecoderOptionsHint map[string]any` is an intentional dynamic decoder-options boundary. |
| 681-1045 | Traffic, C2, APT, investigation report/evidence-related types | wire response + domain | Primary contract area for future producer snapshots; evidence types are already architecture-gated to engine/transport/model. |
| 1047-1272 | Industrial and vehicle analysis types | wire response + domain | Large protocol analysis surfaces; good candidates for JSON tag consistency tests before any split. |
| 1274-1541 | Media, speech, USB, and remaining protocol result types | wire response + domain | Media/speech task status and USB nested analysis are contract-sensitive dense UI payloads. |

Dynamic boundary inventory:

- `StreamPayloadCandidate.DecoderOptionsHint map[string]any`
- `StreamPayloadSource.DecoderOptionsHint map[string]any`
- `MiscModuleRunResult.Output any`
- `MiscModuleTableResult` row maps and parsed plugin/MISC output handled in `internal/miscpkg`
- Packet layer output is exposed as `map[string]any` via transport/service interfaces rather than a model struct

Recommended split order if `BE-MODEL-5.2` proceeds later while keeping package name `model`:

1. `packet.go`: packet row and color feature values.
2. `runtime.go`: tool runtime, TLS, YARA, capture status.
3. `tool_protocols.go`: WinRM/SMB3/NTLM/HTTP-login/SMTP/MySQL/Shiro DTOs.
4. `extensions.go`: plugin and MISC extension contracts.
5. `stream.go`: streams and payload inspection/source DTOs.
6. `analysis_c2_apt.go`: traffic, C2, APT, evidence/report-adjacent records.
7. `analysis_industrial_vehicle.go`: industrial and vehicle analysis DTOs.
8. `media_usb.go`: media, speech, USB analysis DTOs.

Guardrails before any split:

- Keep package name `model` to avoid import churn.
- Do not rename exported types or JSON tags.
- Add focused JSON tag consistency tests for selected contract structs before moving large groups.
- Keep dynamic `any` positions documented rather than trying to eliminate them globally.

Validation:

- `git diff --check -- docs/backend-engineering-audit-spec-2026-05-14.md` — PASS.

## 47. Twenty-Round Backend Engineering Approval

Status: cycle 2 approval completed on 2026-05-15 03:05:54 +08:00.

Cycle scope:

- R11 `BE-TRANSPORT-2.1b`: mutating route method policy tests.
- R12 `BE-CONTEXT-3.6`: request cancellation regression test.
- R13 `BE-MODEL-5.3`: dynamic model boundary comments.
- R14 `BE-TSHARK-6.1`: field-plan usage audit.
- R15 transport route baseline expansion for plugin write routes.
- R16 engine service ownership follow-up constructor gate.
- R17 backend producer contract pilot expansion for `/api/tools/runtime-config`.
- R18 `BE-CONTEXT-3.6` context exception audit update.
- R19 docs/report self-review and cycle approval prep.
- R20 cycle approval and next-cycle task optimization.

Validation:

- `cd backend && gofmt -l .` — PASS.
- `cd backend && go test ./internal/model ./internal/engine ./internal/transport ./internal/architecture ./internal/governance ./internal/miscpkg ./internal/plugin -count=1` — PASS.
- `git diff --check -- backend docs/backend-engineering-audit-spec-2026-05-14.md docs/misc-module-interface.md docs/plugin-interface.md docs/audit-development-report-archive-2026-05-14/backend-engineering-report-2026-05-14.md` — PASS.

Cycle approval result:

- Approved.
- The cycle improved route-level safety nets, request cancellation confidence, model contract readability, TShark audit clarity, engine owner invariants, and producer contract maturity without broad refactors.
- Average effective score: Gold.
- No round remained below the 90 approval threshold after self-review.

Optimized next task order:

1. `BE-TRANSPORT-2.2`: move capture handlers after the route baseline is stronger.
2. `BE-ENGINE-4.2` or `BE-ENGINE-4.3`: extract one owner group if a tested seam is now obvious.
3. `BE-CONTRACT-1.6` / `BE-CONTRACT-1.7`: continue contract hardening only where stable dynamic boundaries are already documented.
4. `BE-TSHARK-6.2`: expand capability matrix tests if a new scan path or field registry change lands.
5. `BE-CONTEXT-3.6` follow-up: cover one media/tool path cancellation regression if a lightweight fake becomes available.

Deferred tasks:

- Full schema/codegen remains deferred.
- Deep TShark field-scan subprocess cancellation remains deferred.
- Broad `engine.Service` extraction remains deferred until more focused owner tests exist.

## 48. Capture Handler Split

Status: `BE-TRANSPORT-2.2` completed on 2026-05-15 11:16:00 +08:00.

This slice moved capture lifecycle and upload handlers behind the existing route and method baselines without changing route registrations or handler names.

Changed files:

- `backend/internal/transport/http_server.go`
- `backend/internal/transport/http_capture.go`

Coverage:

- `handleCaptureStart`, `handleCaptureStop`, `handleCapturePrepareReplacement`, `handleCaptureClose`, `handleCaptureStatus`, and `handleCaptureUpload` now live in `http_capture.go`.
- `Server.Handler()` registrations remain unchanged in `http_server.go`.
- Upload cleanup helpers remain in `http_server.go` for now; this keeps the slice limited to handler movement.

Validation:

- `cd backend && go test ./internal/transport -run "TestHandlerRegisters(MutatingRouteMethodPolicy|CoreReadRoutes)$|TestHandleCapture(PrepareReplacement|StatusReportsEmptyCapture)$" -count=1` — PASS.
- `cd backend && gofmt -l internal/transport/http_server.go internal/transport/http_capture.go` — PASS.

Self-review:

- Score: 94/100, Gold.
- The change is behavior-preserving and route-level tests already cover the moved capture endpoints.
- Residual risk: upload helper ownership is still mixed into `http_server.go`; defer until more upload-specific tests exist.

## 49. Split Handler Architecture Gate

Status: `BE-CONTEXT-3.2` follow-up completed on 2026-05-15 11:24:00 +08:00.

The context-aware handler boundary test now scans every non-test Go file under `backend/internal/transport` instead of only `http_server.go`. This prevents future handler moves from bypassing the no-context-call regression gate.

Changed file:

- `backend/internal/architecture/boundary_test.go`

Coverage:

- The architecture test explicitly confirms `internal/transport/http_server.go` and `internal/transport/http_capture.go` are included in the scan.
- The forbidden long-running no-context service calls are checked across all transport implementation files.

Validation:

- `cd backend && go test ./internal/architecture -count=1` — PASS.

Self-review:

- Score: 96/100, Gold.
- This is a low-risk test hardening step that directly addresses the risk introduced by handler file splits.

## 50. Capture Analysis Reset Seam

Status: `BE-ENGINE-4.2` guardrail slice completed on 2026-05-15 11:30:00 +08:00.

This slice avoided a broad owner-struct extraction because capture reset currently crosses analysis caches, stream state, media/speech state, and display-filter state under shared locks. Instead, it extracted the reset block into a focused helper and added a regression test for the reset surface.

Changed files:

- `backend/internal/engine/service.go`
- `backend/internal/engine/page_filter_test.go`

Coverage:

- `resetCaptureAnalysisStateLocked` now owns the in-memory derived-state reset performed by `ClearCapture`.
- `TestClearCaptureResetsDerivedAnalysisState` seeds analysis, media/speech, stream, and display-filter state, then asserts `ClearCapture` resets them.

Validation:

- `cd backend && go test ./internal/engine -run "TestNewServiceInitializesOwnerState|TestClearCaptureResets(PacketStore|DerivedAnalysisState)$" -count=1` — PASS.

Self-review:

- Score: 93/100, Gold.
- This improves the seam without relocating locks or changing public behavior.
- Residual risk: a real owner struct is still deferred until capture reset and stream/media owners have stronger isolated tests.

## 51. Global Traffic Producer Contract

Status: `BE-CONTRACT-1.6` follow-up completed on 2026-05-15 11:33:00 +08:00.

This slice expanded backend producer contract coverage to `/api/stats/traffic/global`, adding a stable top-level shape check alongside existing industrial, vehicle, USB, and C2 analysis contract tests.

Changed file:

- `backend/internal/transport/http_contract_test.go`

Coverage:

- `TestGlobalTrafficStatsContract` checks stable keys and basic JSON types for global traffic stats.
- The contract fake now returns initialized traffic buckets for representative global fields.

Validation:

- `cd backend && go test ./internal/transport -run "Test(GlobalTrafficStats|IndustrialAnalysis|VehicleAnalysis|USBAnalysis|C2Analysis)Contract$" -count=1` — PASS.

Self-review:

- Score: 94/100, Gold.
- This strengthens `P2-6` backend evidence without promoting full schema/codegen.

## 52. Media Transcription Cancellation Regression

Status: `BE-CONTEXT-3.6` follow-up completed on 2026-05-15 11:36:00 +08:00.

This slice added a media-path request cancellation regression and aligned media transcription cancellation error handling with the existing C2 behavior.

Changed files:

- `backend/internal/transport/http_server.go`
- `backend/internal/transport/http_server_test.go`

Coverage:

- `TestHandleMediaArtifactTranscriptionUsesCanceledRequestContext` passes a canceled request context into `/api/analysis/media/transcribe`.
- The fake media service records `ctx.Err()` and returns it.
- The handler now returns `408 Request Timeout` for `context.Canceled` instead of a generic bad request.

Validation:

- `cd backend && go test ./internal/transport -run "TestHandleMediaArtifactTranscriptionUsesCanceledRequestContext|TestHandleC2AnalysisUsesCanceledRequestContext" -count=1` — PASS.

Self-review:

- Score: 95/100, Gold.
- Behavior is more consistent for request-scoped cancellation and does not alter successful transcription payloads.

## 53. `P2-6` Backend Evidence Update

Status: governance evidence updated on 2026-05-15 11:40:00 +08:00.

`docs/governance-defect-register.json` keeps `P2-6` open because the issue is explicitly about mapper schema/codegen feasibility after WireDTO gates and still has frontend-facing promotion criteria. Backend-side evidence now supports the deferred decision:

- Full OpenAPI / JSON Schema / TypeScript DTO generation remains deferred.
- Producer contract pilots now cover `/api/streams/index`, `/api/evidence`, `/api/tools/runtime-config`, `/api/stats/traffic/global`, and representative analysis endpoints.
- Dynamic boundaries remain documented rather than hidden by generated schemas.

Validation:

- `cd backend && go test ./internal/governance -count=1` — planned for final cycle validation.

Self-review:

- Score: 92/100, Gold.
- The register schema intentionally rejects ad-hoc open-defect notes, so the evidence is recorded here instead of extending the register format mid-cycle.

## 54. Thirty-Round Backend Engineering Approval

Status: cycle 3 approval completed on 2026-05-15 11:48:00 +08:00.

Cycle scope:

- R21 `BE-TRANSPORT-2.2`: moved capture handlers into `http_capture.go` after route baselines existed.
- R22 `BE-CONTEXT-3.2` follow-up: upgraded architecture context scan to cover split transport files.
- R23 `BE-ENGINE-4.2` guardrail slice: extracted derived capture reset helper and added reset invariant coverage.
- R24 `BE-CONTRACT-1.6` follow-up: added `/api/stats/traffic/global` producer contract.
- R25 route/auth/audit reassessment: confirmed split-handler architecture coverage instead of adding redundant route assertions.
- R26 `BE-CONTEXT-3.6` follow-up: added media transcription request-cancellation regression and `408` cancellation mapping.
- R27 governance evidence update: kept `P2-6` open and recorded backend-side evidence here because the canonical register schema disallows open-defect notes.
- R28 docs/self-review: validated governance, formatting, and whitespace.
- R29 final validation: selected backend package suite passed.
- R30 cycle approval and commit prep.

Validation:

- `cd backend && gofmt -l .` — PASS.
- `cd backend && go test ./internal/governance -count=1` — PASS.
- `git diff --check -- backend docs/backend-engineering-audit-spec-2026-05-14.md docs/governance-defect-register.json` — PASS.
- `cd backend && go test ./internal/model ./internal/engine ./internal/transport ./internal/architecture ./internal/governance ./internal/miscpkg ./internal/plugin -count=1` — PASS.

Cycle approval result:

- Approved.
- The cycle reduced `http_server.go` capture-handler scope, strengthened architecture coverage for split transport files, improved capture reset ownership safety, expanded backend producer contracts, and added a second request-cancellation regression.
- Average effective score: Gold.
- No round remained below the 90 approval threshold after self-review.

Optimized next task order:

1. `BE-TRANSPORT-2.3`: move packet/stream handlers only if route baselines cover the selected endpoints first.
2. `BE-ENGINE-4.3`: consider stream cache owner extraction, starting with tests for cache/override invariants.
3. `BE-CONTRACT-1.7`: add explicit dynamic-boundary contract helper for packet layers and decoder options.
4. `BE-CONTEXT-3.6`: add one tool-analysis cancellation regression if a lightweight fake stays small.
5. `BE-TSHARK-6.2`: defer capability matrix expansion until a new field-scan path changes.

Deferred tasks:

- Full schema/codegen remains deferred while `P2-6` stays open.
- Upload helper extraction remains deferred until upload-specific route tests exist.
- Broad `engine.Service` owner struct extraction remains deferred until stream/media reset seams have more focused tests.

## 55. Packet/Stream Route Baseline

Status: `BE-TRANSPORT-2.3` baseline slice completed on 2026-05-15 12:02:00 +08:00.

This slice adds route-level coverage for packet and basic stream endpoints before moving any handlers.

Changed file:

- `backend/internal/transport/http_server_test.go`

Coverage:

- `TestHandlerRegistersPacketStreamRoutes` exercises routes through `Server.Handler()` with a fake `CaptureService`.
- Covered packet routes: `/api/packets`, `/api/packets/page`, `/api/packets/locate`, `/api/packet`, `/api/packet/raw`, `/api/packet/layers`.
- Covered stream routes: `/api/streams/index`, `/api/streams/http`, `/api/streams/raw`, `/api/streams/raw/page`, `/api/streams/payload-sources`.

Validation:

- `cd backend && go test ./internal/transport -run "TestHandlerRegisters(PacketStreamRoutes|CoreReadRoutes)$" -count=1` — PASS.

Self-review:

- Score: 95/100, Gold.
- The test uses route registration rather than direct handler calls, so it protects the next split from route drift.

## 56. Packet/Stream Handler Split

Status: `BE-TRANSPORT-2.3` split slice completed on 2026-05-15 12:07:00 +08:00.

This slice moved packet and basic stream read handlers into `http_packet_stream.go`. POST decode/inspect/payload mutation handlers stay in `http_server.go` until their method/payload baselines are stronger.

Changed files:

- `backend/internal/transport/http_server.go`
- `backend/internal/transport/http_packet_stream.go`
- `backend/internal/transport/http_server_test.go`

Coverage:

- Moved packet handlers: packets list/page/locate/detail/raw/layers.
- Moved basic stream handlers: index, HTTP stream, raw stream, raw stream page, payload sources.
- Route registrations remain unchanged in `Server.Handler()`.

Validation:

- `cd backend && go test ./internal/transport -run "TestHandlerRegistersPacketStreamRoutes|Test(PacketDetail|PacketLocate|PacketRaw|PacketLayers|StreamIndex|PacketsPage)Contract$|TestHandleStreamPayloadSourcesReturnsInitializedPayload" -count=1` — PASS.
- `cd backend && go test ./internal/architecture -count=1` — PASS.

Self-review:

- Score: 94/100, Gold.
- The split is behavior-preserving and intentionally excludes higher-risk POST stream mutation handlers.

## 57. Stream Cache Owner Invariants

Status: `BE-ENGINE-4.3` guardrail slice completed on 2026-05-15 12:13:00 +08:00.

This slice adds stream cache and override invariants before any owner-struct extraction.

Changed file:

- `backend/internal/engine/stream_cache_test.go`

Coverage:

- `TestCacheStreamStoresClone` proves cached streams do not alias caller-owned chunks or metadata.
- `TestCacheStreamEvictsOldestBeyondLimit` covers LRU size enforcement.
- `TestCacheStreamRefreshesExistingOrder` covers refreshing an existing cache entry before eviction.
- `TestStreamWithOverridesUsesClones` proves overrides do not mutate the source stream.

Validation:

- `cd backend && go test ./internal/engine -run "Test(CacheStream|StreamWithOverrides)" -count=1` — PASS.

Self-review:

- Score: 95/100, Gold.
- Runtime behavior was not changed; this creates the guardrail needed before future stream owner extraction.

## 58. Dynamic Boundary Contract Helper

Status: `BE-CONTRACT-1.7` first slice completed on 2026-05-15 12:16:00 +08:00.

This slice adds an explicit contract helper for dynamic JSON object boundaries and applies it to packet layer output.

Changed file:

- `backend/internal/transport/http_contract_test.go`

Coverage:

- `requireDynamicJSONObject` documents that a JSON object is intentionally dynamic rather than a fully static contract surface.
- `TestPacketLayersContract` now uses this helper for `layers`, matching the model boundary inventory.

Validation:

- `cd backend && go test ./internal/transport -run "TestPacketLayersContract|TestPacketInlineContractRejectsInvalidID" -count=1` — PASS.

Self-review:

- Score: 93/100, Gold.
- This does not broaden the contract; it makes the intentional dynamic boundary explicit for future schema/codegen decisions.

## 59. NTLM Tool Cancellation Regression

Status: `BE-CONTEXT-3.6` tool-analysis slice completed on 2026-05-15 12:20:00 +08:00.

This slice adds a lightweight tool-analysis cancellation regression and aligns NTLM cancellation response handling with C2/media behavior.

Changed files:

- `backend/internal/transport/http_server.go`
- `backend/internal/transport/http_server_test.go`

Coverage:

- `TestHandleNTLMSessionMaterialsUsesCanceledRequestContext` passes a canceled request context to `/api/tools/ntlm-sessions`.
- The fake `ToolAnalysisService` records `ctx.Err()` and returns it.
- The handler now maps `context.Canceled` to `408 Request Timeout`.

Validation:

- `cd backend && go test ./internal/transport -run "TestHandleNTLMSessionMaterialsUsesCanceledRequestContext|TestHandleMediaArtifactTranscriptionUsesCanceledRequestContext" -count=1` — PASS.

Self-review:

- Score: 95/100, Gold.
- This is a narrow consistency fix on an already context-aware endpoint.

## 60. Thirty-Nine-Round Backend Engineering Approval

Status: cycle 4 approval completed on 2026-05-15 12:24:00 +08:00.

Cycle scope:

- R31 packet/stream route baselines.
- R32 packet/basic-stream handler split.
- R33 stream cache owner invariant tests.
- R34 dynamic-boundary contract helper for packet layers.
- R35 NTLM tool cancellation regression.
- R36 backend governance evidence update in this spec.
- R37 docs/self-review.
- R38 final backend validation.
- R39 cycle approval and commit prep.

Validation:

- `cd backend && gofmt -l .` — PASS.
- `git diff --check -- backend docs/backend-engineering-audit-spec-2026-05-14.md` — PASS.
- `cd backend && go test ./internal/model ./internal/engine ./internal/transport ./internal/architecture ./internal/governance ./internal/miscpkg ./internal/plugin -count=1` — PASS.

Cycle approval result:

- Approved.
- The cycle continued transport decomposition only after route-level baselines, added stream owner guardrails before extraction, and extended cancellation consistency without frontend changes.
- Average effective score: Gold.

Optimized next task order:

1. Add POST baselines for `/api/streams/decode`, `/api/streams/inspect`, and `/api/streams/payloads` before moving remaining stream mutation handlers.
2. Consider extracting a package-private stream cache owner helper only if current invariants remain green after final validation.
3. Apply `requireDynamicJSONObject` or equivalent helpers to decoder option hints and extension output contract tests when those surfaces receive producer tests.
4. Add SMB3 or WinRM cancellation response consistency only if a compact fake avoids broad test scaffolding.
5. Keep full schema/codegen deferred while `P2-6` remains open.

## 61. Stream Mutation Route Baseline

Status: `BE-TRANSPORT-2.4` baseline slice completed on 2026-05-15 12:39:00 +08:00.

This slice adds POST route baselines for remaining stream mutation/utility endpoints before moving their handlers.

Changed file:

- `backend/internal/transport/http_server_test.go`

Coverage:

- `TestHandlerRegistersStreamMutationRoutes` validates `/api/streams/decode`, `/api/streams/inspect`, and `/api/streams/payloads` through `Server.Handler()`.
- Each route rejects `GET` with `405` and accepts a minimal valid `POST` payload.

Validation:

- `cd backend && go test ./internal/transport -run "TestHandlerRegistersStreamMutationRoutes|TestHandlerRegistersPacketStreamRoutes" -count=1` — PASS.

Self-review:

- Score: 95/100, Gold.
- This catches route registration, method policy, and minimal payload compatibility before handler movement.

## 62. Remaining Stream Handler Split

Status: `BE-TRANSPORT-2.4` split slice completed on 2026-05-15 12:43:00 +08:00.

This slice moved `/api/streams/decode`, `/api/streams/inspect`, and `/api/streams/payloads` handlers into `http_packet_stream.go`, completing packet/basic stream handler decomposition while preserving routes.

Changed files:

- `backend/internal/transport/http_server.go`
- `backend/internal/transport/http_packet_stream.go`
- `backend/internal/transport/http_server_test.go`

Validation:

- `cd backend && go test ./internal/transport -run "TestHandlerRegisters(StreamMutationRoutes|PacketStreamRoutes)$|TestHandleStreamPayloadSourcesReturnsInitializedPayload|TestStreamIndexContract" -count=1` — PASS.
- `cd backend && go test ./internal/architecture -count=1` — PASS.

Self-review:

- Score: 94/100, Gold.
- The move is route-preserving and the architecture context scan still covers split transport files.

## 63. Stream Cache Helper Extraction

Status: `BE-ENGINE-4.3` helper slice completed on 2026-05-15 12:47:00 +08:00.

This slice keeps full stream cache owner extraction deferred, but extracts cache-order refresh into `markStreamCacheKeyNewestLocked` under existing locks.

Changed file:

- `backend/internal/engine/service.go`

Validation:

- `cd backend && go test ./internal/engine -run "Test(CacheStream|StreamWithOverrides)" -count=1` — PASS.

Self-review:

- Score: 93/100, Gold.
- The helper reduces duplicated ordering logic without moving lock ownership or changing cache behavior.

## 64. Dynamic Boundary Helper Coverage

Status: `BE-CONTRACT-1.7` helper coverage completed on 2026-05-15 12:50:00 +08:00.

This slice adds direct coverage for the dynamic JSON boundary helper rather than inventing unstable endpoint fixtures for decoder option hints.

Changed file:

- `backend/internal/transport/http_contract_test.go`

Coverage:

- `TestDynamicJSONBoundaryContractHelper` verifies the helper returns the dynamic object map.
- Packet layer contract coverage continues to use the helper for `layers`.

Validation:

- `cd backend && go test ./internal/transport -run "TestDynamicJSONBoundaryContractHelper|TestPacketLayersContract" -count=1` — PASS.

Self-review:

- Score: 92/100, Gold.
- This documents helper semantics without locking protocol-dependent payload source fixtures too early.

## 65. Tool Cancellation Consistency Expansion

Status: `BE-CONTEXT-3.6` tool consistency slice completed on 2026-05-15 12:55:00 +08:00.

This slice expands request-cancellation consistency from NTLM to SMB3 candidate listing and WinRM decrypt.

Changed files:

- `backend/internal/transport/http_server.go`
- `backend/internal/transport/http_server_test.go`

Coverage:

- `TestHandleSMB3SessionCandidatesUsesCanceledRequestContext` verifies canceled request propagation and `408` mapping.
- `TestHandleWinRMDecryptUsesCanceledRequestContext` verifies canceled request propagation and `408` mapping.
- Existing NTLM cancellation regression remains covered by the same fake service.

Validation:

- `cd backend && go test ./internal/transport -run "TestHandle(NTLMSessionMaterials|SMB3SessionCandidates|WinRMDecrypt)UsesCanceledRequestContext" -count=1` — PASS.

Self-review:

- Score: 95/100, Gold.
- This is a narrow consistency improvement on already context-aware tool endpoints.

## 66. Forty-Eight-Round Backend Engineering Approval

Status: cycle 5 approval completed on 2026-05-15 12:59:00 +08:00.

Cycle scope:

- R40 stream POST route baselines.
- R41 remaining stream handler split.
- R42 stream cache helper extraction.
- R43 dynamic-boundary helper coverage.
- R44 SMB3 and WinRM cancellation consistency.
- R45 backend governance evidence update in this spec.
- R46 docs/self-review.
- R47 final backend validation.
- R48 cycle approval and commit prep.

Validation:

- `cd backend && gofmt -l .` — PASS.
- `git diff --check -- backend docs/backend-engineering-audit-spec-2026-05-14.md` — PASS.
- `cd backend && go test ./internal/model ./internal/engine ./internal/transport ./internal/architecture ./internal/governance ./internal/miscpkg ./internal/plugin -count=1` — PASS.

Cycle approval result:

- Approved.
- The cycle completed stream handler decomposition, added route-level POST baselines first, made stream cache ordering clearer under existing locks, and expanded cancellation consistency.
- Average effective score: Gold.

Optimized next task order:

1. Split tool handlers into a dedicated transport file only after route/method baselines cover WinRM, SMB3, NTLM, HTTP-login, SMTP, MySQL, and Shiro.
2. Consider extracting packet handler tests into grouped table helpers if transport tests become too long.
3. Add one producer contract for stream decode/inspect response shapes if those response DTOs are stable enough.
4. Keep stream cache owner struct extraction deferred until cache/raw-index mutation paths can be isolated behind a small interface.
5. Keep full schema/codegen deferred while `P2-6` remains open.

## 39. Mutating Route Method Policy Baseline

Status: `BE-TRANSPORT-2.1b` completed on 2026-05-15 02:31:18 +08:00.

This slice extends the route behavior baseline from read-route registration into representative mutating route method policy.

Changed file:

- `backend/internal/transport/http_server_test.go`

Coverage added:

- `TestHandlerRegistersMutatingRouteMethodPolicy` exercises routes through `Server.Handler()` rather than direct handler methods.
- Covered routes: `/api/capture/stop`, `/api/capture/prepare-replacement`, and `/api/capture/close`.
- Each route now has a route-level assertion that a bad `GET` method returns `405 Method Not Allowed`.
- Each route now has a route-level assertion that the intended `POST` method returns the stable status JSON payload.

Validation:

- `cd backend && go test ./internal/transport -run "TestHandlerRegisters(MutatingRouteMethodPolicy|CoreReadRoutes)$" -count=1` — PASS.

Self-review:

- Score: 95/100, Gold.
- Risk remains low because this is test-only and avoids endpoints that require real captures, multipart uploads, or external tools.
- Follow-up route baselines can add auth/audit-sensitive paths before moving handler groups into separate files.

## 40. Request Cancellation Regression Test

Status: `BE-CONTEXT-3.6` first slice completed on 2026-05-15 02:35:44 +08:00.

This slice adds a narrow transport regression test proving a request-scoped context reaches a context-aware long-running analysis method.

Changed file:

- `backend/internal/transport/http_server_test.go`

Coverage added:

- `TestHandleC2AnalysisUsesCanceledRequestContext` creates an already-canceled request context.
- A fake `AnalysisService` records `ctx.Err()` in `C2SampleAnalysis(ctx)` and returns it.
- The handler returns `408 Request Timeout` for `context.Canceled`, matching existing cancellation error handling.
- The test fails if the handler stops passing `r.Context()` to `C2SampleAnalysis`.

Validation:

- `cd backend && go test ./internal/transport -run "TestHandleC2Analysis(ReturnsInitializedPayload|UsesCanceledRequestContext)$" -count=1` — PASS.

Self-review:

- Score: 94/100, Gold.
- The test avoids slow external tools while still guarding the request-context propagation behavior that matters for cancellation.
- Further cancellation tests should cover one media/tool path once a fake service can be injected without broad scaffolding.

## 41. Dynamic Model Boundary Comments

Status: `BE-MODEL-5.3` first slice completed on 2026-05-15 02:39:26 +08:00.

This slice adds narrow comments at the currently identified dynamic JSON boundaries in `backend/internal/model/types.go`.

Changed file:

- `backend/internal/model/types.go`

Comments added:

- `MiscModuleRunResult.Output` explains that MISC modules may return scalar, object, or list payloads.
- `StreamPayloadCandidate.DecoderOptionsHint` explains that different payload families expose different option sets.
- `StreamPayloadSource.DecoderOptionsHint` mirrors that explanation for source-level payload discovery.
- `C2DecryptedRecord.Parsed` explains that the parsed payload is family-specific decrypted metadata beside stable fields.

Validation:

- `cd backend && go test ./internal/model -count=1` — PASS.

Self-review:

- Score: 93/100, Gold.
- The comments are deliberately small and sit only on dynamic boundaries already tolerated by contract tests.
- A broader boundary inventory can wait until the next model split or contract expansion.

## 42. TShark Field-Plan Usage Audit

Status: `BE-TSHARK-6.1` audited on 2026-05-15 02:43:12 +08:00.

This slice audits current `field-scan` usage rather than changing the TShark subsystem.

Findings:

- `backend/internal/tshark/analysis_helpers.go` is the single shared execution path for cache-aware field scans.
- `backend/internal/tshark/field_scan_plan.go` already centralizes capability-aware planning, alias resolution, optional-field degradation, and projection back to caller layout.
- Existing call sites already route through the planner or its exported wrapper, including `engine/tool_ntlm.go`, `engine/tool_smb3.go`, `engine/tool_winrm.go`, `miscpkg/manager.go`, `engine/c2_decrypt.go`, `tshark/runner.go`, `tshark/filter_ids.go`, `tshark/stream_follow.go`, `tshark/usb_analysis.go`, and the various helper tests.
- The current test suite already covers optional-field skipping, required-field rejection, alias resolution, argument ordering, degradation notes, and cache reuse.

Remaining watchpoints:

- If a new field-scan path is added outside the planner, it should either call `BuildPlannedFieldArgs` or justify a direct scan with a test.
- Deep subprocess cancellation is still bounded by the current `Command` execution model and is better handled with a future focused helper change than with this audit slice.

Validation:

- `rg -n "ScanFieldRowsWithDisplayFilter|BuildPlannedFieldArgs|planFieldScanByCapabilities" backend/internal` — PASS as an audit pass.

Self-review:

- Score: 92/100, Gold.
- This is an audit-only slice because the existing design is already centralized and the current tests cover the important planner invariants.
- The next TShark change should be event-driven, not speculative.

## 43. Plugin Write Route Registration Baseline

Status: transport route baseline expansion completed on 2026-05-15 02:48:57 +08:00.

This slice extends route-level testing into plugin write routes that are audit/security sensitive.

Changed file:

- `backend/internal/transport/http_server_test.go`

Coverage added:

- `TestHandlerRegistersPluginWriteRoutes` exercises plugin routes through `Server.Handler()` with a fake `PluginService`.
- Covered routes: `/api/plugins/add`, `/api/plugins/delete`, `/api/plugins/source`, and `/api/plugins/bulk`.
- The test verifies route registration, method wiring, basic JSON response shape, and that the expected plugin service method is invoked for add/delete/bulk.

Validation:

- `cd backend && go test ./internal/transport -run "TestHandlerRegistersPluginWriteRoutes|TestHandlerRegistersMutatingRouteMethodPolicy" -count=1` — PASS.

Self-review:

- Score: 95/100, Gold.
- The route matrix is still intentionally partial, but it now covers read routes, simple mutating capture routes, and plugin write routes.
- Future transport splitting has a stronger route-level safety net without broad handler movement yet.

## 44. Engine Service Owner State Constructor Gate

Status: engine ownership follow-up completed on 2026-05-15 02:52:08 +08:00.

This slice adds a small constructor invariant test before any `Service` owner extraction.

Changed file:

- `backend/internal/engine/service_ownership_test.go`

Coverage added:

- `TestNewServiceInitializesOwnerState` verifies `NewService` initializes the default emitter, packet store, capture task registry, display-filter cache, stream owner maps, media owner maps, default hunting prefixes, and default YARA config.
- The test protects future service-owner extraction from accidentally leaving map-backed owner state nil.

Validation:

- `cd backend && go test ./internal/engine -run TestNewServiceInitializesOwnerState -count=1` — PASS.

Self-review:

- Score: 94/100, Gold.
- This avoids broad `Service` extraction while adding a useful invariant around the owner groups documented earlier.
- Future extraction can use this as a minimum constructor-safety baseline.

## 45. Runtime Config Producer Contract Pilot

Status: third backend producer contract pilot completed on 2026-05-15 02:57:24 +08:00.

This slice adds the previously recommended `/api/tools/runtime-config` producer contract pilot.

Changed file:

- `backend/internal/transport/http_contract_test.go`

Coverage added:

- `TestToolRuntimeConfigContract` exercises `handleToolRuntimeConfig` with a fake `ToolRuntimeService`.
- The test verifies top-level keys: `config`, `tshark`, `ffmpeg`, `speech`, and `yara`.
- The test verifies stable nested keys for tool runtime config and status objects while respecting `omitempty` fields.
- `contractToolRuntimeService` provides stable fixture data without requiring local tools to be installed.

Validation:

- `cd backend && go test ./internal/transport -run "TestToolRuntimeConfigContract|TestHandlerRegistersPluginWriteRoutes|TestHandlerRegistersMutatingRouteMethodPolicy" -count=1` — PASS.

Self-review:

- Score: 95/100, Gold.
- This completes the third small producer pilot without introducing full schema/codegen or frontend changes.
- The pilot strengthens `P2-6` evidence while preserving the current handwritten DTO strategy.

## 46. Context Exception Audit Update

Status: context policy update completed on 2026-05-15 03:00:16 +08:00.

This slice revisits the `context.Background()` classification after adding request-cancellation coverage.

Current enforcement evidence:

- `backend/internal/architecture/boundary_test.go` still blocks known HTTP handlers from using no-context long-running wrappers.
- `TestHandleC2AnalysisUsesCanceledRequestContext` now proves a canceled request context reaches a context-aware analysis service and returns `408 Request Timeout`.
- The grep audit found production `context.Background()` uses still fit the documented categories: tests, legacy wrappers delegating to `WithContext`, nil-context fallback, short tool/runtime probes, background tasks, server shutdown, and field capability planning.

Clarified exception:

- `tshark/field_scan_plan.go` uses `context.Background()` for capability planning because it is not request-owned today. This remains an accepted short probe/planning category, not a request handler exception.

Deferred limitation:

- Request contexts reach many long-running handlers, but field-scan subprocess cancellation is still constrained by current `tshark.Command`/`CommandContext` call sites. Changing that requires a focused helper migration and should not be mixed into route or contract work.

Validation:

- `rg -n "context\.Canceled|WithContext\(r\.Context\(\)\)|context\.Background\(\)" backend/internal` — PASS as context policy audit evidence.

Self-review:

- Score: 91/100, Gold.
- This is intentionally documentation/audit-only because the current production usage still matches the policy and the new cancellation test adds machine evidence.
- Future hardening should add AST-based allowlists only if string-based checks become noisy.

## 36. Core Route Registration Baseline

Status: `BE-TRANSPORT-2.1` first slice completed on 2026-05-15 02:21:54 +08:00.

This slice adds a route registration smoke baseline before any `http_server.go` handler split.

Changed file:

- `backend/internal/transport/http_server_test.go`

Coverage added:

- `TestHandlerRegistersCoreReadRoutes` exercises `Server.Handler()` rather than direct handler methods.
- Covered routes: `/health`, `/api/runtime/identity`, `/api/capture/status`, `/api/packets/page`, `/api/streams/index`, `/api/evidence`, `/api/tools/misc/modules`.
- The test verifies core read routes remain registered and return `200 OK` on an unauthenticated local test server.

Validation:

- `cd backend && gofmt -w internal/transport/http_server_test.go` — PASS.
- `cd backend && go test ./internal/transport -run "TestHandlerRegistersCoreReadRoutes" -count=1 -v` — PASS.
- `cd backend && go test ./internal/transport -count=1` — PASS.

Next route baseline hardening:

- Add method policy checks for mutating routes before splitting capture/tool/media handlers.
- Add auth/audit route baseline only where behavior is already stable and tested.

## 37. Ten-Round Backend Engineering Approval

Status: cycle 1 approval completed on 2026-05-15 02:23:40 +08:00.

Cycle scope:

- R1 `BE-MODEL-5.1`: model type classification.
- R2 `BE-CONTRACT-1.8`: backend schema/codegen decision for `P2-6`.
- R3 stream index producer contract pilot.
- R4 evidence producer contract pilot.
- R5 `BE-CONTEXT-3.3`: evidence collector cancellation.
- R6 `BE-CONTEXT-3.5`: `context.Background()` exception classification.
- R7 `BE-MODEL-5.5`: core JSON tag consistency gate.
- R8 `BE-ENGINE-4.1`: engine service state ownership map.
- R9 `BE-TRANSPORT-2.1`: core route registration baseline.
- R10 cycle approval and task optimization.

Validation:

- `cd backend && gofmt -l .` — PASS.
- `cd backend && go test ./internal/model ./internal/engine ./internal/transport ./internal/architecture ./internal/governance ./internal/miscpkg ./internal/plugin -count=1` — PASS.
- `git diff --check -- backend docs/backend-engineering-audit-spec-2026-05-14.md docs/misc-module-interface.md docs/plugin-interface.md` — PASS.

Cycle approval result:

- Approved. The cycle improved producer contracts, context cancellation, model governance, script governance, and route baseline without high-risk broad refactors.
- Average effective score: Gold.
- No round remained below the 90 approval threshold after self-review.

Optimized next task order:

1. `BE-TRANSPORT-2.1b`: add method policy tests for a small set of mutating routes.
2. `BE-CONTEXT-3.6`: add one cancellation regression test for a request-scoped long-running handler path.
3. `BE-MODEL-5.3`: add dynamic payload comments near model dynamic boundaries.
4. `BE-TSHARK-6.1`: audit field-plan usage for recently migrated scan paths.
5. `BE-TRANSPORT-2.2`: only after route/method baselines, move capture handlers into a separate file.

Deferred tasks:

- Full OpenAPI/JSON Schema/codegen remains deferred.
- Deep TShark field-scan context migration remains deferred until after smaller route/context gates.
- Broad `engine.Service` extraction remains deferred until owner-specific tests are expanded.

## 30. Stream Index Producer Contract Pilot

Status: backend producer contract pilot completed on 2026-05-15 02:00:03 +08:00.

This slice implements the first `P2-6` backend producer contract pilot for `/api/streams/index`.

Changed file:

- `backend/internal/transport/http_contract_test.go`

Coverage strengthened:

- `TestStreamIndexContract` now requires the exact response key set: `protocol`, `total`, `ids`.
- Empty-capture behavior now asserts `ids` is encoded as an empty JSON array, not `null`.
- `TestStreamIndexContractWithIDs` covers non-empty IDs, protocol normalization for `udp` -> `UDP`, and `total == len(ids)`.
- `contractCaptureService` now allows per-test stream ID fixtures and returns a copy to avoid accidental mutation coupling.

Validation:

- `cd backend && gofmt -w internal/transport/http_contract_test.go` — PASS.
- `cd backend && go test ./internal/transport -run "TestStreamIndexContract" -count=1 -v` — PASS.
- `cd backend && go test ./internal/transport -count=1` — PASS.

Next producer contract pilot:

- Strengthen `/api/evidence` by adding a non-empty/module-filtered response contract fixture.

## 31. Evidence Producer Contract Pilot

Status: second backend producer contract pilot completed on 2026-05-15 02:06:49 +08:00.

This slice strengthens `/api/evidence` producer-side contract coverage for non-empty and module-filtered responses.

Changed file:

- `backend/internal/transport/http_contract_test.go`

Coverage added:

- `TestEvidenceContractModuleFilter` verifies query parsing trims module names and skips empty entries.
- The test verifies a non-empty response includes `records`, `total`, and `notes`.
- The test verifies evidence record core fields: `id`, `module`, `source_type`, `summary`, and `severity`.
- The test verifies `notes` remains a JSON array when present.
- `contractEvidenceAnalysisService` captures the passed `model.EvidenceFilter` and returns a stable one-record fixture.

Validation:

- `cd backend && gofmt -w internal/transport/http_contract_test.go` — PASS.
- `cd backend && go test ./internal/transport -run "TestEvidenceContract" -count=1 -v` — PASS.
- `cd backend && go test ./internal/transport -count=1` — PASS.

`P2-6` backend pilot status:

- Pilot 1 `/api/streams/index`: completed.
- Pilot 2 `/api/evidence`: completed for empty and non-empty/module-filter paths.
- Full schema/codegen remains deferred until JSON tag consistency and dynamic boundary tests improve.

## 32. Evidence Collector Cancellation

Status: `BE-CONTEXT-3.3` completed on 2026-05-15 02:12:30 +08:00.

This slice strengthens `GatherEvidence` cancellation behavior without changing HTTP response shapes.

Changed files:

- `backend/internal/engine/evidence.go`
- `backend/internal/engine/evidence_collectors_detection.go`
- `backend/internal/engine/evidence_collectors_assets.go`
- `backend/internal/engine/evidence_test.go`

Behavior changes:

- `GatherEvidence` now normalizes a nil context to `context.Background()`.
- Each selected evidence module checks `ctx.Err()` before starting collection.
- Industrial evidence now calls `IndustrialAnalysisWithContext(ctx)`.
- Vehicle evidence now calls `VehicleAnalysisWithContext(ctx)`.
- USB evidence now calls `USBAnalysisWithContext(ctx)`.
- `TestGatherEvidenceReturnsCanceledContext` verifies canceled contexts return `context.Canceled` before expensive collectors run.

Validation:

- `cd backend && gofmt -w internal/engine/evidence.go internal/engine/evidence_collectors_detection.go internal/engine/evidence_collectors_assets.go internal/engine/evidence_test.go` — PASS.
- `cd backend && go test ./internal/engine -run "TestGatherEvidence" -count=1` — PASS.
- `cd backend && go test ./internal/engine ./internal/transport -count=1` — PASS.

Remaining context work:

- Deep TShark field-scan cancellation still requires context-aware variants under `backend/internal/tshark/analysis_helpers.go`.
- Desktop/legacy `context.Background()` wrappers should still be classified under `BE-CONTEXT-3.5`.

## 33. `context.Background()` Exception Classification

Status: `BE-CONTEXT-3.5` completed on 2026-05-15 02:14:24 +08:00.

This documentation slice classifies allowed `context.Background()` use so future context gates can distinguish legitimate wrappers from HTTP handler regressions.

Allowed categories:

| Category | Example Files | Policy |
|---|---|---|
| Tests | `*_test.go` | Allowed; tests may use background contexts unless specifically testing cancellation. |
| Legacy synchronous wrappers | `engine/service.go`, `tool_ntlm.go`, `tool_smb3.go`, `tool_winrm.go`, `speech_to_text.go` | Allowed only when the method immediately delegates to a `WithContext` variant. HTTP handlers must call the `WithContext` variant. |
| Nil-context fallback | `engine/*`, `tshark/capabilities.go`, `media_playback.go`, `c2_decrypt.go` | Allowed inside context-aware functions to normalize `nil` into a usable context. |
| Tool/runtime probes | `tshark/config.go`, speech runtime checks | Allowed for short local capability probes that are not tied to a request lifecycle. Prefer timeout contexts when subprocesses are involved. |
| Background tasks | `speech_to_text.go`, `service.go` capture task registry | Allowed for user-initiated background tasks that own their own cancel function. Must be registered/cancellable where long-running. |
| Server shutdown | `transport/http_server.go` | Allowed as an operational root; future improvement can add a bounded timeout context. |

Disallowed category:

- HTTP handlers must not use no-context long-running service wrappers when a request context is available.

Current machine enforcement:

- `backend/internal/architecture/boundary_test.go` prevents known migrated HTTP handlers from calling no-context wrappers.

Future hardening:

- Promote this classification into a small architecture allowlist if `context.Background()` starts spreading outside the categories above.
- Add timeout context to server shutdown if graceful shutdown hangs become observable.

Validation:

- `git diff --check -- docs/backend-engineering-audit-spec-2026-05-14.md` — PASS.

## 34. Core JSON Tag Consistency Gate

Status: `BE-MODEL-5.5` first slice completed on 2026-05-15 02:17:22 +08:00.

This slice adds a small model-level JSON tag consistency test for the most contract-sensitive structs touched by current producer pilots.

Changed file:

- `backend/internal/model/json_tags_test.go`

Coverage added:

- `Packet`: packet table/detail contract tags such as `id`, `source_ip`, `dest_ip`, `stream_id`.
- `EvidenceRecord`: core evidence record tags such as `id`, `module`, `source_type`, `summary`, `severity`.
- `EvidenceResponse`: `records`, `total`, and `notes,omitempty`.
- `ToolRuntimeSnapshot`: `config`, `tshark`, `ffmpeg`, `speech`, and `yara`.

Validation:

- `cd backend && gofmt -w internal/model/json_tags_test.go` — PASS.
- `cd backend && go test ./internal/model -count=1 -v` — PASS.
- `cd backend && go test ./internal/model ./internal/transport ./internal/architecture -count=1` — PASS.

Next JSON tag hardening:

- Add protocol-analysis tag tests only when touching their tests or before splitting `model/types.go`.

## 35. Engine Service State Ownership Map

Status: `BE-ENGINE-4.1` completed on 2026-05-15 02:18:48 +08:00.

This documentation-only slice maps ownership groups inside `backend/internal/engine/service.go` before any state extraction.

Current `Service` state groups:

| Fields | Owner Group | Notes |
|---|---|---|
| `emitter`, `pluginManger` | integration dependencies | Constructor-owned dependencies; spelling of `pluginManger` is existing API/internal state and should not be renamed casually. |
| `mu`, `loadMu`, `activeLoadMu`, `activeLoadID`, `activeLoadCancel`, `runID`, `cancel` | capture lifecycle and cancellation | Governs load serialization, active run identity, cancellation and capture replacement behavior. |
| `captureTaskMu`, `captureTaskSeq`, `captureTasks` | capture-scoped background task registry | Owns cancellable tasks tied to capture lifecycle such as speech/media background work. |
| `packetStore`, `pcap`, `tlsConf` | capture data and parse configuration | Core loaded capture state and TLS parse options. |
| `displayFilterCache`, `displayFilterCacheOrder` | packet filter cache owner | LRU-like packet filter index cache; separate from tshark field scan cache. |
| `globalTrafficStats`, `industrialAnalysis`, `vehicleAnalysis`, `mediaAnalysis`, `usbAnalysis`, `c2Analysis`, `aptAnalysis` | analysis result cache owner | Cached high-level analysis outputs; invalidated on capture replacement. |
| `vehicleDBCDefs` | vehicle DBC owner | Vehicle-specific decode configuration; candidate for a focused owner if vehicle code grows. |
| `streamCache`, `streamCacheOrder`, `rawStreamIndex`, `streamOverrides` | stream cache and override owner | Reassembled stream caching, pagination/indexing, and user patch state. |
| `exportDir`, `mediaExportDir`, `objectsLoaded`, `objects`, `mediaArtifacts`, `mediaPlayback`, `mediaSpeech`, `speechBatch`, `speechCancel`, `objMu` | object/media/speech owner | Mixed asset extraction and speech transcription state; likely future extraction target. |
| `yaraLoaded`, `yaraHits`, `yaraLastError`, `yaraMu` | YARA result owner | Detection cache and last error. |
| `toolRuntimeMu`, `huntMu`, `huntingPrefixes`, `yaraConf` | runtime configuration owner | Tool paths, hunting prefixes, and YARA runtime config; already partially protected by focused locks. |

Extraction guardrails:

- Do not extract fields only to reduce line count; extract only when a tested behavior boundary exists.
- Prefer helper-owner structs that stay inside package `engine` before introducing new packages.
- Preserve `Service` public method signatures unless a transport interface already hides the change.
- Move tests first or alongside owner extraction.

Recommended extraction order:

1. Stream cache owner (`streamCache`, `rawStreamIndex`, `streamOverrides`) because cache behavior is cohesive and already has stream tests.
2. Object/media/speech owner because state is broad but user-facing workflows already have tests.
3. Capture task registry owner because cancellation semantics are now important and isolated.
4. Analysis result cache owner only after contract/cancellation gates remain stable.

Validation:

- `git diff --check -- docs/backend-engineering-audit-spec-2026-05-14.md` — PASS.

Next recommended task:

- `BE-CONTRACT-1.8`: record backend-only schema/codegen decision for `P2-6`, using this classification to choose a small producer-side contract pilot.

## 29. Backend Schema/Codegen Decision for `P2-6`

Status: `BE-CONTRACT-1.8` backend-side decision completed on 2026-05-15 01:55:04 +08:00.

Decision:

- Do not introduce full OpenAPI, JSON Schema generation, or generated TypeScript DTOs yet.
- Continue handwritten Go structs and frontend WireDTOs for now, but add producer-side backend contract pilots for small stable surfaces.
- Revisit full schema/codegen only after at least two backend producer pilots prove stable field naming, optionality, and dynamic-boundary policy.

Rationale:

- `backend/internal/model/types.go` still mixes domain, wire response, runtime config, plugin/MISC contracts, and dynamic boundaries.
- Several response surfaces intentionally contain dynamic JSON (`map[string]any` / `any`) because packet layers, decoder options, and extension outputs are protocol/script dependent.
- Full codegen now would encode unstable ownership boundaries and increase migration cost.
- Backend producer contract tests already exist and are lower-risk than adding a generation toolchain during ongoing refactors.

Pilot recommendation:

1. First pilot: `/api/streams/index`.
   - Small shape: `protocol`, `total`, `ids`.
   - Already covered by `TestStreamIndexContract`.
   - Low dynamic payload risk.
   - Good candidate for stricter JSON snapshot/schema-like assertions.
2. Second pilot: `/api/evidence` empty and module-filtered responses.
   - High product value.
   - Already has empty-capture contract coverage.
   - Needs non-empty/module-filter fixture before schema generation should be considered.
3. Third pilot candidate: `/api/tools/runtime-config`.
   - Stable runtime/tool status surface.
   - Useful for config compatibility checks.

Promotion threshold for full schema/codegen:

- At least two pilot surfaces have backend producer contract tests with stable JSON fields.
- Dynamic boundary inventory is documented and tests explicitly allow those dynamic positions.
- Model type groups have been split or at least guarded by JSON tag consistency tests.
- Generated artifacts have a clear owner and CI check that does not require frontend source changes in backend-only flows.
- The governance register can cite concrete backend tests and validation commands before closing `P2-6`.

Next backend-only contract task:

- Add a stricter producer contract test for `/api/streams/index`, checking field set, value types, empty-list encoding, and protocol normalization.

Validation:

- `git diff --check -- docs/backend-engineering-audit-spec-2026-05-14.md` — PASS.
