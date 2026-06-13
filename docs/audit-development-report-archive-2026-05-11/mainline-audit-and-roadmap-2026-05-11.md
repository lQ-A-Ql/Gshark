# Mainline Audit and Roadmap - 2026-05-11

Date: 2026-05-11 11:27:28 +08:00  
Author: Codex

## Goal

Turn the latest cycle from **frontend split-first** back into **mainline capability closure first**.

## Latest Document Review

Reviewed before this round:

- `docs/README.md`
- `docs/audit-development-report-archive-2026-05-05/mainline-evidence-scope-and-validation-report-2026-05-05.md`
- the carried-forward frontend engineering log now split into `docs/audit-development-report-archive-2026-05-11/frontend-engineering-report-2026-05-11.md`

### Assessment

- The documentation direction was already correct: prioritize evidence schema, protocol report output, real-sample validation, and false-positive suppression.
- The execution drift was real: 2026-05-11 commit flow was still dominated by frontend presentation/state splits.
- The archive layout had started to drift: 2026-05-11 rounds were still being appended to a 2026-05-10 file.

## What This Round Corrects

### 1. Shared report contract

A unified structured investigation report now exists for the first-wave protocol and mainline analysis surfaces:

- HTTP 登录分析
- SMTP 会话重建
- MySQL 会话重建
- Shiro rememberMe 分析
- 工控分析
- 车机流量分析

All six now emit the same four-section shape:

- 摘要
- 证据
- 明细
- 建议

### 2. Frontend consumption contract

The frontend now consumes the shared report payload through one reusable panel and one reusable text export path instead of letting every module invent its own report-only presentation.

### 3. Regression gate upgrade

This round added coverage for:

- report contract generation in backend
- report contract mapping in frontend
- mixed desktop/http bridge fallback retaining protocol report payloads
- bundled public baseline samples for SMTP, MySQL, Industrial, and Vehicle analyses

## Current Engineering Position

### Stronger than before

- Mainline report output is now explicit and packet-linked.
- First-wave protocol modules can surface evidence/recommendations in a uniform, testable way.
- Public sample regression is no longer only a documentation suggestion; part of it is now executable.
- Documentation date boundaries are corrected for 2026-05-11.

### Still pending

- Unified Evidence and shared report are now closer, but not yet merged into one end-to-end investigation contract.
- Additional false-positive baselines should be added for HTTP/object/USB and more industrial/vehicle samples.
- `SentinelContext.tsx` and bridge lifecycle still deserve risk-driven extraction, but only when they block mainline delivery.

## Next Step Order

1. Extend the shared report schema to more stable mainline modules that already produce reliable evidence.
2. Add more bundled sample assertions for benign HTTP / object / USB and for richer industrial / vehicle cases.
3. Add snapshot or contract checks for report JSON shapes at transport boundaries.
4. Only then continue `SentinelContext.tsx` / bridge lifecycle refactoring where it directly reduces delivery risk for the mainline investigation flow.

## Progress Update - 2026-05-11 11:47:50 +08:00

### Additional closure completed

A second wave of the shared investigation report rollout is now in place:

- USB now emits backend report payloads.
- C2 now emits family-level backend report payloads for CS / VShell.
- Object Export and Threat Hunting now present the same shared report structure from frontend-derived summaries.
- Public sample regression now also covers USB write-path and delete-baseline behavior.

### Updated position

The project is no longer only "planning" to return to mainline closure — the mainline report layer is now actively spreading across protocol, forensic-object, USB, C2, and hunting surfaces.

### Refined next-step order

1. Tighten the connection between unified Evidence and the shared investigation report contract.
2. Add more benign / false-positive sample baselines for HTTP, object extraction, USB, and hunting.
3. Add transport-boundary contract checks where report payloads cross desktop/http bridge surfaces.
4. Continue `SentinelContext.tsx` / lifecycle cleanup only when it directly improves delivery or reliability for these mainline paths.

## Progress Update - 2026-05-11 11:56:18 +08:00

### Evidence/report alignment completed

Unified Evidence now also emits a shared investigation-style report view on the frontend. This means the project has a clearer layered model:

- raw module analyses
- unified evidence aggregation
- shared investigation report presentation

### Additional regression closure

The bundled public sample gate now also asserts:

- benign HTTP should stay quiet for flag-style threat hunting
- public HTTP object traffic should extract non-executable objects as expected

### Refined next-step order

1. Add transport-boundary contract tests for evidence/report payloads across bridge surfaces.
2. Keep expanding benign / false-positive baselines for object extraction, hunting, and USB.
3. Revisit `SentinelContext.tsx` and lifecycle refactors only where the next mainline slice is concretely blocked.

## Progress Update - 2026-05-11 16:35:51 +08:00

### Transport-boundary contract coverage added

The report/evidence work is now defended not only at domain mappers and UI surfaces, but also at transport-facing client/bridge boundaries.

### Autonomous iteration note

Full frontend CI exposed timeout-only failures in the slow MISC tests during autonomous work. Those have now been hardened so the project can keep using end-to-end CI as the default iteration gate instead of falling back to partial validation.

### Refined next-step order

1. Continue benign / false-positive baseline expansion for object extraction, hunting, and USB.
2. If bridge aggregation becomes the next risk hotspot, add one more contract layer at `createHttpBridge` aggregation boundaries.
3. Keep `SentinelContext.tsx` / lifecycle refactors strictly risk-driven rather than returning to broad split-first work.

## Progress Update - 2026-05-11 16:41:07 +08:00

### Baseline calibration refined

The benign/public baseline work now captures a more realistic rule:

- ordinary USB mount/storage captures may contain write-like operations,
- but they must not escalate into high/critical mainline USB evidence without stronger supporting signals.

### Refined next-step order

1. Continue false-positive calibration for hunting/object/USB edge cases.
2. If needed, add one more contract layer at aggregated `createHttpBridge` composition boundaries.
3. Keep state/lifecycle refactors deferred until a concrete mainline blocker appears.

## Progress Update - 2026-05-11 17:16:52 +08:00

### Client contract coverage broadened

Object and hunting transport clients now join analysis/evidence paths in having explicit transport-level contract tests.

### Baseline nuance refined again

The public TFTP object sample reinforced the same principle used for USB mount calibration: some benign traces should be modeled with bounded expectations rather than forcing idealized extraction behavior.

### Refined next-step order

1. Continue false-positive calibration for object/hunting/USB edge cases.
2. If transport composition risk rises, add explicit `createHttpBridge` aggregation contract coverage.
3. Keep architecture refactors secondary to mainline detection/report/evidence correctness.

## Progress Update - 2026-05-11 17:20:24 +08:00

### Aggregation-level contract coverage added

The transport contract stack now spans:

- domain mappers
- transport clients
- desktop fallback bridge
- aggregated `createHttpBridge` composition

### Edge-case baseline calibration continued

The benign SMTP and TFTP cases further confirm the current strategy: calibrate around realistic invariants rather than forcing idealized outcomes from every public sample.

### Refined next-step order

1. Continue false-positive edge calibration for object/hunting/USB.
2. Keep searching for the next small contract seam with high anti-drift value.
3. Maintain architecture work as secondary to correctness and regression safety.

## Progress Update - 2026-05-11 17:59:51 +08:00

### Top-level bridge composition covered

The anti-drift transport coverage now reaches the bridge factory itself, not just individual clients and lower-level bridge layers.

### Baseline calibration continued

Benign MySQL and benign JPEG object paths now contribute explicit regression expectations alongside the earlier HTTP/SMTP/USB/TFTP coverage.

### Refined next-step order

1. Continue false-positive calibration for remaining object/hunting/USB edges.
2. Keep looking for the next small, high-value evidence/report contract seam.
3. Leave architecture refactors secondary to correctness, regression safety, and mainline investigative clarity.

## Progress Update - 2026-05-11 19:29:41 +08:00

### Object evidence became more decision-useful

Unified object evidence is no longer flat informational noise. Executable-class objects now stand out more clearly, while benign image/text paths remain informational.

### Refined next-step order

1. Continue false-positive calibration for remaining object/hunting/USB edge cases.
2. Prefer bounded evidence/report contract seams over broad refactors.
3. Keep UI structure work secondary unless it blocks the mainline investigation flow.
