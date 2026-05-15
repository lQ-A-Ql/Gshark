# Frontend Engineering Audit Spec - 2026-05-15

Author: Codex

Timestamp: 2026-05-15 00:30:47 +08:00

## 1. Background

GShark-Sentinel frontend has moved beyond rapid feature delivery into an engineering-governance phase. The application is a dense security traffic analysis workbench rather than a marketing-style web UI: packet navigation, stream inspection, C2/APT evidence, protocol-specific panels, media/object extraction, MISC tools, runtime settings, and long-running capture workflows are all active frontend surfaces.

This audit records the current frontend engineering position and defines the next executable improvement plan. It treats `docs/README.md`, `docs/governance-defect-register.json`, `docs/misc-module-interface.md`, and `docs/backend-engineering-audit-spec-2026-05-14.md` as current facts. Historical `docs/audit-development-report-archive-*` reports are evidence trails only.

## 2. Current Facts

- Frontend lives under `frontend/` and uses Vite, React 18, TypeScript strict mode, Tailwind CSS 4, Radix UI, lucide-react, Vitest, ESLint, and Prettier.
- Package management is pnpm-only. `frontend/package.json` declares `packageManager: pnpm@10.31.0`; `frontend/pnpm-lock.yaml` is the maintained lockfile.
- CI path is `pnpm run ci`, which runs package-manager, typecheck, ESLint, scoped format, size budget, boundary, raw-`any`, Vitest, and Vite build checks.
- Source layout is already meaningfully layered: `src/app/integrations`, `core/types`, `features`, `state`, `pages`, `components`, `misc`, `layouts`, `hooks`, and `utils`.
- Integration code is split into `clients`, `mappers`, and `wire` DTO packages. Client, mapper, and wire raw `any` checks are in CI.
- `frontend/scripts/check-boundaries.mjs` enforces import-boundary rules for integrations, pages, features, state, UI primitives, shared analysis components, clients, and mappers.
- Current frontend corpus has about 796 TypeScript/TSX files, including about 201 test files.
- Largest current complexity hotspots include `src/app/state/SentinelContext.tsx`, `src/app/integrations/httpBridge.ts`, `src/app/integrations/bridgeTypes.ts`, `src/app/components/useStreamDecoderWorkbench.ts`, and several dense page/workbench files.
- The governance register currently keeps `P2-6` open: evaluate mapper schema/codegen feasibility after WireDTO gates stabilize.

## 3. Validation Baseline

The following frontend validation commands passed during this audit:

| Command | Result |
|---|---|
| `pnpm run typecheck` | Passed |
| `pnpm run lint` | Passed |
| `pnpm run boundary:check` | Passed |
| `pnpm run client:any:check` | Passed |
| `pnpm run mapper:any:check` | Passed |
| `pnpm run wire:any:check` | Passed |
| `pnpm run format:check` | Passed |
| `pnpm run package-manager:check` | Passed |
| `pnpm run size:check` | Passed |
| `pnpm run test:run` | Passed: 208 test files, 605 tests |

`pnpm run build` and full `pnpm run ci` should remain the final verification gate for implementation work that changes frontend source or build behavior. This audit did not modify frontend source.

## 4. Engineering Assessment

| Dimension | Score | Assessment |
|---|---:|---|
| Architecture boundaries | 84/100 | The import-boundary script is unusually strong for a frontend codebase and already blocks common layering regressions. Remaining risk is dependency gravity around aggregate `backendClients` and a few large context/workbench modules. |
| Type and contract safety | 82/100 | TypeScript strict mode is active; `clients`, `mappers`, and `wire` reject raw `any`; WireDTOs isolate unknown backend payloads. The main gap is that producer-side backend schemas are still handwritten/implicit, matching open governance item `P2-6`. |
| Testability | 86/100 | Vitest coverage is broad across state workflows, mapper normalization, clients, pages, and UI interactions. Gaps remain around real Wails bridge behavior, browser end-to-end flows, visual regressions, and large capture performance. |
| Runtime reliability | 80/100 | Abort signals, capture task scopes, cancellation helpers, cache keys, and workflow-specific state tests reduce stale async updates. Risk remains in long-running analysis flows that directly call `backendClients` from scattered feature hooks. |
| Build and dependency governance | 88/100 | pnpm-only gate, size budget, scoped format, strict typecheck, ESLint, and chunking rules are in place. The risk is keeping Vite/Tailwind/React upgrades deliberate as the app grows. |
| Security boundary hygiene | 78/100 | The frontend treats backend responses as untrusted `unknown` at wire boundaries and uses mappers to normalize. Dynamic payload rendering, markdown rendering, Wails `window.go`, localStorage, and downloaded artifacts still deserve explicit security review rules. |
| Maintainability | 76/100 | The codebase has split many behaviors into hooks and feature modules, but `SentinelContext`, `bridgeTypes`, bridge aggregation, and several page-level workbenches remain broad ownership points. |
| UI engineering consistency | 82/100 | The UI is aligned with an operational security workbench: dense panels, tables, filters, status surfaces, and evidence actions. The next maturity step is visual regression coverage and more consistent empty/loading/error states across protocol modules. |
| Overall | 82/100 | Frontend engineering governance is real and enforced by CI. Next work should focus on contract generation/snapshots, reducing aggregate bridge gravity, and adding browser-level validation rather than broad rewrites. |

## 5. Primary Risks

### 5.1 Handwritten contract drift

The frontend currently protects itself with handwritten WireDTOs and mappers. This is a strong consumer-side pattern, but backend response shape drift can still arrive as runtime fallback behavior instead of an explicit contract failure.

Risk indicators:

- `P2-6` is the only open governance item.
- WireDTOs intentionally use `unknown`, but there is no generated schema or producer-side snapshot tied to them.
- Packet, stream, traffic, protocol-tool, plugin, and MISC payloads include dynamic or partially typed shapes.

Recommended next slice:

- Add schema/codegen feasibility notes for a small, stable response group first, such as traffic stats, evidence records, runtime tool snapshot, and stream index.
- Prefer contract snapshots before full OpenAPI/codegen if backend shape ownership is still moving.

### 5.2 Aggregate `backendClients` dependency gravity

`backendClients` is properly centralized under integrations, but many feature hooks, state hooks, and a few components still import the aggregate directly. This is acceptable today, but it can make feature-level tests depend on a broad mock surface.

Risk indicators:

- `SentinelContext.tsx` and state hooks coordinate multiple backend domains.
- Several feature hooks import `backendClients` directly instead of accepting narrow domain clients consistently.
- Components such as stream decoder helpers still reach into integration clients.

Recommended next slice:

- Continue moving new backend calls behind feature hooks or narrow injected client interfaces.
- Keep `pages` free of direct aggregate imports; the current boundary gate already enforces this.

### 5.3 Wide frontend runtime context

`SentinelContext.tsx` remains the largest frontend ownership point. It composes capture lifecycle, packet pagination, stream loading, selected packet resources, tool runtime, media cancellation, recent captures, progress, and derived views.

Risk indicators:

- It has broad dependency fan-in and fan-out.
- It must coordinate capture replacement cancellation correctly.
- New workflow state can be added there by convenience.

Recommended next slice:

- Extract only stable, already-tested workflow bundles rather than rewriting the provider.
- Keep provider behavior unchanged and verify with existing state hook tests.

### 5.4 UI behavior coverage stops before real browser confidence

Vitest coverage is broad, but most tests run in jsdom. That is enough for mapper, state, and many component interactions, but it does not fully validate layout density, browser event timing, scrolling, large tables, file download behavior, or Wails-like bridge integration.

Risk indicators:

- No explicit Playwright or visual regression gate is currently part of `pnpm run ci`.
- Large capture workflows and packet/stream screens are layout-sensitive.
- UI defects can still pass strict TypeScript and jsdom tests.

Recommended next slice:

- Add a small smoke suite for core user journeys after the app can be served predictably: workspace load shell, packet table navigation, stream dialog/workbench, evidence filtering, MISC payload decoder.
- Keep screenshots as optional local evidence first, then decide whether to promote to CI.

### 5.5 Dynamic content and local bridge security review

The frontend handles markdown, decoded payloads, extracted artifacts, stream bodies, dynamic module output, localStorage settings, and a Wails desktop bridge. These are expected for a security tool, but they need explicit review rules because many inputs are attacker-controlled capture data.

Risk indicators:

- `react-markdown` renders release/report content.
- Stream and decoded payload panes display untrusted traffic-derived content.
- `window.go` bridge detection uses a narrow unavoidable cast.
- Custom module and plugin outputs can affect UI tables/forms.

Recommended next slice:

- Document a frontend untrusted-data rule: payloads render as text by default, markdown sources must be trusted or sanitized, artifact downloads must preserve backend-provided tokens safely, and bridge calls stay behind mappers/clients.

## 6. Non-Goals

- Do not replace Vite, React, Radix UI, Tailwind, or pnpm.
- Do not introduce a new global state framework as an audit reaction.
- Do not rewrite `SentinelContext` or bridge aggregation in one pass.
- Do not generate TypeScript DTOs from backend models until a small schema pilot proves field naming, optionality, and dynamic payload policy.
- Do not turn UI polish into a marketing-site redesign; this product should remain a dense security investigation workbench.
- Do not treat local historical archive reports as canonical current facts.

## 7. Task Plan

### Epic 0: Audit documentation baseline

| Task | Title | Deliverable | Acceptance |
|---|---|---|---|
| FE-SPEC-0.1 | Create frontend engineering audit spec | `docs/frontend-engineering-audit-spec-2026-05-15.md` | Includes background, current facts, scoring, risks, non-goals, task plan, and validation rules. |
| FE-SPEC-0.2 | Append frontend audit report | `docs/audit-development-report-archive-2026-05-15/frontend-engineering-report-2026-05-15.md` | Records commands, findings, document review, self-review, and timestamp. |

### Epic 1: Contract governance pilot

| Task | Title | Deliverable | Acceptance |
|---|---|---|---|
| FE-CONTRACT-1.1 | Pick first schema pilot surface | Short design note or governance update | Select stable responses: evidence, traffic stats, runtime snapshot, or stream index. |
| FE-CONTRACT-1.2 | Add producer/consumer contract baseline | Backend snapshot/schema test plus frontend mapper fixture | Backend shape drift fails before UI fallback hides it. |
| FE-CONTRACT-1.3 | Decide codegen threshold | Governance note for `P2-6` | Defines when JSON Schema/OpenAPI/DTO generation is worth the maintenance cost. |

### Epic 2: Bridge and dependency tightening

| Task | Title | Deliverable | Acceptance |
|---|---|---|---|
| FE-BRIDGE-2.1 | Narrow feature hook client dependencies | Focused hook signatures for new or touched modules | New feature hooks accept narrow clients or domain projections, not the aggregate bridge by default. |
| FE-BRIDGE-2.2 | Keep page boundary zero-regression | Existing `boundary:check` | Pages continue to avoid direct aggregate `backendClients` imports. |
| FE-BRIDGE-2.3 | Review component-level backend calls | Small refactor candidates only | Backend calls in generic components are moved only when behavior is already covered by tests. |

### Epic 3: Runtime and UI confidence

| Task | Title | Deliverable | Acceptance |
|---|---|---|---|
| FE-RUNTIME-3.1 | Add browser smoke plan | Playwright or browser-use plan for local Vite/Wails-like target | Covers workspace shell, packet table, stream view, evidence filters, and MISC decoder. |
| FE-RUNTIME-3.2 | Standardize untrusted-content rendering rules | Frontend security note | Payload, markdown, artifact, and module-output rendering rules are explicit. |
| FE-RUNTIME-3.3 | Add visual/interaction evidence for dense screens | Optional local screenshots or smoke tests | Confirms critical tables and dialogs remain usable at desktop sizes. |

### Epic 4: Maintainability slices

| Task | Title | Deliverable | Acceptance |
|---|---|---|---|
| FE-MAINT-4.1 | Split only touched large modules | Behavior-preserving extractions | Extract stable helper/hooks from `SentinelContext`, stream decoder, or page workbenches only when tests already cover behavior. |
| FE-MAINT-4.2 | Keep route and layout ownership stable | No broad route/layout rewrite | Navigation, sidebar, and app shell stay predictable for users. |
| FE-MAINT-4.3 | Continue feature-local test additions | Focused Vitest tests | Every risky extraction keeps or improves current behavior coverage. |

## 8. Validation Rules

For documentation-only audit work:

```powershell
cd C:\Users\QAQ\Desktop\gshark
git diff -- docs
```

For frontend source changes:

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run typecheck
pnpm run lint
pnpm run boundary:check
pnpm run client:any:check
pnpm run mapper:any:check
pnpm run wire:any:check
pnpm run format:check
pnpm run package-manager:check
pnpm run size:check
pnpm run test:run
```

For handoff or CI-equivalent confidence:

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run ci
```

## 9. Document Review Notes

- `docs/README.md` correctly states that current project direction remains offline traffic analysis, protocol-specific investigation, dangerous-application triage, and evidence-chain workbench delivery. The frontend audit aligns with that direction.
- `docs/governance-defect-register.json` currently has one open item, `P2-6`, which directly maps to this audit's contract-governance risk.
- `docs/backend-engineering-audit-spec-2026-05-14.md` identifies backend API contract maturity as a primary risk. The frontend has consumer-side gates, so the next cross-cutting improvement should be a small producer/consumer contract pilot rather than a broad codegen jump.
- `docs/misc-module-interface.md` remains relevant to frontend engineering because custom module form schemas, table results, and host bridge exposure create dynamic UI and trust-boundary concerns.
