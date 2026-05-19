# Frontend Engineering Report - 2026-05-15

Author: Codex

Timestamp: 2026-05-15 00:30:47 +08:00

## Summary

Completed a documentation-only frontend engineering audit for `frontend/`. No frontend source, build config, tests, lockfiles, or backend files were changed. The audit output is versioned in `docs/frontend-engineering-audit-spec-2026-05-15.md`.

The frontend is in a healthy governance state: strict TypeScript, ESLint, pnpm-only package management, scoped Prettier checks, size budgets, import-boundary checks, raw-`any` checks for `clients`, `mappers`, and `wire`, and broad Vitest coverage are all active and currently passing.

Overall frontend engineering score: 82/100.

## Files Added

- `docs/frontend-engineering-audit-spec-2026-05-15.md`
- `docs/audit-development-report-archive-2026-05-15/frontend-engineering-report-2026-05-15.md`

## Validation Performed

The following commands were run before writing the audit and passed:

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

Observed test baseline:

- 208 test files passed.
- 605 tests passed.

Documentation diff should be reviewed with:

```powershell
cd C:\Users\QAQ\Desktop\gshark
git diff -- docs
```

## Current Findings

| Area | Result | Notes |
|---|---|---|
| Architecture boundaries | Strong | `check-boundaries.mjs` enforces integration, page, feature, state, mapper, client, UI primitive, and shared analysis boundaries. |
| Type safety | Strong | Strict TypeScript is enabled; raw `any` is blocked in `clients`, `mappers`, and `wire`. |
| Contract safety | Good but incomplete | Frontend WireDTO and mapper gates are strong, but backend producer schemas/snapshots remain the open cross-cutting risk. |
| Testability | Strong | Vitest coverage is broad across state, clients, mappers, pages, and components. Browser-level confidence is still a gap. |
| Runtime reliability | Good | Abort signals, capture task scope, and async workflow tests reduce stale request risk. Long-running analysis surfaces still need continued discipline. |
| Build governance | Strong | pnpm-only, size budget, lint, format, typecheck, and CI script composition are all present. |
| Maintainability | Moderate-good | `SentinelContext.tsx`, `httpBridge.ts`, `bridgeTypes.ts`, and large workbench/page modules remain the main complexity hotspots. |
| UI engineering | Good | The UI matches a dense operational security workbench. Visual regression and real-browser journey checks would improve confidence. |

## Risk Ranking

1. `P2-6` contract/codegen question remains the main cross-stack risk. The frontend has consumer-side mappers, but backend response drift is not yet anchored by producer-side schema or snapshot gates.
2. Aggregate `backendClients` usage can still become dependency gravity. Pages are guarded, but feature hooks, state hooks, and a few components still depend on the aggregate.
3. `SentinelContext.tsx` remains a broad runtime coordinator. Future changes should extract stable, tested slices instead of adding more direct workflow state.
4. Browser-level validation is not yet part of normal frontend checks. jsdom tests are broad but do not prove dense table/dialog layout, scroll behavior, or Wails bridge behavior.
5. Dynamic payloads, markdown, custom module output, localStorage settings, and `window.go` bridge access need an explicit frontend untrusted-data rule.

## Document Review

- `docs/README.md`: Current direction is still aligned. It says the project should prioritize evidence schema, protocol reports, real sample validation, and false-positive suppression while keeping frontend consistency and build size as maintenance tracks. This audit supports that framing.
- `docs/governance-defect-register.json`: Only `P2-6` is open. Frontend WireDTO gates make the next step a producer/consumer contract pilot rather than another consumer-only mapper cleanup.
- `docs/backend-engineering-audit-spec-2026-05-14.md`: Backend audit identifies API contract maturity and type mixing as risks. Frontend findings match that and recommend a small stable schema/snapshot pilot.
- `docs/misc-module-interface.md`: MISC module form schemas, table output, host bridge, and script backends are relevant to frontend trust and dynamic rendering review. The frontend audit calls this out as a security-boundary concern.

## Self-Review

- Scope stayed documentation-only, matching the requested plan.
- Existing unrelated worktree changes were not touched.
- The audit avoids broad rewrite recommendations and favors small follow-up slices.
- The plan keeps the UI identity as a network-security investigation workbench instead of drifting into generic dashboard polish.
- The next actionable engineering item should connect frontend WireDTO/mappers with backend contract baselines for a small stable API surface.

## Next Step

Run a contract-governance pilot for one stable API group, preferably `evidence`, `traffic stats`, `runtime snapshot`, or `stream index`, then decide whether `P2-6` should become schema snapshots, JSON Schema/OpenAPI generation, or remain handwritten with stricter fixtures.
