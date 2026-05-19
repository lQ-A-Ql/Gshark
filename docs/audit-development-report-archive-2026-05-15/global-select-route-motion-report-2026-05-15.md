# Global Select and Route Motion Report - 2026-05-15

Author: Codex

Timestamp: 2026-05-15 01:11:31 +08:00 (Asia/Shanghai)

## Summary

Implemented the global Select and page transition optimization plan for `frontend/` while keeping the current frontend engineering gates intact. No backend, API, mapper, wire DTO, Vite config, package manager, lockfile, or dependency changes were made.

The implementation keeps the UI direction aligned with a dense network-security workbench: compact controls, low-noise surfaces, clear focus rings, restrained blue/cyan/rose state tones, and CSS-only page motion with reduced-motion fallback.

## Files Changed

- `frontend/src/app/components/ui/select.tsx`
- `frontend/src/app/components/ui/select.test.tsx`
- `frontend/src/app/components/StreamDecoderControls.tsx`
- `frontend/src/app/features/c2/C2DecryptFormControls.tsx`
- `frontend/src/app/features/object/ObjectExportPanels.tsx`
- `frontend/src/app/features/object/ObjectExportPanels.test.tsx`
- `frontend/src/app/features/usb/UsbMassStorageTables.tsx`
- `frontend/src/app/features/usb/UsbMassStorageTables.test.tsx`
- `frontend/src/app/features/usb/UsbTablesSplit.test.tsx`
- `frontend/src/app/layouts/MainLayout.tsx`
- `frontend/src/app/layouts/MainLayout.test.ts`
- `frontend/src/app/misc/modules/GenericMiscSelectField.tsx`
- `frontend/src/app/misc/modules/GenericMiscSelectField.test.tsx`
- `frontend/src/styles/theme.css`
- `frontend/src/test/setup.ts`

## Implementation Notes

- Extended the Radix-based UI Select primitive with `SelectOption`, `SelectControl`, and `SelectField`.
- Preserved the existing low-level exports: `Select`, `SelectTrigger`, `SelectContent`, `SelectItem`, `SelectGroup`, and `SelectValue`.
- Added internal empty-string sentinel mapping so external callers can keep using `""` for placeholder/no-value semantics while avoiding Radix item value restrictions.
- Migrated real select surfaces for object export filtering, USB Mass Storage filters, C2 decrypt controls, stream decoder settings, and MISC custom module forms.
- Left `DisplayFilterBar` datalist behavior untouched because it is an input suggestion surface, not a select control.
- Replaced the MISC custom select dropdown state machine with the global Select field while preserving placeholder, disabled, and cyan-tone behavior.
- Added route motion direction metadata in `MainLayout` and tuned CSS-only page transition timing, translation, blur, and reduced-motion behavior in `theme.css`.
- Added jsdom shims for Radix Select tests: pointer events, pointer capture, and `scrollIntoView`.

## Tests Added Or Updated

- Global Select coverage for label/help rendering, option selection, empty string sentinel mapping, and disabled options.
- Object export toolbar select interaction coverage.
- USB Mass Storage device/LUN select coverage, including the compatibility barrel test.
- MISC custom select placeholder and selection coverage.
- MainLayout route motion direction coverage.

## Validation Performed

The targeted migration tests passed:

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec vitest run src/app/components/ui/select.test.tsx src/app/features/object/ObjectExportPanels.test.tsx src/app/features/usb/UsbMassStorageTables.test.tsx src/app/misc/modules/GenericMiscSelectField.test.tsx src/app/layouts/MainLayout.test.ts
pnpm exec vitest run src/app/features/usb/UsbTablesSplit.test.tsx src/app/features/usb/UsbMassStorageTables.test.tsx
```

The full frontend CI passed:

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run ci
```

Observed final CI result:

- `package-manager:check`: passed
- `typecheck`: passed
- `lint`: passed with `--max-warnings=0`
- `format:check`: passed
- `size:check`: passed
- `boundary:check`: passed
- `client:any:check`: passed
- `mapper:any:check`: passed
- `wire:any:check`: passed
- `test:run`: 212 test files passed, 612 tests passed
- `build`: passed

## Document Review

- `docs/README.md`: The change remains aligned with the documented frontend governance direction: keep UI consistency, bundle size, type safety, and test discipline as active maintenance tracks.
- `docs/frontend-engineering-audit-spec-2026-05-15.md`: The implementation directly exercises the audit recommendations around UI engineering consistency, component reuse, boundary hygiene, and maintaining existing gates during frontend refactors.
- `docs/governance-defect-register.json`: No change to the remaining open `P2-6` contract/codegen item. This work did not touch wire DTOs, mappers, clients, or backend producer contracts.
- `docs/backend-engineering-audit-spec-2026-05-14.md`: No backend contract surface changed. The frontend Select work stays independent from backend API maturity risks.

## Self-Review

- Scope stayed within frontend UI components, affected page/component tests, route animation CSS, and this report.
- No new dependencies were introduced.
- No package manager files were changed.
- The global Select component stays domain-free inside `components/ui`.
- The route animation remains CSS-only and respects `prefers-reduced-motion`.
- MainLayout was kept within the existing size budget after adding route motion metadata.

## Follow-Up

The next useful slice is visual/browser verification of the densest select surfaces in a running app, especially USB Mass Storage filters, MISC custom module forms, and decoder settings inside scrollable workbench panels. The current jsdom coverage verifies semantics and value propagation, while real browser checks would add confidence for portal positioning and clipped-container behavior.
