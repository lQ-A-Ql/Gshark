# GShark Sentinel Frontend Visual System

GShark Sentinel is a dense security traffic investigation workbench. The UI should feel like a light forensic operations console: precise, calm, data-heavy, and purpose-built for repeated packet, stream, payload, and evidence review.

## Direction

- Use the existing light forensic glass cockpit language.
- Prefer continuous rectangular information regions over floating rounded cards.
- Keep surfaces quiet and low-boundary; reserve strong contrast for payloads, code, warnings, selected rows, and destructive actions.
- Use route accent colors to orient the analyst, not to decorate every element.
- Keep controls compact and scannable. This is an analyst tool, not a marketing page.

## Surface Roles

- Page shell: `gshark-page-bg`, `gshark-glass-shell`, and `gshark-theme-main` belong to the app layout.
- Page content: use `PageShell` with tiled layout for normal analysis pages.
- Region/container: use `gshark-tile`, `gshark-tile-grid`, `gshark-tile-header`, `gshark-tile-toolbar`, or `gshark-tile-table`.
- Soft inner emphasis: use `gshark-soft-fill`.
- Chips and small labels: use `gshark-diffuse-chip` or `AnalysisBadge`.
- Buttons and icon controls: use shared `Button` or `gshark-control`, `gshark-control-primary`, `gshark-control-ghost`.
- Inputs/selects/forms: use shared `Input`, `Select`, `gshark-field`, or `gshark-form-surface`.
- Status: use `StatusHint`, `gshark-status-dot`, `gshark-risk-accent`, and `gshark-evidence-accent`.
- Stream pages: keep their dedicated workbench structure; only sync controls with `gshark-stream-control-cluster`, `gshark-stream-segment`, and `gshark-stream-value`.

## Avoid

- Do not add new page-level radial or linear decorative backgrounds inside pages.
- Do not introduce floating SaaS card stacks, card-in-card sections, or oversized hero marketing layouts.
- Avoid raw `bg-white`, `bg-slate-50`, `border-slate-200`, `shadow-sm`, `rounded-xl`, and `rounded-2xl` in normal page content.
- Avoid one-off class strings for status blocks, code previews, and chips when a shared primitive already fits.
- Do not use decorative blobs, orbs, bokeh, or purely ornamental illustration.

## Allowed Exceptions

- Dialogs, tooltips, select menus, and floating popovers may keep stronger panel identity.
- Code, terminal, hex, raw payload, JSON, and media preview blocks may keep stronger contrast for readability.
- Round marks are allowed for status dots, graph points, avatar-like indicators, and small badges where the shape carries meaning.
- Stream payload workbenches may keep specialized layouts and backgrounds when they improve payload inspection.

## Validation

For visual implementation rounds, run the relevant Vitest files plus:

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run typecheck
pnpm run lint
pnpm run format:check
pnpm run size:check
pnpm run boundary:check
```

Before handoff, prefer full frontend CI and browser screenshots across the main routes. Check for horizontal overflow, unreadable glass text, clipped controls, and accidental stream-page structure migration.
