# Desktop IPC MISC native binding design

> Scope: Round 12 design spike, Round 13 first runtime slice, Round 14 mutating-state isolation boundary, Round 15 package delete typed IPC, Round 16 package invoke typed IPC, Round 17 package import typed IPC, and Round 18 final compatibility audit. This document defines the safe typed IPC shape for the now-closed MISC desktop compatibility window.

## Current compatibility inventory

| Frontend operation | Current HTTP route | Body | Current status | Typed migration decision |
|---|---|---|---|---|
| `listMiscModules` | `GET /api/tools/misc/modules` | none | typed migrated | Migrated as `ListMiscModules()`. |
| `importMiscModulePackage` | `POST /api/tools/misc/import` | multipart zip file | typed migrated | Desktop release imports through `ImportMiscModulePackageFromPath(path string)`; browser-dev keeps multipart HTTP upload. |
| `deleteMiscModule` | `DELETE /api/tools/misc/packages/{id}` | none | typed migrated | Migrated as `DeleteMiscModulePackage(id string)`. |
| `runMiscModule` | `POST /api/tools/misc/packages/{id}/invoke` | JSON `{ values }` | typed migrated | Migrated as `RunMiscModulePackage(id string, values map[string]string)`; execution sandbox errors remain business errors, not IPC transport errors. |

Non-goals:

- Do not reclassify built-in WinRM/SMB3/NTLM/HTTP-Login/SMTP/MySQL/Shiro tools as generic MISC. Those already have typed DesktopApp bindings.
- Do not force browser-dev through Wails bindings. Browser-dev keeps HTTP multipart and SSE.
- Do not stream arbitrary zip blobs through typed JSON until file size limits and diagnostics are explicit.

## Proposed typed DesktopApp surface

Preferred desktop release shape:

- `ListMiscModules() ([]model.MiscModuleManifest, error)`
- `SelectMiscModulePackage() (openCaptureDialogResult, error)`
- `ImportMiscModulePackageFromPath(path string) (model.MiscModulePackageImportResult, error)`
- `DeleteMiscModulePackage(id string) error`
- `RunMiscModulePackage(id string, values map[string]string) (model.MiscModuleRunResult, error)`

Fallback-compatible shape if native file selection cannot be shared:

- `ImportMiscModulePackage(request { file_name: string, data_base64: string })`

The preferred path is file-path based because desktop release can avoid a large base64 payload through JS/Wails, while browser-dev can keep the existing multipart upload path.

## Required implementation boundary

Before mutating runtime migration:

- Move or expose MISC package manager operations behind a root DesktopApp-accessible service boundary, or add narrowly scoped backend proxy helpers that do not create new generic `/api/...` string expansion in frontend clients.
- Preserve current package validation from `backend/internal/miscpkg`: zip file count limits, file size limits, path traversal checks, manifest validation, execution timeout, and Python host bridge sandbox behavior.
- Keep import/delete/invoke audit semantics equivalent to the HTTP routes.
- Keep `frontend/scripts/check-desktop-generic-ipc-allowlist.mjs` and `frontend/scripts/check-desktop-misc-compat-inventory.mjs` green as routes move from explicit compatibility into typed migration.
- Use the smoke-owned package directory boundary for any desktop mutating smoke. `scripts/check-desktop-ipc-smoke.ps1` creates per-run directories under `output/desktop-ipc-smoke/misc-packages`, sets `MEOW_TRAFFIC_MISC_PACKAGE_DIR`, and verifies the backend runtime identity reports the same directory.

## Error taxonomy

- Business empty result: no custom packages installed, empty module list beyond built-ins, or successful module execution with empty text/table.
- Business error: invalid package, duplicate module id, path traversal rejection, missing module, unsupported runtime, module execution timeout, module execution stderr.
- Desktop IPC transport error: Wails binding missing, Wails invocation timeout, binding argument mismatch, backend proxy unreachable.
- Compat fallback: browser-dev HTTP multipart upload only. Desktop MISC runtime routes are no longer classified as generic IPC compatibility once the matching typed binding exists.

## Migration readiness checklist

The native import migration is considered complete only when all are true:

- `ImportMiscModulePackageFromPath(path string)` is added to binding checks without removing browser-dev multipart HTTP.
- Frontend MISC import can choose the desktop typed file-path route when Wails exposes a real local path, and can keep the existing `File` multipart route outside desktop typed mode.
- Root Go contract tests cover the service call or backend route used by the typed import method, including validation of safe zip import behavior.
- WebView smoke uses the isolated package directory if it performs a real import, or explicitly records why only binding availability was checked.
- Browser-dev HTTP multipart remains tested.

## Current decision

Status: `runtime-complete; list-import-delete-run-typed`.

Round 13 migrated the non-mutating module list route through `ListMiscModules()`. Round 14 established smoke-owned temporary package-state isolation for desktop release, desktop WebView typed smoke, and browser-dev, with backend runtime identity verification. Round 15 migrated package deletion through `DeleteMiscModulePackage(id string)` and kept smoke non-destructive by asserting binding availability inside the isolated MISC package boundary. Round 16 migrated package invocation through `RunMiscModulePackage(id string, values map[string]string)` while preserving backend sandbox errors as business errors. Round 17 migrates desktop package import through `SelectMiscModulePackage()` plus `ImportMiscModulePackageFromPath(path string)` so Wails carries a local path instead of a zip blob; browser-dev keeps multipart HTTP upload for debugging.

Round 18 closes the MISC desktop compatibility window: `frontend/scripts/check-desktop-misc-compat-inventory.mjs` treats modules/import/delete/invoke as migrated typed desktop routes and expects zero remaining MISC desktop compatibility routes. Browser-dev multipart upload is intentionally retained as HTTP debugging compatibility, not as a desktop generic IPC exception.
