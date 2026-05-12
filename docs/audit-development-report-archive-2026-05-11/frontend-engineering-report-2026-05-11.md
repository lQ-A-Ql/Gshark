# Frontend Engineering Report - 2026-05-11

## Round 182 - Lifecycle TLS Domain Migration

Time: 2026-05-12 08:52:00 +08:00  
Author: Codex

### Scope

- Continued bridge removal inside backend lifecycle controls.
- Kept local TLS config merge behavior and connected-backend sync behavior unchanged.

### Changes

- Updated `state/hooks/useBackendLifecycleControls.ts` to call `backendClients.securityMaterial.updateTLSConfig`.
- Updated both lifecycle control and full lifecycle hook test mocks to expose the security material domain client.

### Validation

- `pnpm exec vitest run src/app/state/hooks/useBackendLifecycleControls.test.tsx src/app/state/hooks/useBackendLifecycle.test.tsx src/app/integrations/bridgeDomains.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run size:check` - passed.
- `pnpm run ci` - passed after adding the missing lifecycle harness mock export; final run included 179 test files / 495 tests and production build.

### Review

- Lifecycle TLS writes now use the security material domain client.
- Remaining direct `bridge` imports are limited to lifecycle startup wiring and Sentinel context compatibility wiring.

---

## Round 181 - TLS Dialog Domain Migration

Time: 2026-05-12 08:46:30 +08:00  
Author: Codex

### Scope

- Continued bridge removal with the TLS / HTTPS decryption dialog.
- Kept TLS config saving, capture reload, and display-filter restore behavior unchanged.

### Changes

- Updated `components/TLSDecryptionDialog.tsx` to call `backendClients.securityMaterial.updateTLSConfig` instead of aggregate `bridge.updateTLSConfig`.
- Updated the TLS dialog test mock to expose `backendClients.securityMaterial.updateTLSConfig`.

### Validation

- `pnpm exec vitest run src/app/components/TLSDecryptionDialog.test.tsx src/app/integrations/bridgeDomains.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run size:check` - passed.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- TLS dialog config writes now use the security material domain client.
- Remaining direct `bridge` imports are limited to backend lifecycle controls and Sentinel context wiring.

---

## Round 180 - Media Workflow Domain Migration

Time: 2026-05-12 08:41:50 +08:00  
Author: Codex

### Scope

- Continued bridge removal across media playback and transcription workflows.
- Kept media session rendering, transcription batching, playback dialogs, and error routing unchanged.

### Changes

- Updated `features/media/useMediaPlaybackWorkflow.ts` to call `backendClients.media.downloadMediaArtifact`, `backendClients.runtime.checkFFmpeg`, and `backendClients.media.getMediaPlaybackBlob`.
- Updated `features/media/useMediaTranscriptionWorkflow.ts` to call `backendClients.media.getMediaBatchTranscriptionStatus`, `backendClients.runtime.checkSpeechToText`, `backendClients.media.transcribeMediaArtifact`, `backendClients.media.startMediaBatchTranscription`, `backendClients.media.cancelMediaBatchTranscription`, and `backendClients.media.exportMediaBatchTranscription`.
- No media-specific tests needed mock changes beyond the existing integration coverage.

### Validation

- `pnpm exec vitest run src/app/features/media/useMediaTranscriptionWorkflow.test.ts src/app/features/media/MediaOverviewPanels.test.tsx src/app/features/media/MediaSessionTableUtils.test.ts src/app/features/media/MediaSessionCells.test.tsx` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run boundary:check` - passed.
- `pnpm run size:check` - passed.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- Media playback and transcription workflows now use the media and runtime domain clients.
- Remaining direct `bridge` imports are now concentrated in lifecycle controls, sentinel context wiring, and TLS dialog handling.

---

## Round 179 - Stream Decoder Domain Migration

Time: 2026-05-12 08:37:30 +08:00  
Author: Codex

### Scope

- Continued bridge removal in the shared stream payload decoder workbench hooks.
- Kept decoder settings, candidate inspection, batch decode, and payload overwrite behavior unchanged.

### Changes

- Updated `components/useStreamDecoderWorkbench.ts` to call `backendClients.stream.decodeStreamPayload`.
- Updated `components/useStreamPayloadInspection.ts` to call `backendClients.stream.inspectStreamPayload`.
- Moved MISC page test mocks for decode/inspect into `backendClients.stream` while preserving remaining legacy bridge mocks for unmigrated consumers.

### Validation

- `pnpm exec vitest run src/app/pages/MiscTools.test.tsx src/app/pages/MiscTools.payloadHints.test.tsx src/app/pages/MiscTools.sessions.test.tsx src/app/pages/MiscTools.smb3.test.tsx src/app/pages/MiscTools.customModules.test.tsx src/app/integrations/bridgeDomains.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run size:check` - passed.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- Stream payload decode, inspection, and source loading now all use the stream domain client.
- Remaining direct bridge usage is now mostly lifecycle/runtime, media workflow, TLS config, and Sentinel context wiring.

---

## Round 178 - Payload WebShell Source Domain Migration

Time: 2026-05-12 08:33:10 +08:00  
Author: Codex

### Scope

- Continued bridge removal with the MISC payload webshell decoder module.
- Kept source discovery, payload drafting, sample insertion, source selection, and decoded-workbench rendering unchanged.

### Changes

- Updated `misc/modules/PayloadWebShellDecoderModule.tsx` to import `backendClients` instead of aggregate `bridge`.
- Replaced payload source loading with `backendClients.stream.listStreamPayloadSources`.
- Updated MISC page tests to expose the stream domain client and compressed mock scaffolding to stay under size budgets.

### Validation

- `pnpm exec vitest run src/app/pages/MiscTools.test.tsx src/app/pages/MiscTools.payloadHints.test.tsx src/app/pages/MiscTools.sessions.test.tsx src/app/pages/MiscTools.smb3.test.tsx src/app/pages/MiscTools.customModules.test.tsx src/app/integrations/bridgeDomains.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run boundary:check` - passed.
- `pnpm run size:check` - passed after removing one stale mock line.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- Payload webshell source loading now uses the stream domain client.
- Remaining direct bridge usage is concentrated in the shared stream decoder/inspection helpers and backend lifecycle/runtime control paths.

---

## Round 177 - MISC Tools Page Domain Client Migration

Time: 2026-05-12 08:27:35 +08:00  
Author: Codex

### Scope

- Continued direct aggregate bridge removal with the MISC tools page shell.
- Kept module list loading, default expansion/mounting, package import, category selection, and reload-after-import behavior unchanged.

### Changes

- Updated `pages/MiscTools.tsx` to import `backendClients` instead of aggregate `bridge`.
- Replaced module list and package import calls with `backendClients.miscModule.listMiscModules` and `backendClients.miscModule.importMiscModulePackage`.
- Updated MISC page test mocks to expose the misc-module domain client and compressed mocks to stay under size budgets.

### Validation

- `pnpm exec vitest run src/app/pages/MiscTools.test.tsx src/app/pages/MiscTools.sessions.test.tsx src/app/pages/MiscTools.smb3.test.tsx src/app/pages/MiscTools.payloadHints.test.tsx src/app/pages/MiscTools.customModules.test.tsx src/app/integrations/bridgeDomains.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run boundary:check` - passed.
- `pnpm run size:check` - passed after mock compression.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- MISC module list/import, custom execution, and custom deletion are now on the misc-module domain client.
- Remaining MISC aggregate bridge usage is concentrated in payload webshell decoding and shared stream decoder/payload inspection helpers.

---

## Round 176 - Generic MISC Module Domain Client Migration

Time: 2026-05-12 08:23:05 +08:00  
Author: Codex

### Scope

- Continued direct aggregate bridge removal with custom MISC module execution and deletion.
- Kept schema-driven form rendering, result rendering, delete confirmation, and module-list refresh behavior unchanged.

### Changes

- Updated `misc/modules/GenericMiscModule.tsx` to import `backendClients` instead of aggregate `bridge`.
- Replaced generic module invoke and delete calls with `backendClients.miscModule.runMiscModule` and `backendClients.miscModule.deleteMiscModule`.
- Updated custom MISC module tests to expose the misc-module domain client.

### Validation

- `pnpm exec vitest run src/app/pages/MiscTools.customModules.test.tsx src/app/integrations/bridgeDomains.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run boundary:check` - passed.
- `pnpm run size:check` - passed.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- Generic custom module execution and deletion no longer depend on the aggregate bridge.
- `pages/MiscTools.tsx` still owns misc-module list/import through the aggregate bridge and remains the next small MISC domain migration candidate.

---

## Round 175 - WinRM Decrypt Domain Client Migration

Time: 2026-05-12 08:19:05 +08:00  
Author: Codex

### Scope

- Continued MISC security-material migration with the WinRM decrypt module.
- Kept decrypt execution, full-text preview loading, export behavior, and copy behavior unchanged.

### Changes

- Updated `misc/modules/WinRMDecryptModule.tsx` to import `backendClients` instead of aggregate `bridge`.
- Replaced WinRM decrypt, result text, and export calls with `backendClients.securityMaterial.*` equivalents.
- Updated MISC page test mocks to expose the WinRM security-material domain methods anywhere the lazy module can be imported.

### Validation

- `pnpm exec vitest run src/app/pages/MiscTools.test.tsx src/app/pages/MiscTools.sessions.test.tsx src/app/pages/MiscTools.smb3.test.tsx src/app/pages/MiscTools.payloadHints.test.tsx src/app/pages/MiscTools.customModules.test.tsx src/app/misc/modules/WinRMDecryptUtils.test.ts src/app/misc/modules/WinRMPreviewUtils.test.ts src/app/integrations/bridgeDomains.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run boundary:check` - passed.
- `pnpm run size:check` - passed after compressing the payload-hints mock shape back under budget.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- WinRM decrypt flows no longer depend on the aggregate bridge.
- Remaining MISC direct bridge candidates are now centered on custom module management, payload webshell decoding, and MISC package list/import flows.

---

## Round 174 - SMB3 Session Key Domain Client Migration

Time: 2026-05-12 08:14:30 +08:00  
Author: Codex

### Scope

- Continued MISC security-material migration with the SMB3 session key module.
- Kept candidate lazy loading, refresh behavior, autofill behavior, and random session key generation unchanged.

### Changes

- Updated `misc/modules/SMB3SessionKeyModule.tsx` to import `backendClients` instead of aggregate `bridge`.
- Replaced SMB3 candidate listing and random session key generation calls with `backendClients.securityMaterial.*` equivalents.
- Updated the SMB3 MISC test mock to expose the security material domain client.

### Validation

- `pnpm exec vitest run src/app/pages/MiscTools.smb3.test.tsx src/app/integrations/bridgeDomains.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run boundary:check` - passed.
- `pnpm run size:check` - passed.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- SMB3 session candidate and key-generation flows no longer depend on the aggregate bridge.
- WinRM decrypt remains the next small security-material direct bridge candidate.

---

## Round 173 - NTLM Session Materials Domain Client Migration

Time: 2026-05-12 08:11:30 +08:00  
Author: Codex

### Scope

- Continued direct aggregate bridge removal with the NTLM session materials MISC module.
- Kept deferred loading, refresh-after-selection behavior, and session-material rendering unchanged.

### Changes

- Updated `misc/modules/NTLMSessionMaterialsModule.tsx` to import `backendClients` instead of aggregate `bridge`.
- Replaced NTLM material listing calls with `backendClients.securityMaterial.listNTLMSessionMaterials()`.
- Updated MISC test mocks to expose the security material domain client while preserving older aggregate bridge mocks for unmigrated modules.

### Validation

- `pnpm exec vitest run src/app/pages/MiscTools.sessions.test.tsx src/app/pages/MiscTools.test.tsx src/app/pages/MiscTools.payloadHints.test.tsx src/app/integrations/bridgeDomains.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run boundary:check` - passed.
- `pnpm run size:check` - passed.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- NTLM session material loading no longer depends on the aggregate bridge.
- Remaining MISC direct bridge candidates include SMB3 session key, WinRM decrypt, generic custom module operations, payload webshell decoding, and MISC module package list/import flows.

---

## Round 172 - Update Center Domain Client Migration

Time: 2026-05-12 08:04:46 +08:00  
Author: Codex

### Scope

- Continued direct aggregate bridge removal with the standalone Update Center page.
- Kept update status refresh, install progress, and error handling unchanged.

### Changes

- Updated `pages/UpdateCenter.tsx` to import `backendClients` instead of aggregate `bridge`.
- Replaced `checkAppUpdate` and `installAppUpdate` calls with `backendClients.runtime.*` equivalents.

### Validation

- `pnpm exec vitest run src/app/features/update/updateCenterUtils.test.ts src/app/integrations/bridgeDomains.test.ts src/app/integrations/wailsBridge.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run boundary:check` - passed.
- `pnpm run size:check` - passed.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- Update Center no longer imports the aggregate bridge directly.
- Runtime update operations now align with the existing runtime domain client surface.

---

## Round 171 - Raw Stream Page Domain Client Migration

Time: 2026-05-12 02:28:14 +08:00  
Author: Codex

### Scope

- Continued direct aggregate bridge removal with a single raw stream page dependency.
- Kept raw stream pagination, route selection, search, export, and rendering behavior unchanged.

### Changes

- Updated `pages/RawStreamPage.tsx` to import `backendClients` instead of aggregate `bridge`.
- Passed `backendClients.stream.getRawStreamPage` into `useRawStreamPageLoader`.

### Validation

- `pnpm exec vitest run src/app/pages/useRawStreamPageLoader.test.tsx src/app/pages/useRawStreamRouteSelection.test.tsx src/app/pages/RawStreamUtils.test.ts src/app/pages/RawStreamProtocolConfig.test.ts src/app/integrations/bridgeDomains.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run boundary:check` - passed.
- `pnpm run size:check` - passed.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- Raw stream page-level pagination no longer depends on the aggregate bridge.
- Deeper stream state wiring in `SentinelContext` still has direct bridge usage and remains a later, higher-coupling migration candidate.

---

## Round 170 - Bridge Domain Migration Self-Check

Time: 2026-05-12 02:26:10 +08:00  
Author: Codex

### Scope

- Performed the scheduled ten-round self-check before continuing further bridge-domain migrations.
- Audited commit continuity, report continuity, remaining direct bridge imports, and baseline frontend gates.

### Checks

- Recent ten commits are sequential bridge-domain migration/audit commits from Round 160 through Round 169.
- Report entries are present through Round 169 and match the committed migration sequence.
- Remaining production direct `bridge` imports: 16 files, reduced from the Round 160 count of 28.
- Worktree was clean before this report-only round began.

### Validation

- `pnpm run typecheck` - passed.
- `pnpm run boundary:check` - passed.
- `pnpm run size:check` - passed.

### Review

- No migration drift found in the last ten rounds.
- Remaining candidates are larger or mixed-domain areas: raw stream page/state, stream decoder/payload inspection, lifecycle/runtime controls, media playback/transcription, update center, TLS/security material, and remaining MISC utility modules.

---

## Round 169 - Analysis Progress Domain Clients

Time: 2026-05-12 02:24:08 +08:00  
Author: Codex

### Scope

- Continued direct aggregate bridge removal inside threat-analysis refresh state.
- Kept cancellation, sequence checks, status messages, and state updates unchanged.

### Changes

- Updated `state/hooks/useAnalysisProgress.ts` to import `backendClients` instead of aggregate `bridge`.
- Replaced object refresh with `backendClients.object.listObjects(task.signal)`.
- Replaced threat-hit refresh with `backendClients.hunting.listThreatHits(["flag{", "ctf{"], task.signal)`.

### Validation

- `pnpm exec vitest run src/app/state/hooks/useBackendLifecycle.test.tsx src/app/state/hooks/useRefreshAnalysisResult.test.tsx src/app/integrations/bridgeDomains.test.ts src/app/integrations/clients/huntingClient.test.ts src/app/integrations/clients/objectClient.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run boundary:check` - passed.
- `pnpm run size:check` - passed.
- `pnpm run format:check` - passed.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- Threat-analysis refresh now uses the same narrow hunting/object clients as the migrated feature pages.
- The next round is Round 170 and should include the scheduled ten-round self-check before continuing migration.

---

## Round 168 - Capture Mission Overview Domain Clients

Time: 2026-05-12 02:20:32 +08:00  
Author: Codex

### Scope

- Continued direct aggregate bridge removal in the capture mission overview hook.
- Kept overview fetch/cache/unavailable-state behavior unchanged.

### Changes

- Updated `components/useCaptureMissionOverviewBundle.ts` to import `backendClients` instead of aggregate `bridge`.
- Routed traffic, industrial, vehicle, and USB overview requests through `backendClients.analysis`.
- Routed media overview request through `backendClients.media`.
- Updated the focused hook test mock to expose `backendClients.analysis` and `backendClients.media`.

### Validation

- `pnpm exec vitest run src/app/components/useCaptureMissionOverviewBundle.test.tsx src/app/integrations/bridgeDomains.test.ts src/app/integrations/clients/analysisClient.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run boundary:check` - passed.
- `pnpm run size:check` - passed.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- Capture mission overview no longer depends on the aggregate bridge for read-only summary analysis calls.
- The hook now mirrors existing per-feature domain ownership: analysis data via `analysis`, media data via `media`.

---

## Round 167 - MISC Analysis Domain Client Migration

Time: 2026-05-12 02:16:12 +08:00  
Author: Codex

### Scope

- Continued bridge domain migration on MISC built-in analysis modules.
- Kept MISC shell/module behavior unchanged; only narrowed the analysis API surface.

### Changes

- Updated `HTTPLoginAnalysisModule`, `MySQLSessionAnalysisModule`, `SMTPSessionAnalysisModule`, and `ShiroRememberMeAnalysisModule` to import `backendClients` instead of aggregate `bridge`.
- Replaced MISC analysis calls with `backendClients.analysis.*` equivalents.
- Updated MISC page test mocks to expose `backendClients.analysis` so lazy-loaded modules exercise the same domain-client path as production.

### Validation

- `pnpm exec vitest run src/app/pages/MiscTools.payloadHints.test.tsx src/app/pages/MiscTools.sessions.test.tsx src/app/pages/MiscTools.test.tsx src/app/integrations/bridgeDomains.test.ts src/app/integrations/clients/analysisClient.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run boundary:check` - passed.
- `pnpm run size:check` - passed.
- `pnpm run format:check` - passed.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- The four MISC built-in analysis modules no longer directly call aggregate bridge methods.
- Remaining MISC direct bridge users are custom modules, payload/stream/session utility modules, and export/decrypt flows; these stay as later focused rounds.

---

## Round 166 - Vehicle DBC Domain Client Migration

Time: 2026-05-12 02:06:22 +08:00  
Author: Codex

### Scope

- Continued bridge domain migration on remaining Vehicle page DBC operations.
- Kept vehicle analysis hook behavior unchanged; this round only moved DBC profile/file-picker calls to narrow client.

### Changes

- Updated `pages/VehicleAnalysis.tsx` to import `backendClients` instead of aggregate `bridge`.
- Replaced `listVehicleDBCProfiles`, `addVehicleDBC`, `removeVehicleDBC`, and `openDBCFile` with `backendClients.vehicleDBC.*` calls.
- Preserved existing DBC import/remove error handling and analysis refresh behavior.

### Validation

- `pnpm exec vitest run src/app/pages/VehicleAnalysis.test.ts src/app/pages/analysisCacheKeys.test.ts src/app/integrations/bridgeDomains.test.ts src/app/integrations/mappers/vehicleMapper.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run boundary:check` - passed.
- `pnpm run size:check` - passed.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- Vehicle page no longer directly imports aggregate bridge.
- DBC operations now sit behind `vehicleDBC` domain client, matching earlier `useVehicleAnalysis` analysis-domain migration.

---

## Round 165 - Threat Hunting Domain Client Migration

Time: 2026-05-12 02:02:33 +08:00  
Author: Codex

### Scope

- Continued direct aggregate bridge removal with the Threat Hunting page.
- Kept the page UI/state behavior unchanged and only swapped the API surface to the hunting domain client.

### Changes

- Updated `pages/ThreatHunting.tsx` to import `backendClients` instead of `bridge`.
- Replaced `listThreatHits`, `getHuntingRuntimeConfig`, and `updateHuntingRuntimeConfig` calls with `backendClients.hunting.*` equivalents.

### Validation

- `pnpm exec vitest run src/app/features/hunting/threatHuntingInvestigationReport.test.ts src/app/features/hunting/ThreatHuntingMetricCards.test.tsx src/app/integrations/bridgeDomains.test.ts src/app/integrations/clients/huntingClient.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run boundary:check` - passed.
- `pnpm run size:check` - passed.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- Threat Hunting page runtime/config calls now use the narrow hunting client.
- Related state hook `useAnalysisProgress` still has hunting bridge usage and remains a later migration candidate.

---

## Round 164 - Traffic Graph Domain Client Migration

Time: 2026-05-12 01:58:28 +08:00  
Author: Codex

### Scope

- Continued replacing direct aggregate bridge imports in feature hooks.
- Targeted `useTrafficGraph`, which has a primary global stats path and a fallback packet aggregation path.

### Changes

- Updated `features/traffic/useTrafficGraph.ts` to call `backendClients.analysis.getGlobalTrafficStats(signal)` for the primary stats request.
- Updated the local fallback path to call `backendClients.packet.listPackets()` before rebuilding summary stats from packets.
- Preserved existing cache-key behavior, abort-like error handling, and fallback semantics.

### Validation

- `pnpm exec vitest run src/app/pages/TrafficGraph.test.ts src/app/pages/analysisCacheKeys.test.ts src/app/integrations/bridgeDomains.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run boundary:check` - passed.
- `pnpm run size:check` - passed.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- Traffic graph no longer imports the aggregate bridge directly.
- This was a two-domain hook migration, but the behavior remains identical because both methods already exist in the domain projection.

---

## Round 163 - C2 Decrypt Domain Client Migration

Time: 2026-05-12 01:54:52 +08:00  
Author: Codex

### Scope

- Finished the C2 analysis-domain migration slice by moving the decrypt workbench off the aggregate bridge.
- Kept the change limited to existing C2 analysis APIs already exposed by `AnalysisClient`.

### Changes

- Updated `features/c2/C2DecryptWorkbench.tsx` to call `backendClients.analysis.decryptC2Traffic(request)` instead of `bridge.decryptC2Traffic(request)`.
- Updated all C2 page test mocks so both `getC2SampleAnalysis` and `decryptC2Traffic` are provided by `backendClients.analysis`.
- Left `bridge: {}` in those mocks only as a compatibility shell for any unrelated imports, not as an active method surface.

### Validation

- `pnpm exec vitest run src/app/pages/C2Analysis.test.tsx src/app/pages/C2Analysis.decrypt.test.tsx src/app/pages/C2Analysis.vshell.test.tsx src/app/pages/C2Analysis.candidates.test.tsx src/app/pages/analysisCacheKeys.test.ts src/app/integrations/bridgeDomains.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run boundary:check` - passed.
- `pnpm run size:check` - passed.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- C2 production analysis/decrypt flows no longer depend on direct aggregate `bridge` methods.
- The next bridge migration should move to another narrow consumer rather than refactoring C2 UI internals further.

---

## Round 162 - C2 Sample Analysis Domain Client Migration

Time: 2026-05-12 00:56:19 +08:00  
Author: Codex

### Scope

- Continued the `BackendBridge` domain client migration with the C2 sample-analysis hook.
- Kept C2 decrypt on the aggregate bridge for this round because `C2DecryptWorkbench` is a separate mixed workflow and will be migrated independently.

### Changes

- Updated `features/c2/useC2Analysis.ts` to call `backendClients.analysis.getC2SampleAnalysis(signal)` instead of `bridge.getC2SampleAnalysis(signal)`.
- Updated the C2 page test mocks to expose `backendClients.analysis.getC2SampleAnalysis` while preserving `bridge.decryptC2Traffic` for the decrypt workbench path.

### Validation

- `pnpm exec vitest run src/app/pages/C2Analysis.test.tsx src/app/pages/C2Analysis.decrypt.test.tsx src/app/pages/C2Analysis.vshell.test.tsx src/app/pages/C2Analysis.candidates.test.tsx src/app/pages/analysisCacheKeys.test.ts src/app/integrations/bridgeDomains.test.ts` - passed.
- `pnpm run typecheck` - passed.
- `pnpm run boundary:check` - passed.
- `pnpm run size:check` - passed.
- `pnpm run ci` - passed, including 179 test files / 495 tests and production build.

### Review

- This removes another direct production dependency on the aggregate bridge without altering C2 cache keys, abort handling, or page behavior.
- Remaining C2 bridge usage is now concentrated in `C2DecryptWorkbench`, which is a good later candidate for the `analysis.decryptC2Traffic` client path.

---

## Round 41 - Backend Go Test Timeout Triage

Time: 2026-05-11 00:03:51 +08:00  
Author: Codex

### Scope

- Investigated the user-reported `go test` timeout after the capture-open and release-bootstrap stabilization work.
- Separated ordinary backend unit/integration tests from local real-sample regressions that depend on large PCAP files and a real Wireshark `tshark.exe`.

### Root Cause

- The timeout was not caused by the new capture status endpoint or the capture-open navigation fix.
- `backend/internal/engine/real_sample_validation_test.go` ran by default whenever the user's local absolute sample paths existed.
- On this machine all referenced samples exist, so ordinary `cd backend && go test ./...` automatically parsed multiple large captures with real `tshark`:
  - `C:\Users\QAQ\Downloads\cs流量分析.pcapng` was parsed three times, each taking roughly 30-38 seconds.
  - `C:\Users\QAQ\Desktop\gshark\bx3base.pcap` parsed about 135,525 packets and took roughly 40 seconds.
  - `gsl4.0.pcap` additionally triggered many HTTP stream-follow subprocesses and took roughly 25-28 seconds.
- A focused `go test -run TestRealSample -v ./internal/engine -count=1 -timeout=8m` completed in about 202 seconds, confirming the slow path is the real-sample regression suite rather than normal Go test execution.

### Changes

- Added an explicit opt-in gate to `real_sample_validation_test.go`.
- Local real-sample regressions now run only when `GSHARK_ENABLE_REAL_SAMPLE_TESTS=1` is set.
- The same tests also skip under `go test -short`, matching the existing sample-backed behavior in the `tshark` package.
- Existing environment variable overrides such as `GSHARK_SAMPLE_CS`, `GSHARK_SAMPLE_VSHELL`, and WebShell/Modbus/CAN sample paths are preserved for opt-in runs.

### Validation

- `cd backend && go test ./...` - passed in about 16 seconds.
- `cd backend && go test -run TestRealSample -v ./internal/engine -count=1` - passed with the real-sample tests skipped by default and clear skip messages.
- `cd backend; $env:GSHARK_ENABLE_REAL_SAMPLE_TESTS='1'; go test -run TestRealSampleModbusIndustrialEvidence -v ./internal/engine -count=1 -timeout=90s` - passed, proving the opt-in path still executes real samples.

### Review

- Default backend tests are now deterministic enough for routine development and CI-style local checks.
- The real-payload validation path is intentionally preserved because it catches detector regressions that synthetic fixtures miss.
- When validating C2/WebShell/Industrial/Vehicle detection against real captures, use:

```powershell
cd backend
$env:GSHARK_ENABLE_REAL_SAMPLE_TESTS='1'
go test -run TestRealSample -v ./internal/engine -count=1 -timeout=8m
```

- If future real-sample regressions are added, they should follow the same opt-in pattern instead of silently joining the default `go test ./...` path.

---

## Round 42 - Mixed Transport Contract Tests And Abort Cancellation Fix

Time: 2026-05-11 00:20:06 +08:00  
Author: Codex

### Scope

- Implemented the first slice of the new engineering plan by locking down the mixed transport boundary with focused frontend contract tests.
- Kept the selected architecture unchanged:
  - desktop control plane on Wails IPC where a binding exists,
  - packet / stream / analysis / blob / event data plane on HTTP fallback,
  - `/api/events` SSE still used for events.
- Did not touch MISC evidence routing, samples, or any real PCAP corpus.

### Changes

- Added `desktopBridge.test.ts` to assert that supported desktop control-plane calls use Wails IPC:
  - backend readiness / backend status,
  - capture start / capture status,
  - tool runtime snapshot,
  - TLS config read / update.
- Added contract coverage that data-plane calls remain on the HTTP fallback even in desktop mode:
  - packet page reads,
  - raw stream page reads,
  - industrial analysis reads,
  - event subscription.
- Added per-method fallback coverage so missing desktop bindings fall back to the HTTP bridge instead of failing the whole bridge.
- Added `httpBridge.test.ts` for transport helper behavior:
  - desktop auth token is applied to non-health requests,
  - `/health` remains unauthenticated,
  - caller-provided Authorization is preserved,
  - FormData uploads do not get forced JSON content type,
  - backend JSON error detail is surfaced,
  - browser fetch failures become actionable backend connectivity messages.
- Fixed `httpBridge.ts` cancellation handling:
  - `DOMException` AbortError is now preserved instead of being normalized into a backend connectivity failure.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations` - passed, 20 files / 56 tests.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.
- `cd frontend && pnpm run ci` - passed, 103 test files / 334 tests, plus package-manager check, typecheck, ESLint, scoped Prettier check, size budget, and Vite build.

### Review

- This round turns the intended mixed transport split into executable contracts instead of relying on convention.
- The only production behavior change is the AbortError fix. It is low-risk and important because caller-side cancellation must not be reported as a backend/data-plane outage.
- The next engineering slice should move to `SentinelContext` internal ownership extraction, starting with packet-page or capture-transaction helpers, while keeping `useSentinel()` public shape stable.
- `docs/audit-development-report-archive-2026-05-10/` remains ignored locally; this report was updated for audit continuity and should not be pushed unless the repository policy changes.

---

## Round 43 - Sentinel Capture Task Reset Extraction

Time: 2026-05-11 00:29:45 +08:00  
Author: Codex

### Scope

- Continued the engineering plan after the mixed-transport contract round.
- Focused on a low-risk `SentinelContext` internal ownership slice instead of expanding mapper logic.
- Kept `useSentinel()` public shape unchanged and did not alter backend API behavior.
- Did not modify MISC evidence routing, samples, or real PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- Current largest mapper files remain below their size budgets:
  - `vshellDecryptDisplayRules.ts`: 264 lines.
  - `protocolToolMapper.ts`: 226 lines.
  - `vehicleMapper.ts`: 201 lines.
  - `toolMapper.ts`: 181 lines.
- Future decoding or display-rule work should avoid growing mapper files unless the rule genuinely belongs at integration normalization time.

### Changes

- Added `frontend/src/app/state/captureTaskReset.ts` as a pure helper for frontend capture-task cancellation:
  - invalidates current capture task scope,
  - bumps packet-page and threat-analysis sequence guards,
  - bumps all stream-switch sequence guards,
  - clears HTTP/TCP/UDP stream prefetch in-flight sets,
  - cancels pending load-more timer,
  - resets page-loading and packet-page error UI state.
- Added `captureTaskReset.test.ts` covering:
  - stale task invalidation,
  - sequence increments,
  - prefetch cleanup,
  - scheduled load-more timer clearing,
  - no-op timer behavior when no load-more task exists.
- Rewired `SentinelContext.tsx` to call `cancelFrontendCaptureTasks()` instead of keeping that cancellation bundle inline.
- Tightened `frontend/scripts/check-size.mjs`:
  - `SentinelContext.tsx` budget reduced from 1450 to 1390 lines,
  - added budgets for `captureTaskReset.ts` and `captureTaskReset.test.ts`.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/captureTaskReset.test.ts src/app/state/captureResetState.test.ts src/app/state/streamRuntimeReset.test.ts` - passed, 3 files / 8 tests.
- `cd frontend && pnpm exec vitest run src/app/state/captureTaskReset.test.ts scripts/check-size.test.mjs` - passed, 2 files / 4 tests.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.
- `cd frontend && pnpm run ci` - passed, 104 test files / 336 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.

### Review

- This is intentionally a small state-boundary extraction, not a broad provider rewrite.
- The provider line count only drops modestly, but the cancellation ownership is now testable outside React and can be reused safely by later capture transaction extraction.
- The next useful slice is packet-page loading state or display-filter workflow extraction; both should keep `useSentinel()` compatible and add focused helper tests first.
- `docs/audit-development-report-archive-2026-05-10/` remains ignored locally and should not be pushed under the current repository hygiene policy.

---

## Round 44 - Sentinel Packet Page Load Extraction

Time: 2026-05-11 00:37:39 +08:00  
Author: Codex

### Scope

- Continued the `SentinelContext` internal ownership extraction after Round 43.
- Focused on packet-page request lifecycle instead of mapper or presentation files.
- Kept `useSentinel()` public shape unchanged and kept packet / stream / analysis data plane on HTTP.
- Did not modify MISC evidence routing, samples, or real PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- Current largest mapper files remain unchanged:
  - `vshellDecryptDisplayRules.ts`: 264 lines.
  - `protocolToolMapper.ts`: 226 lines.
  - `vehicleMapper.ts`: 201 lines.
  - `toolMapper.ts`: 181 lines.

### Changes

- Added `frontend/src/app/state/packetPageLoad.ts` as a pure async helper for packet-page request lifecycle:
  - validates backend connection and active capture path,
  - normalizes cursor before calling `listPacketsPage`,
  - owns packet-page sequence guard,
  - owns capture task scope creation and stale-result checks,
  - commits current results through a provider callback,
  - maps non-abort failures to packet-page and backend status messages,
  - preserves abort/stale behavior as quiet null results,
  - handles page-loading and optional filter-loading finalization.
- Added `packetPageLoad.test.ts` covering:
  - successful load and normalized cursor commit,
  - disconnected / missing capture no-op,
  - non-abort failure status mapping,
  - abort quiet path,
  - stale result suppression.
- Rewired `SentinelContext.tsx` to call `loadPacketPageState()` instead of carrying packet-page request try/catch/finally inline.
- Tightened `frontend/scripts/check-size.mjs`:
  - `SentinelContext.tsx` budget reduced from 1390 to 1335 lines,
  - added budgets for `packetPageLoad.ts` and `packetPageLoad.test.ts`.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/packetPageLoad.test.ts src/app/state/packetPageStatus.test.ts src/app/state/packetPagination.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 4 files / 15 tests.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.
- `cd frontend && pnpm run ci` - passed, 105 test files / 341 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.

### Review

- This round extracts another real state boundary from `SentinelContext` without changing caller behavior.
- `SentinelContext.tsx` is now about 1194 lines after formatting; the target remains to continue reducing it through tested packet/filter/stream helpers rather than public Context churn.
- The next useful slice is display-filter workflow extraction, because it still owns filter sequence guards, packet viewport reset, repeated polling, and status finalization inside the provider.
- `docs/audit-development-report-archive-2026-05-10/` remains ignored locally and should not be pushed under the current repository hygiene policy.

---

## Round 45 - Sentinel Packet Filter Workflow Extraction

Time: 2026-05-11 00:47:10 +08:00  
Author: Codex

### Scope

- Continued the `SentinelContext` internal ownership extraction after Round 44.
- Focused on display-filter workflow ownership: sequence guard, filter loading, viewport reset, polling, and status finalization.
- Kept `useSentinel()` public shape unchanged and preserved existing behavior:
  - apply filter still polls while backend reports `filtering`.
  - clear filter still performs one immediate page reload without polling.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, or real PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- Current mapper budgets remain unchanged; this round intentionally kept filter workflow in `state/`, not `integrations/mappers/`.

### Changes

- Added `frontend/src/app/state/packetFilterWorkflow.ts`:
  - no-op guard when no active capture / backend / safe runtime exists,
  - owns `filterSeqRef` increment and stale-result suppression,
  - clears packet page error and resets packet viewport,
  - calls `loadPacketPage(0, filter)`,
  - polls with existing packet-filter interval / timeout only when requested,
  - finalizes loading and status only for the current sequence.
- Added `packetFilterWorkflow.test.ts` covering:
  - normal apply workflow,
  - polling until backend filter scan settles,
  - clear-filter no-poll behavior,
  - no-op guard,
  - stale sequence suppression.
- Rewired `SentinelContext.tsx` to call `runPacketFilterWorkflow()` from `applyFilter()` and `clearFilter()`.
- Tightened `frontend/scripts/check-size.mjs`:
  - `SentinelContext.tsx` budget reduced from 1335 to 1300 lines,
  - added budgets for `packetFilterWorkflow.ts` and `packetFilterWorkflow.test.ts`.
- `SentinelContext.tsx` is now about 1173 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/packetFilterWorkflow.test.ts src/app/state/packetFilterStatus.test.ts src/app/state/packetPageLoad.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 4 files / 15 tests.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.
- First full frontend CI attempt exposed a scoped Prettier issue in `SentinelContext.tsx`; fixed with targeted Prettier on changed frontend files.
- `cd frontend && pnpm run ci` - passed, 106 test files / 346 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.

### Review

- This round removes a real state workflow from the provider without changing capture, packet, stream, or analysis behavior.
- The extraction keeps filter behavior testable outside React and prepares later packet-selection / stream-navigation state work.
- The mapper-size constraint was respected: no mapper file grew.
- `docs/audit-development-report-archive-2026-05-10/` remains ignored locally and should not be pushed under the current repository hygiene policy.

---

## Round 46 - Sentinel Packet Locate Workflow Extraction

Time: 2026-05-11 00:52:49 +08:00  
Author: Codex

### Scope

- Performed the requested autonomous iteration after Round 45.
- Focused on packet locate workflow ownership inside `SentinelContext`, not mapper or UI presentation code.
- Kept `useSentinel()` public shape unchanged:
  - `locatePacketById(packetId, filterOverride?)` still returns the located packet or `null`.
  - filter override still updates the visible display filter before loading the located page.
  - abort and stale locate tasks stay quiet.
- Did not modify backend APIs, MISC evidence routing, samples, report tracking policy, or real PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- The new logic lives under `frontend/src/app/state/`, matching state workflow ownership instead of growing mapper files.

### Changes

- Added `frontend/src/app/state/packetLocateWorkflow.ts`:
  - normalizes packet IDs,
  - guards missing capture / invalid ID,
  - owns `packet-locate` capture task scope,
  - calls `locatePacketPage`,
  - handles not-found status,
  - applies filter overrides,
  - loads the located packet page,
  - selects the target packet only when the locate task is still current,
  - maps non-abort failures to backend status.
- Added `packetLocateWorkflow.test.ts` covering:
  - found packet selection,
  - filter override behavior,
  - not-found status,
  - invalid ID / missing capture no-op,
  - quiet abort / stale result,
  - non-abort failure status.
- Rewired `SentinelContext.tsx` to delegate `locatePacketById()` to `locatePacketByIdWorkflow()`.
- Tightened `frontend/scripts/check-size.mjs`:
  - `SentinelContext.tsx` budget reduced from 1300 to 1265 lines,
  - added budgets for `packetLocateWorkflow.ts` and `packetLocateWorkflow.test.ts`.
- `SentinelContext.tsx` is now about 1152 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/packetLocateWorkflow.test.ts src/app/state/packetFilterWorkflow.test.ts src/app/state/packetPageLoad.test.ts src/app/state/selectedPacketState.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 5 files / 25 tests.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.
- First full frontend CI attempt exposed a scoped Prettier issue in `scripts/check-size.mjs`; fixed with targeted Prettier.
- `cd frontend && pnpm run ci` - passed, 107 test files / 352 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.

### Review

- This is a second consecutive state-boundary extraction from the provider and remains aligned with the engineering plan.
- `SentinelContext.tsx` has moved from about 1194 lines before Round 45 to about 1152 lines after Round 46 while preserving public shape.
- Round cycle self-audit counter: 2 / 10. No drift detected:
  - still reducing provider state ownership,
  - no mapper growth,
  - no MISC-to-Evidence coupling,
  - CI remains green,
  - reports remain local ignored artifacts.

---

## Round 47 - Sentinel Stream Index Refresh Extraction

Time: 2026-05-11 00:57:25 +08:00  
Author: Codex

### Scope

- Continued autonomous iteration after Round 46.
- Focused on another small `SentinelContext` state ownership slice: stream ID index refresh.
- Avoided the larger stream-switching workflow in this round because it has wider cache, metric, and prefetch coupling.
- Kept public context shape unchanged and did not alter packet / stream / analysis API behavior.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, or real PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- Stream index refresh belongs under state workflow ownership and was not added to mapper logic.

### Changes

- Added `frontend/src/app/state/streamIndexRefresh.ts`:
  - guards backend disconnected / missing active capture,
  - owns `stream-index` capture task scope,
  - loads HTTP / TCP / UDP stream IDs in parallel,
  - suppresses stale results when capture changes,
  - keeps aborts quiet,
  - maps non-abort failures to `流索引刷新失败`.
- Added `streamIndexRefresh.test.ts` covering:
  - successful stream ID load,
  - disconnected / missing capture no-op,
  - stale capture suppression,
  - quiet abort path,
  - non-abort failure status.
- Rewired `SentinelContext.tsx` to call `refreshStreamIndexState()` from `refreshStreamIndex()`.
- Tightened `frontend/scripts/check-size.mjs`:
  - `SentinelContext.tsx` budget reduced from 1265 to 1240 lines,
  - added budgets for `streamIndexRefresh.ts` and `streamIndexRefresh.test.ts`.
- `SentinelContext.tsx` is now about 1139 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/streamIndexRefresh.test.ts src/app/state/packetLocateWorkflow.test.ts src/app/state/streamPrefetchScheduler.test.ts src/app/state/streamSwitchTask.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 5 files / 19 tests.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `cd frontend && pnpm run ci` - passed, 108 test files / 357 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- This round is aligned with the current engineering target: shrink provider state ownership through tested helpers before public Context splitting.
- `SentinelContext.tsx` has moved from about 1194 lines before Round 45 to about 1139 lines after Round 47.
- Round cycle self-audit counter: 3 / 10. No drift detected:
  - state ownership continues moving out of `SentinelContext`,
  - mapper files did not grow,
  - MISC remains separate from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and should not be pushed.

---

## Round 48 - Sentinel Stream Payload Persist Extraction

Time: 2026-05-11 01:02:28 +08:00  
Author: Codex

### Scope

- Continued autonomous iteration after Round 47.
- Focused on a narrow stream state workflow: persisted stream payload patch commit.
- Kept behavior unchanged:
  - skip disconnected / invalid stream / empty patches,
  - update backend first,
  - only patch active stream state and caches after backend update succeeds.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, or real PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- The work stayed in `state/` because it owns frontend stream state/cache mutation after backend persistence.

### Changes

- Added `frontend/src/app/state/streamPayloadPersist.ts`:
  - guards invalid persist requests,
  - calls `updateStreamPayloads`,
  - applies local patch commits through the existing `commitProtocolStreamPayloadPatches()` helper inside `startTransition`.
- Added `streamPayloadPersist.test.ts` covering:
  - backend update before local patch commit,
  - skip guards,
  - no local mutation when backend update fails.
- Rewired `SentinelContext.tsx` to delegate `persistStreamPayloads()` to `persistStreamPayloadsState()`.
- Tightened `frontend/scripts/check-size.mjs`:
  - `SentinelContext.tsx` budget reduced from 1240 to 1225 lines,
  - added budgets for `streamPayloadPersist.ts` and `streamPayloadPersist.test.ts`.
- `SentinelContext.tsx` is now about 1138 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/streamPayloadPersist.test.ts src/app/state/streamPayloadPatch.test.ts src/app/state/streamIndexRefresh.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 4 files / 13 tests.
- `cd frontend && pnpm run typecheck` - passed after widening the helper's backend update return type to `Promise<unknown>` because the bridge returns the updated stream.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- First full frontend CI attempt exposed a scoped Prettier issue in `scripts/check-size.mjs`; fixed with targeted Prettier.
- `cd frontend && pnpm run ci` - passed, 109 test files / 360 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- This remains aligned with the engineering plan: small state workflow extraction, focused tests, no public shape churn.
- `SentinelContext.tsx` has moved from about 1194 lines before Round 45 to about 1138 lines after Round 48.
- Round cycle self-audit counter: 4 / 10. No drift detected:
  - state ownership continues moving out of `SentinelContext`,
  - mapper files did not grow,
  - MISC remains separate from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and should not be pushed.

---

## Round 49 - Sentinel Packet Stream Prepare Extraction

Time: 2026-05-11 01:06:57 +08:00  
Author: Codex

### Scope

- Continued autonomous iteration after Round 48.
- Focused on a very small packet-to-stream workflow: locate packet, resolve protocol, activate stream.
- Kept `preparePacketStream()` public Context shape unchanged and did not alter stream activation behavior.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, or real PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- This stayed in `state/` because it orchestrates packet location and stream activation, not backend response mapping.

### Changes

- Added `frontend/src/app/state/packetStreamPrepare.ts`:
  - delegates packet lookup,
  - returns `{ packet, protocol: null, streamId: null }` when no valid stream exists,
  - resolves protocol through existing `resolvePacketStreamProtocol()`,
  - activates the selected stream,
  - returns the prepared packet stream descriptor.
- Added `packetStreamPrepare.test.ts` covering:
  - normal locate and stream activation,
  - preferred protocol override and filter pass-through,
  - no activation when packet / stream ID is unavailable.
- Rewired `SentinelContext.tsx` to delegate `preparePacketStream()` to `preparePacketStreamState()`.
- Tightened `frontend/scripts/check-size.mjs`:
  - `SentinelContext.tsx` budget reduced from 1225 to 1210 lines,
  - added budgets for `packetStreamPrepare.ts` and `packetStreamPrepare.test.ts`.
- `SentinelContext.tsx` is now about 1134 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/packetStreamPrepare.test.ts src/app/state/packetLocateWorkflow.test.ts src/app/state/streamProtocol.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 4 files / 13 tests.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `cd frontend && pnpm run ci` - passed, 110 test files / 363 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- This is intentionally small but continues the same state-boundary reduction direction.
- `SentinelContext.tsx` has moved from about 1194 lines before Round 45 to about 1134 lines after Round 49.
- Round cycle self-audit counter: 5 / 10. No drift detected:
  - state ownership continues moving out of `SentinelContext`,
  - mapper files did not grow,
  - MISC remains separate from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and should not be pushed.

---

## Round 50 - Sentinel Progress Status Workflow Extraction

Time: 2026-05-11 01:13:55 +08:00  
Author: Codex

### Scope

- Continued autonomous frontend engineering iteration after Round 49.
- Focused on progress status handling inside `SentinelContext.tsx`.
- Kept `useSentinel()` public shape unchanged.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, or real PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- The change stayed in `state/` because it handles frontend progress status fan-out, not backend response mapping.

### Changes

- Added `frontend/src/app/state/progressStatusWorkflow.ts`:
  - parses progress status messages through existing `parseProgressStatus()`,
  - updates media analysis progress,
  - updates threat analysis progress,
  - updates capture preload counters and packet totals,
  - preserves malformed progress consumption behavior.
- Added `progressStatusWorkflow.test.ts` covering:
  - non-progress messages,
  - malformed progress messages,
  - media progress phase / percent / recent labels,
  - threat progress phase / percent / recent labels,
  - capture totals and refs,
  - counting-phase reset,
  - negative processed clamp.
- Rewired `SentinelContext.tsx` to delegate `updateProgressFromStatus()` to the new helper.
- Tightened `frontend/scripts/check-size.mjs`:
  - `SentinelContext.tsx` budget reduced from 1210 to 1185 lines,
  - added budgets for `progressStatusWorkflow.ts` and `progressStatusWorkflow.test.ts`.
- `SentinelContext.tsx` is now about 1074 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/progressStatusWorkflow.test.ts src/app/state/progressStatus.test.ts src/app/state/packetStreamPrepare.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 4 files / 16 tests.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- First full frontend CI attempt exposed a scoped Prettier issue in `scripts/check-size.mjs`; fixed with targeted Prettier.
- `cd frontend && pnpm run ci` - passed, 111 test files / 370 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- This remains aligned with the engineering plan: state workflow extraction, focused tests, no public shape churn.
- `SentinelContext.tsx` has moved from about 1194 lines before Round 45 to about 1074 lines after Round 50.
- Round cycle self-audit counter: 6 / 10. No drift detected:
  - state ownership continues moving out of `SentinelContext`,
  - mapper files did not grow,
  - MISC remains separate from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and should not be pushed.

---

## Round 51 - Sentinel Stream Adjacent Prefetch Extraction

Time: 2026-05-11 01:20:02 +08:00  
Author: Codex

### Scope

- Continued autonomous iteration after Round 50.
- Focused on adjacent stream prefetch scheduling inside `SentinelContext.tsx`.
- Kept `useSentinel()` public shape unchanged.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, or real PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- This stayed in `state/` because it schedules stream-cache prefetch work, not backend response normalization.

### Changes

- Added `frontend/src/app/state/streamAdjacentPrefetch.ts`:
  - applies backend/capture/stream/limit guards,
  - selects adjacent stream IDs through existing `pickAdjacentStreamTargets()`,
  - resolves protocol-specific prefetch task state,
  - delegates opportunistic fetch scheduling to existing `scheduleStreamPrefetch()`,
  - returns number of scheduled prefetches for focused tests.
- Added `streamAdjacentPrefetch.test.ts` covering:
  - guard skip behavior,
  - adjacent HTTP target scheduling and cache fill,
  - TCP/UDP raw stream fetcher selection,
  - cached and in-flight target suppression.
- Rewired `SentinelContext.tsx` to delegate `prefetchAdjacentStreams()` to the new helper.
- Tightened `frontend/scripts/check-size.mjs`:
  - `SentinelContext.tsx` budget reduced from 1185 to 1165 lines,
  - added budgets for `streamAdjacentPrefetch.ts` and `streamAdjacentPrefetch.test.ts`.
- `SentinelContext.tsx` is now about 1062 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/streamAdjacentPrefetch.test.ts src/app/state/streamPrefetchScheduler.test.ts src/app/state/streamPrefetchPlan.test.ts src/app/state/streamPrefetchTask.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 5 files / 15 tests.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- First full frontend CI attempt exposed a scoped Prettier issue in `scripts/check-size.mjs`; fixed with targeted Prettier.
- `cd frontend && pnpm run ci` - passed, 112 test files / 374 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- This remains aligned with the engineering plan: state ownership and stream workflow code continue moving out of `SentinelContext`.
- `SentinelContext.tsx` has moved from about 1194 lines before Round 45 to about 1062 lines after Round 51.
- Round cycle self-audit counter: 7 / 10. No drift detected:
  - state ownership continues moving out of `SentinelContext`,
  - mapper files did not grow,
  - MISC remains separate from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and should not be pushed.

---

## Round 52 - Sentinel Stream Switch Workflow Extraction

Time: 2026-05-11 01:27:42 +08:00  
Author: Codex

### Scope

- Continued autonomous iteration after Round 51.
- Focused on active HTTP/TCP/UDP stream switching inside `SentinelContext.tsx`.
- Kept `useSentinel()` public shape unchanged.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, or real PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- The change stayed in `state/` because it owns stream cache/fetch/switch orchestration, not backend response mapping.

### Changes

- Added `frontend/src/app/state/streamSwitchWorkflow.ts`:
  - guards disconnected / no capture / invalid stream IDs,
  - bumps protocol-specific stream switch sequence,
  - applies cached streams through existing cache helper,
  - applies loading stream placeholders,
  - fetches HTTP/TCP/UDP stream payloads,
  - commits loaded stream and metrics through existing commit helper,
  - preserves stale request and abort handling,
  - reports non-abort stream switch errors.
- Added `streamSwitchWorkflow.test.ts` covering:
  - invalid request skips,
  - cache hit apply + metric + prefetch,
  - loading state + fetch commit + metric + prefetch,
  - non-abort fetch failure status.
- Rewired `SentinelContext.tsx` to delegate `setActiveStream()` to the new helper.
- Tightened `frontend/scripts/check-size.mjs`:
  - `SentinelContext.tsx` budget reduced from 1165 to 1115 lines,
  - added budgets for `streamSwitchWorkflow.ts` and `streamSwitchWorkflow.test.ts`.
- `SentinelContext.tsx` is now about 1008 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/streamSwitchWorkflow.test.ts src/app/state/streamSwitchTask.test.ts src/app/state/streamSwitchCommit.test.ts src/app/state/streamSwitchCache.test.ts src/app/state/streamSwitchSequence.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 6 files / 16 tests.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `cd frontend && pnpm run ci` - passed, 113 test files / 378 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- This remains aligned with the engineering plan: the largest remaining provider workflow moved to a tested state helper.
- `SentinelContext.tsx` has moved from about 1194 lines before Round 45 to about 1008 lines after Round 52.
- Round cycle self-audit counter: 8 / 10. No drift detected:
  - state ownership continues moving out of `SentinelContext`,
  - mapper files did not grow,
  - MISC remains separate from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and should not be pushed.

---

## Round 53 - Sentinel Capture Replacement Prepare Extraction

Time: 2026-05-11 01:32:45 +08:00  
Author: Codex

### Scope

- Continued autonomous iteration after Round 52.
- Focused on the pre-capture replacement reset path inside `SentinelContext.tsx`.
- Kept `useSentinel()` public shape unchanged.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, or real PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- The change stayed in `state/` because it owns frontend capture replacement reset and backend cleanup orchestration.

### Changes

- Added `frontend/src/app/state/captureReplacementPrepare.ts`:
  - cancels frontend capture tasks,
  - wakes capture waiters,
  - finishes parse/preload runtime state,
  - resets filter loading and preload counters,
  - calls backend `stopStreamingPackets()` and `prepareCaptureReplacement()` only when connected,
  - suppresses best-effort backend cleanup failures.
- Added `captureReplacementPrepare.test.ts` covering:
  - local parse/filter/preload reset,
  - connected backend cleanup with suppressed stop failure,
  - disconnected backend skip behavior.
- Rewired `SentinelContext.tsx` to delegate `prepareForCaptureReplacement()` to the new helper.
- Tightened `frontend/scripts/check-size.mjs`:
  - `SentinelContext.tsx` budget reduced from 1115 to 1100 lines,
  - added budgets for `captureReplacementPrepare.ts` and `captureReplacementPrepare.test.ts`.
- `SentinelContext.tsx` is now about 1009 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/captureReplacementPrepare.test.ts src/app/state/captureTaskReset.test.ts src/app/state/captureResetState.test.ts src/app/state/captureParseRuntimeState.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 5 files / 14 tests.
- `cd frontend && pnpm run typecheck` - passed after widening helper setter types to match React setters and retaining `finishCaptureParseRuntime` import for stop-capture behavior.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- First full frontend CI attempt exposed a scoped Prettier issue in `scripts/check-size.mjs`; fixed with targeted Prettier.
- `cd frontend && pnpm run ci` - passed, 114 test files / 381 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- This remains aligned with the engineering plan: state ownership continues moving out of `SentinelContext` without changing public Context shape.
- `SentinelContext.tsx` has moved from about 1194 lines before Round 45 to about 1009 lines after Round 53.
- Round cycle self-audit counter: 9 / 10. No drift detected:
  - state ownership continues moving out of `SentinelContext`,
  - mapper files did not grow,
  - MISC remains separate from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and should not be pushed.

---

## Round 54 - Sentinel Capture Stop Workflow Extraction and Cycle Audit

Time: 2026-05-11 01:38:21 +08:00  
Author: Codex

### Scope

- Continued autonomous iteration after Round 53.
- Focused on stop-capture cleanup inside `SentinelContext.tsx`.
- Completed the requested 10-round self-audit cycle.
- Kept `useSentinel()` public shape unchanged.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, or real PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- Current mapper sizes remain within budget:
  - `wailsBridge.ts`: about 23 lines,
  - `c2DecryptDisplayMapper.ts`: about 88 lines,
  - `vshellDecryptDisplayRules.ts`: about 264 lines.

### Changes

- Added `frontend/src/app/state/captureStopWorkflow.ts`:
  - increments capture/filter/threat-analysis sequences,
  - finishes parse/preload runtime,
  - clears filter loading,
  - cancels frontend capture tasks,
  - wakes capture waiters,
  - clears capture UI state,
  - reports disconnected stop state,
  - best-effort cancels media batch transcription,
  - closes backend capture and reports close errors.
- Added `captureStopWorkflow.test.ts` covering:
  - frontend state cleanup and backend close,
  - disconnected backend skip,
  - suppressed media cancellation failure with reported close failure.
- Rewired `SentinelContext.tsx` to delegate `stopCapture()` to the new helper.
- Tightened `frontend/scripts/check-size.mjs`:
  - `SentinelContext.tsx` budget reduced from 1100 to 1085 lines,
  - added budgets for `captureStopWorkflow.ts` and `captureStopWorkflow.test.ts`.
- `SentinelContext.tsx` is now about 999 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/captureStopWorkflow.test.ts src/app/state/captureStopStatus.test.ts src/app/state/captureReplacementPrepare.test.ts src/app/state/captureTaskReset.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 5 files / 13 tests.
- `cd frontend && pnpm run typecheck` - passed after removing an unused provider import.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `cd frontend && pnpm run ci` - passed, 115 test files / 384 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### 10-Round Self-Audit

- Cycle covered Round 45 through Round 54.
- Direction stayed aligned with the agreed plan:
  - state ownership moved out of `SentinelContext`,
  - every extracted helper has focused tests,
  - public Context shape was preserved,
  - mapper files did not grow,
  - MISC remained independent and was not connected to unified Evidence,
  - package-manager / typecheck / lint / format / size / Vitest / build gates stayed active,
  - docs archive remained local/ignored and was not staged.
- Quantitative result:
  - `SentinelContext.tsx` moved from about 1194 lines before Round 45 to about 999 lines after Round 54.
  - Frontend test corpus moved from 105-ish files before this state-extraction sequence to 115 files / 384 tests.
- Next-cycle recommendation:
  - continue with capture-start/preload sub-workflows only if they can be extracted with clear tests,
  - otherwise pivot to the next large state boundary or UI primitive split instead of forcing a risky mega-helper.

---

## Round 55 - Capture Failure Status Extraction

Time: 2026-05-11 01:44:58 +08:00  
Author: Codex

### Scope

- Began the next autonomous engineering cycle after the Round 54 audit.
- Focused on capture-open failure status normalization inside `SentinelContext.tsx`.
- Kept `useSentinel()` public shape unchanged.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, or PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- Mapper growth remains controlled; this round touched only state helper/provider code and size budgets.

### Changes

- Extended `frontend/src/app/state/captureTransactionStatus.ts` with `buildFailedCaptureTransactionStatus`.
- Moved capture-open failure reason selection out of `SentinelContext.tsx`:
  - `preload_timeout`,
  - `empty_parse`,
  - `switch_failed`,
  - `open_failed`.
- Preserved pending capture name/path fallback behavior for replacement failures.
- Added `captureTransactionStatus.test.ts` covering open failure fallback, replacement failure, timeout, and empty-parse classification.
- Tightened `frontend/scripts/check-size.mjs`:
  - `SentinelContext.tsx` budget reduced from 1085 to 1065 lines,
  - added a focused budget for `captureTransactionStatus.test.ts`.
- `SentinelContext.tsx` is now about 989 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/captureTransactionStatus.test.ts src/app/state/capturePreloadStatus.test.ts src/app/state/captureStopWorkflow.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 4 files / 12 tests.
- `cd frontend && pnpm run typecheck` - passed after removing unused provider imports.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `cd frontend && pnpm run ci` - passed, 116 test files / 387 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- New cycle counter: 1 / 10.
- No drift detected:
  - state ownership continues moving out of `SentinelContext`,
  - mapper files did not grow,
  - MISC remains independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: continue with a small capture-start state helper only if it can be isolated with tests and without broad provider churn.

---

## Round 56 - Capture Start State Initialization Extraction

Time: 2026-05-11 01:51:38 +08:00  
Author: Codex

### Scope

- Continued autonomous iteration after Round 55.
- Focused on the low-risk capture-start initialization block inside `SentinelContext.tsx`.
- Kept `useSentinel()` public shape unchanged.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, or PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- Mapper growth remains controlled; this round touched only state helper/provider code and size budgets.

### Changes

- Added `frontend/src/app/state/captureStartState.ts` with `initializeCaptureStartState`.
- Moved the following effects out of `SentinelContext.tsx`:
  - clearing filter loading,
  - clearing packet-page error,
  - resetting preload counters,
  - starting capture parse runtime,
  - setting pending capture transaction,
  - recording recent capture metadata.
- Added `captureStartState.test.ts` covering reset/runtime/pending transaction/recent capture effects.
- Tightened `frontend/scripts/check-size.mjs`:
  - `SentinelContext.tsx` budget reduced from 1065 to 1045 lines,
  - added budgets for `captureStartState.ts` and `captureStartState.test.ts`.
- `SentinelContext.tsx` is now about 984 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/captureStartState.test.ts src/app/state/captureTransactionStatus.test.ts src/app/state/captureResetState.test.ts src/app/state/captureParseRuntimeState.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 5 files / 13 tests.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `cd frontend && pnpm run ci` - passed, 117 test files / 388 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- Current cycle counter: 2 / 10.
- No drift detected:
  - state ownership continues moving out of `SentinelContext`,
  - mapper files did not grow,
  - MISC remains independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: extract another small state-boundary helper only if it is testable without moving the preload loop wholesale.

---

## Round 57 - Capture Commit State Extraction

Time: 2026-05-11 01:59:11 +08:00  
Author: Codex

### Scope

- Continued autonomous iteration after Round 56.
- Focused on the successful capture commit state block inside `SentinelContext.tsx`.
- Kept `useSentinel()` public shape unchanged.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, or PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- Mapper growth remains controlled; this round touched only state helper/provider code and size budgets.

### Changes

- Added `frontend/src/app/state/captureCommitState.ts` with `commitValidatedCaptureState`.
- Moved the successful capture commit effects out of `SentinelContext.tsx`:
  - packet viewport reset,
  - stream runtime/cache/prefetch reset,
  - stream switch metric reset,
  - analysis-state reset,
  - file metadata update,
  - capture revision increment,
  - active capture path update,
  - optional first-page commit.
- Added `captureCommitState.test.ts` covering packet reset, stream runtime reset, metadata update, revision increment, active path update, and first-page commit.
- Tightened `frontend/scripts/check-size.mjs`:
  - `SentinelContext.tsx` budget reduced from 1045 to 1040 lines,
  - added budgets for `captureCommitState.ts` and `captureCommitState.test.ts`.
- `SentinelContext.tsx` is now about 981 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/captureCommitState.test.ts src/app/state/streamRuntimeReset.test.ts src/app/state/captureResetState.test.ts src/app/state/captureCommitStatus.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 5 files / 13 tests.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `cd frontend && pnpm run ci` - passed, 118 test files / 389 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- Current cycle counter: 3 / 10.
- No drift detected:
  - state ownership continues moving out of `SentinelContext`,
  - mapper files did not grow,
  - MISC remains independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: continue only with small, testable capture/provider state seams; avoid extracting the preload polling loop as a mega-helper without stronger behavior tests.

---

## Round 58 - Packet Page Commit State Extraction

Time: 2026-05-11 02:04:14 +08:00  
Author: Codex

### Scope

- Continued autonomous iteration after Round 57.
- Focused on packet-page commit state inside `SentinelContext.tsx`.
- Kept `useSentinel()` public shape unchanged.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, or PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- Mapper growth remains controlled; this round touched only packet state helper/provider code and size budgets.

### Changes

- Added `frontend/src/app/state/packetPageCommit.ts` with `commitPacketPageState`.
- Moved packet-page commit effects out of `SentinelContext.tsx`:
  - cursor/page state updates,
  - total packet and row updates,
  - selected packet retention or clearing,
  - raw hex/layer reset,
  - previous/next page flags,
  - packet-page error clearing.
- Added `packetPageCommit.test.ts` covering selected-packet retention and clearing.
- Tightened `frontend/scripts/check-size.mjs`:
  - `SentinelContext.tsx` budget reduced from 1040 to 1038 lines,
  - added budgets for `packetPageCommit.ts` and `packetPageCommit.test.ts`.
- `SentinelContext.tsx` is now about 979 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/packetPageCommit.test.ts src/app/state/packetPagination.test.ts src/app/state/packetPageLoad.test.ts src/app/state/captureCommitState.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 5 files / 15 tests.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `cd frontend && pnpm run ci` - passed, 119 test files / 391 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- Current cycle counter: 4 / 10.
- No drift detected:
  - state ownership continues moving out of `SentinelContext`,
  - mapper files did not grow,
  - MISC remains independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: evaluate remaining provider-local callbacks; prefer small helpers with direct tests over broad context shape changes.

---

## Round 59 - Capture Clear UI State Extraction

Time: 2026-05-11 02:11:05 +08:00  
Author: Codex

### Scope

- Continued autonomous iteration after Round 58.
- Focused on capture close/stop UI clearing inside `SentinelContext.tsx`.
- Kept `useSentinel()` public shape unchanged.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, or PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- Mapper growth remains controlled; this round touched only capture state helper/provider code and size budgets.

### Changes

- Added `frontend/src/app/state/captureClearState.ts` with `clearCaptureUiStateData`.
- Moved capture UI clearing effects out of `SentinelContext.tsx`:
  - packet viewport reset,
  - preload counter reset,
  - analysis state reset,
  - stream panel and stream id reset,
  - stream runtime/cache/prefetch reset,
  - switch metric reset,
  - file metadata and capture transaction reset,
  - active capture path clear,
  - capture revision increment.
- Added `captureClearState.test.ts` covering UI, preload, stream runtime, metadata, active path, and revision clearing effects.
- Tightened `frontend/scripts/check-size.mjs` with budgets for `captureClearState.ts` and `captureClearState.test.ts` while keeping `SentinelContext.tsx` under the reduced 1035-line budget.
- `SentinelContext.tsx` is now about 968 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/captureClearState.test.ts src/app/state/captureResetState.test.ts src/app/state/streamRuntimeReset.test.ts src/app/state/captureStopWorkflow.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 5 files / 12 tests.
- `cd frontend && pnpm run typecheck` - passed after tightening one test assertion type.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `cd frontend && pnpm run ci` - passed, 120 test files / 392 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- Current cycle counter: 5 / 10.
- No drift detected:
  - state ownership continues moving out of `SentinelContext`,
  - mapper files did not grow,
  - MISC remains independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: inspect the remaining small provider callbacks; if state seams become too thin, pivot to the next planned UI primitive or core-rule boundary.

---

## Round 60 - Packet Filter Action Extraction

Time: 2026-05-11 02:18:40 +08:00  
Author: Codex

### Scope

- Continued autonomous iteration after Round 59.
- Focused on display-filter apply/clear callbacks inside `SentinelContext.tsx`.
- Kept `useSentinel()` public shape unchanged.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, or PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- Mapper budgets remain unchanged; this round touched only state helper/provider code and size budgets.

### Changes

- Added `frontend/src/app/state/packetFilterAction.ts` with `runPacketFilterAction`.
- Moved display-filter synchronization and workflow dispatch out of `SentinelContext.tsx` while preserving:
  - explicit filter apply behavior,
  - current typed filter apply behavior,
  - clear-filter behavior without settled-page polling,
  - inactive-capture backend skip behavior.
- Added `packetFilterAction.test.ts` covering sync, current-value apply, clear, and inactive-capture paths.
- Added size budgets for `packetFilterAction.ts` and `packetFilterAction.test.ts`.
- `SentinelContext.tsx` remains about 968 lines after formatting; this round reduces provider responsibility rather than line count.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/packetFilterAction.test.ts src/app/state/packetFilterWorkflow.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 3 files / 11 tests.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `cd frontend && pnpm run ci` - passed, 121 test files / 396 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- Current cycle counter: 6 / 10.
- No drift detected:
  - state ownership continues moving out of `SentinelContext`,
  - mapper files did not grow,
  - MISC remains independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: inspect remaining provider callbacks for a meaningful state extraction; if only thin wrappers remain, pivot to sidebar/core boundary instead of artificial file splitting.

---

## Round 61 - Packet Page Navigation Extraction

Time: 2026-05-11 02:23:07 +08:00  
Author: Codex

### Scope

- Continued autonomous iteration after Round 60.
- Focused on packet pagination callbacks inside `SentinelContext.tsx`.
- Kept `useSentinel()` public shape unchanged.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, or PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- Mapper file budgets remain unchanged; this round touched only packet state helper/provider code and size budgets.

### Changes

- Added `frontend/src/app/state/packetPageNavigation.ts` with helpers for:
  - next page loading,
  - previous page loading,
  - clamped page jump,
  - current-page retry with status message.
- Replaced provider-local cursor math and retry status wiring in `SentinelContext.tsx` with the new helper calls.
- Added `packetPageNavigation.test.ts` covering next/previous cursor movement, underflow protection, clamped jump, and retry status behavior.
- Added source/test size budgets for the new navigation helper.
- `SentinelContext.tsx` is now about 963 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/packetPageNavigation.test.ts src/app/state/packetPagination.test.ts src/app/state/packetPageStatus.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 4 files / 14 tests.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `cd frontend && pnpm run ci` - passed, 122 test files / 400 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- Current cycle counter: 7 / 10.
- No drift detected:
  - state ownership continues moving out of `SentinelContext`,
  - mapper files did not grow,
  - MISC remains independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: evaluate selected-packet callback or stream helper boundaries; avoid thin extractions that only move one line without testable state behavior.

---

## Round 62 - Capture Preload Probe Extraction

Time: 2026-05-11 02:28:42 +08:00  
Author: Codex

### Scope

- Continued autonomous iteration after Round 61.
- Focused on the capture preload probing block inside `startCapture`.
- Kept `useSentinel()` public shape unchanged.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, or PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- Mapper budgets remain unchanged; this round touched capture state helper/provider code and size budgets only.

### Changes

- Added `frontend/src/app/state/capturePreloadProbe.ts` with `resolveCapturePreloadFirstPage`.
- Moved first-page validation, active-capture status confirmation, polling waits, stale-sequence handling, empty-parse error, and timeout error out of `SentinelContext.tsx`.
- Kept `startCapture` responsible for orchestration only: opening, replacement prep, stream start, commit, analysis refresh, and error transaction handling.
- Added `capturePreloadProbe.test.ts` covering:
  - validated first-page success,
  - polling until backend status matches selected capture,
  - stale capture sequence return,
  - empty parse error,
  - preload timeout.
- Added source/test size budgets for the new preload probe helper.
- `SentinelContext.tsx` is now about 900 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/capturePreloadProbe.test.ts src/app/state/capturePreloadStatus.test.ts src/app/state/captureCommitStatus.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 4 files / 15 tests.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- Initial `cd frontend && pnpm run ci` failed only at scoped Prettier check for `scripts/check-size.mjs`; fixed with Prettier.
- `cd frontend && pnpm run format:check` - passed after formatting.
- `cd frontend && pnpm run ci` - passed, 123 test files / 405 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- Current cycle counter: 8 / 10.
- No drift detected:
  - state ownership continues moving out of `SentinelContext`,
  - mapper files did not grow,
  - MISC remains independent from unified Evidence,
  - quality gates remain green after format correction,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: continue toward sub-800 provider by extracting another meaningful capture/stream state boundary; avoid mapper growth and avoid MISC/Evidence coupling.

---

## Round 63 - Capture Start Backend Extraction

Time: 2026-05-11 02:34:18 +08:00  
Author: Codex

### Scope

- Continued autonomous iteration after Round 62.
- Focused on backend-start orchestration inside `startCapture`.
- Kept `useSentinel()` public shape unchanged.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, or PCAP fixtures.

### Mapper Size Check

- No mapper files were changed this round.
- Mapper budgets remain unchanged; this round touched capture start helper/provider code and size budgets only.

### Changes

- Added `frontend/src/app/state/captureStartBackend.ts` with:
  - `resolveOpenedCapture` for provided-path versus file-dialog selection,
  - `startCaptureBackend` for scoped backend streaming start and stale-sequence guard,
  - `prepareAndStartOpenedCapture` for replacement prep, pending transaction initialization, stream start, and preload status transition.
- Replaced provider-local open/start initialization code in `SentinelContext.tsx` with the new helper calls.
- Added `captureStartBackend.test.ts` covering path resolution, dialog fallback, backend start, stale sequence, and start-state initialization with preload status.
- Added source/test size budgets for the new helper.
- `SentinelContext.tsx` is now about 894 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/captureStartBackend.test.ts src/app/state/captureStartState.test.ts src/app/state/captureOpenState.test.ts src/app/state/capturePreloadProbe.test.ts src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 5 files / 18 tests.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run size:check` - passed.
- `cd frontend && pnpm run ci` - passed, 124 test files / 410 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- Current cycle counter: 9 / 10.
- No drift detected:
  - state ownership continues moving out of `SentinelContext`,
  - mapper files did not grow,
  - MISC remains independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: one more round, then perform the required 10-round self-audit after Round 64.

---

## Round 64 - Capture Finalization Extraction

Time: 2026-05-11 02:44:47 +08:00  
Author: Codex

### Scope

- Completed the final capture-open step extraction after Round 63.
- Focused on validated capture commit, stream index refresh, done status publication, and quiet analysis refresh.
- Kept `useSentinel()` public shape unchanged.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, PCAP fixtures, or public model shapes.

### Mapper Size Check

- No mapper files were changed this round.
- Mapper budgets remain unchanged.

### Changes

- Added `frontend/src/app/state/captureFinalizeWorkflow.ts` with `finalizeOpenedCapture`.
- Moved post-validation capture finalization out of `SentinelContext.tsx`:
  - commit validated first packet page,
  - refresh stream index,
  - stop stale capture finalization,
  - publish idle capture transaction and done backend status,
  - run quiet analysis refresh.
- Added `captureFinalizeWorkflow.test.ts` covering success and stale finalization behavior.
- Added `formatBytes.ts` as a tiny shared byte-format helper and moved direct imports away from `SentinelContext`.
- Removed the `filteredPackets` alias and inline page count calculation in the provider value to keep the provider below the tightened budget.
- Tightened `SentinelContext.tsx` size budget to `930` lines and added budgets for `captureFinalizeWorkflow.ts`, `captureFinalizeWorkflow.test.ts`, and `formatBytes.ts`.
- `SentinelContext.tsx` is now under the new size budget after formatting.

### Validation

- `cd frontend && pnpm run ci` - passed, 125 test files / 412 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.
- Intermediate focused validation for capture finalization passed before full CI.
- Initial size check caught `SentinelContext.tsx` above the new budget; fixed by extracting `formatBytes` and removing provider-local aliases instead of relaxing the budget.

### Review

- Current cycle counter: 10 / 10.
- No drift detected:
  - state ownership continues moving out of `SentinelContext`,
  - mapper files did not grow,
  - MISC remains independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.

### Ten-Round Self-Audit

- Rounds 55-64 stayed on frontend state-boundary engineering.
- `SentinelContext.tsx` dropped from about 1085 lines at the Round 55 baseline to under the new 930-line budget.
- Added focused tests for capture failure/start/commit/clear, packet page commit/navigation/filter, preload probing, backend start, and finalization.
- No mapper files changed in this cycle.
- No MISC-to-Evidence coupling introduced.
- Package manager and CI discipline remain unchanged: pnpm only, full `pnpm run ci` required.
- Mainline remains valid. Next cycle should continue only where boundary extraction is real and testable; otherwise pivot to the planned sidebar/core targets rather than mechanically splitting files.

---

## Round 65 - Sentinel Derived View and Packet Resource Hooks

Time: 2026-05-11 03:01:06 +08:00  
Author: Codex

### Scope

- Began the next autonomous cycle after the Round 64 ten-round self-audit.
- Continued state-boundary cleanup in `SentinelContext.tsx`.
- Kept `useSentinel()` public shape unchanged.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, PCAP fixtures, or public model shapes.

### Mapper Size Check

- No mapper files were changed this round.
- Mapper budgets remain unchanged.

### Changes

- Added `frontend/src/app/state/sentinelDerivedView.ts` to derive:
  - filtered packet view,
  - selected packet,
  - protocol tree,
  - hex dump,
  - current and total packet pages.
- Added `frontend/src/app/state/hooks/useSelectedPacketResources.ts` to compose selected packet detail, raw hex, and layer loading hooks.
- Replaced provider-local selected packet artifact loading with the composed hook.
- Added focused tests for the derived view and selected packet resources.
- Tightened `SentinelContext.tsx` budget from `930` to `910` and added budgets for the new helper/hook/tests.
- `SentinelContext.tsx` is now about 862 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/sentinelDerivedView.test.ts src/app/state/hooks/useSelectedPacketResources.test.tsx src/app/state/hooks/useSelectedPacketDetail.test.tsx src/app/state/hooks/useSelectedPacketArtifact.test.tsx src/app/components/workspace/WorkspacePanels.test.tsx` - passed, 5 files / 11 tests.
- `cd frontend && pnpm run ci` - passed, 127 test files / 415 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.
- Initial size check caught the new hook test above its budget; fixed by reducing test fixture noise instead of relaxing the budget.

### Review

- Current cycle counter: 1 / 10.
- No drift detected:
  - state ownership continues moving out of `SentinelContext`,
  - mapper files did not grow,
  - MISC remains independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: continue only if another meaningful provider state boundary is testable; otherwise pivot to planned `sidebar.tsx` or core rule extraction.

---

## Round 66 - Sidebar Menu Primitive Split

Time: 2026-05-11 03:06:42 +08:00  
Author: Codex

### Scope

- Pivoted from `SentinelContext` to the next planned oversized shared UI primitive.
- Focused on `components/ui/sidebar.tsx`, then the largest remaining frontend UI primitive file.
- Kept the public import path `components/ui/sidebar` compatible.
- Did not modify mapper files, backend APIs, MISC evidence routing, samples, PCAP fixtures, or public model shapes.

### Mapper Size Check

- No mapper files were changed this round.
- Mapper budgets remain unchanged.

### Changes

- Added `frontend/src/app/components/ui/sidebarMenu.tsx` for menu-specific sidebar primitives:
  - menu container/item,
  - menu button variant styling,
  - menu action/badge/skeleton,
  - sub-menu item/button primitives.
- Left `sidebar.tsx` responsible for sidebar shell, trigger, rail, inset, header/footer/content/group primitives, and compatibility exports.
- Tightened `sidebar.tsx` budget from `630` to `360` lines and added a new `sidebarMenu.tsx` budget.
- `sidebar.tsx` now sits near 331 lines after formatting.

### Validation

- `cd frontend && pnpm exec vitest run src/app/layouts/MainLayout.test.ts src/app/components/RuntimeSettingsSidebarParts.test.tsx src/app/pages/AnalysisCockpit.test.tsx` - passed, 3 files / 10 tests.
- `cd frontend && pnpm run ci` - passed, 127 test files / 415 tests, plus package-manager check, typecheck, ESLint, scoped Prettier, size budget, and Vite build.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- Current cycle counter: 2 / 10.
- No drift detected:
  - shared UI primitive split followed the planned sidebar target,
  - mapper files did not grow,
  - MISC remains independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: continue sidebar shell split only if a natural provider/rail/content boundary remains; otherwise move to `core/engine.ts` or `captureOverview.ts` pure-rule extraction.

---

## Round 67 - Core Protocol Tree Split

Time: 2026-05-11 03:15:19 +08:00  
Author: Codex

### Scope

- Split core protocol tree logic out of `engine.ts`.
- Kept `core/engine` as compatibility facade.
- Did not change mapper files, backend APIs, MISC Evidence routing, samples, PCAP fixtures, or public model shapes.

### Mapper Size Check

- No mapper files were changed this round.
- Mapper budgets remain unchanged.

### Changes

- Added `protocolTree.ts` for base packet protocol tree building.
- Added `protocolLayerTree.ts` for tshark layer tree expansion.
- Added `protocolLayerFormat.ts` for pure layer formatting helpers.
- Reduced `engine.ts` to facade exports.
- Tightened core size budgets.

### Validation

- Focused core/workspace tests passed, 3 files / 6 tests.
- `cd frontend && pnpm run ci` passed, 127 test files / 415 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.
- Initial size check caught `protocolLayerTree.ts` over budget; fixed by extracting format helpers and tightening structure instead of relaxing budget.

### Review

- Current cycle counter: 3 / 10.
- No drift detected:
  - pure core rule ownership improved,
  - mapper files did not grow,
  - MISC remains independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: `captureOverview.ts` pure-rule split or another natural core/state boundary.

---

## Round 68 - Capture Overview Rule Split

Time: 2026-05-11 03:20:35 +08:00  
Author: Codex

### Scope

- Split capture mission overview scoring, filters, protocol picking, and threat ordering into pure core modules.
- Kept `buildCaptureOverview` and exported capture overview types compatible from `core/captureOverview`.
- Did not change mapper files, backend APIs, MISC Evidence routing, samples, PCAP fixtures, or public model shapes.

### Mapper Size Check

- No mapper files were changed this round.
- Mapper budgets remain unchanged.

### Changes

- Added `captureOverviewTypes.ts` for public overview model contracts.
- Added `captureOverviewCounts.ts` for module/stream/object/threat counts.
- Added `captureOverviewFilters.ts` for static protocol filter registry.
- Added `captureOverviewProtocols.ts` for top-protocol selection.
- Added `captureOverviewThreat.ts` for suspicious-hit ordering.
- Added `captureOverviewRecommendations.ts` for route recommendation scoring.
- Added `captureOverviewQuickFilters.ts` for quick filter suggestions.
- Reduced `captureOverview.ts` from 338 lines to about 65 lines as orchestration plus headline selection.
- Added size budgets for the split capture overview modules.

### Validation

- `cd frontend && pnpm exec vitest run src/app/core/captureOverview.test.ts` passed, 1 file / 2 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 127 test files / 415 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 4 / 10.
- No drift detected:
  - pure core ownership improved,
  - mapper files did not grow,
  - MISC remains independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: inspect remaining large files and choose a natural state/core/UI boundary without mapper growth.

---

## Round 69 - Backend Lifecycle Hook Split

Time: 2026-05-11 03:28:15 +08:00  
Author: Codex

### Scope

- Split `useBackendLifecycle.ts` into startup, SSE event, and timer helpers.
- Kept `BackendLifecycleState` and `useBackendLifecycle` public behavior unchanged.
- Did not change mapper files, backend APIs, MISC Evidence routing, samples, PCAP fixtures, or public model shapes.

### Mapper Size Check

- No mapper files were changed this round.
- Mapper budgets remain unchanged.

### Changes

- Added `backendLifecycleEvents.ts` for packet/status/error event effects.
- Added `backendLifecycleStartup.ts` for desktop backend status, startup runtime check, and TLS config startup load.
- Added `backendLifecycleTimers.ts` for small timer cleanup helper.
- Reduced `useBackendLifecycle.ts` from about 365 lines to about 216 lines.
- Added size budgets for the split backend lifecycle helpers.
- Size gate initially failed at `useBackendLifecycle.ts: 306/295`, then again after formatting at `250/240`; fixed by extracting startup and timer helpers instead of relaxing budget.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/useBackendLifecycle.test.tsx` passed, 1 file / 6 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 127 test files / 415 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 5 / 10.
- No drift detected:
  - state ownership improved around backend lifecycle,
  - mapper files did not grow,
  - MISC remains independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: inspect remaining large files and choose a natural UI/state boundary; likely `Workspace.tsx`, `MiscToolsShell.tsx`, or `MainLayoutChrome.tsx` if a safe split exists.

---

## Round 70 - Workspace Selection Hook Split

Time: 2026-05-11 03:32:48 +08:00  
Author: Codex

### Scope

- Split workspace protocol-tree byte selection and filter loading progress out of `Workspace.tsx`.
- Kept Workspace page behavior, routes, table props, and `useSentinel()` consumption shape unchanged.
- Did not change mapper files, backend APIs, MISC Evidence routing, samples, PCAP fixtures, or public model shapes.

### Mapper Size Check

- No mapper files were changed this round.
- Mapper budgets remain unchanged.

### Changes

- Added `useWorkspaceProtocolSelection.ts` for selected tree node, selected byte offset, byte range, frame bytes, and scroll refs.
- Added `useWorkspaceFilterProgress.ts` for optimistic filter loading progress.
- Reduced `Workspace.tsx` from about 344 lines to about 262 lines.
- Tightened `Workspace.tsx` budget from 350 to 290 and added budgets for the new workspace hooks.
- Size gate initially failed at `Workspace.tsx: 295/290`; fixed by extracting filter progress instead of relaxing budget.

### Validation

- `cd frontend && pnpm exec vitest run src/app/components/workspace/WorkspacePanels.test.tsx src/app/pages/AnalysisCockpit.test.tsx` passed, 2 files / 4 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed via full CI.
- `cd frontend && pnpm run ci` passed, 127 test files / 415 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 6 / 10.
- No drift detected:
  - workspace page is thinner and remains orchestration-focused,
  - mapper files did not grow,
  - MISC remains independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: continue with a natural UI boundary such as `MainLayoutChrome.tsx`, `MiscToolsShell.tsx`, or a tested state boundary.

---

## Round 71 - Main Layout Chrome Split

Time: 2026-05-11 03:37:21 +08:00  
Author: Codex

### Scope

- Split main layout chrome into header, sidebar nav, settings shell, footer, and shared type modules.
- Kept `layouts/MainLayoutChrome` as a compatibility export layer.
- Did not change mapper files, backend APIs, MISC Evidence routing, samples, PCAP fixtures, or public model shapes.

### Mapper Size Check

- No mapper files were changed this round.
- Mapper budgets remain unchanged.

### Changes

- Added `MainHeader.tsx` for menu/header presentation.
- Added `MainSidebarNav.tsx` for icon rail presentation.
- Added `MainSettingsChrome.tsx` for runtime settings offcanvas shell.
- Added `MainFooter.tsx` for file/backend/TLS status presentation.
- Added `mainLayoutChromeTypes.ts` for `MainLayoutChromeProps`.
- Reduced `MainLayoutChrome.tsx` from about 315 lines to a 5-line compatibility export facade.
- Replaced the old 330-line budget with budgets for each new layout chrome module.

### Validation

- `cd frontend && pnpm exec vitest run src/app/layouts/MainLayout.test.ts src/app/pages/AnalysisCockpit.test.tsx src/app/components/RuntimeSettingsSidebarParts.test.tsx` passed, 3 files / 10 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 127 test files / 415 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 7 / 10.
- No drift detected:
  - layout chrome now follows presentation-split boundary,
  - mapper files did not grow,
  - MISC remains independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: `MiscToolsShell.tsx` or `StreamDecoderWorkbench.tsx`, but only if a safe tested presentation boundary exists.

---

## Round 72 - MISC Shell Presentation Split

Time: 2026-05-11 03:43:12 +08:00  
Author: Codex

### Scope

- Split `MiscToolsShell.tsx` into hero, module card, and pure MISC module rules.
- Kept MISC as an independent workbench and did not connect it to unified Evidence.
- Did not change mapper files, backend APIs, samples, PCAP fixtures, or public model shapes.

### Mapper Size Check

- No mapper files were changed this round.
- Mapper budgets remain unchanged.

### Changes

- Added `MiscToolsHero.tsx` for category tabs and module ZIP import presentation.
- Added `MiscModuleCard.tsx` for module card header, metadata tags, lazy renderer mount, and loading state.
- Added `miscModuleRules.ts` for category matching, module metadata summary, and icon selection.
- Reduced `MiscToolsShell.tsx` from about 342 lines to about 86 lines.
- Added size budgets for split MISC modules, with explicit rule that MISC rules do not connect to unified Evidence.

### Validation

- `cd frontend && pnpm exec vitest run src/app/pages/MiscTools.test.tsx src/app/pages/MiscTools.customModules.test.tsx src/app/pages/MiscTools.sessions.test.tsx src/app/pages/MiscTools.smb3.test.tsx src/app/pages/MiscTools.payloadHints.test.tsx` passed, 5 files / 21 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 127 test files / 415 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 8 / 10.
- No drift detected:
  - MISC stayed independent from unified Evidence,
  - mapper files did not grow,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: inspect remaining large files; possible targets are `StreamDecoderWorkbench.tsx`, `AnalysisPrimitives.tsx`, or `SentinelContext.tsx` if a safe state boundary exists.

---

## Round 73 - Stream Decoder Workbench State Split

Time: 2026-05-11 03:51:26 +08:00  
Author: Codex

### Scope

- Split `StreamDecoderWorkbench.tsx` state and inspection workflow into hooks.
- Kept decoder UI behavior, backend bridge calls, request shape, and result rendering unchanged.
- Did not change mapper files, backend APIs, samples, PCAP fixtures, or public model shapes.

### Mapper Size Check

- No mapper files were changed this round.
- `vshellDecryptDisplayRules.ts` remains unchanged at its existing budget.

### Changes

- Added `useStreamDecoderWorkbench.ts` for decoder settings, decode workflow, batch progress, overwrite/derived apply mode, and cancel state.
- Added `useStreamPayloadInspection.ts` for payload inspection bridge calls, candidate selection, loading state, and inspection error handling.
- Reduced `StreamDecoderWorkbench.tsx` from about 346 lines to about 88 lines.
- Tightened `StreamDecoderWorkbench.tsx` size budget from 375 lines to 105 lines.
- Added budgets for the new decoder state and inspection hooks.

### Validation

- `cd frontend && pnpm exec vitest run src/app/components/StreamDecoderWorkbenchUtils.test.ts src/app/components/StreamDecoderBatchPanel.test.tsx src/app/components/StreamDecoderToolbar.test.tsx` passed, 3 files / 13 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 127 test files / 415 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 9 / 10.
- No drift detected:
  - mapper files did not grow,
  - MISC stayed independent from unified Evidence,
  - decoder workbench remains a composition layer,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: one more low-risk frontend boundary split, then perform the 10-round self-audit.

---

## Round 74 - Analysis Primitive Boundary Split

Time: 2026-05-11 03:56:07 +08:00  
Author: Codex

### Scope

- Split shared analysis primitive UI into tone tokens, cards, and collection renderers.
- Kept `AnalysisPrimitives.tsx` as the compatibility export path for existing pages.
- Did not change mapper files, backend APIs, samples, PCAP fixtures, or public model shapes.

### Mapper Size Check

- No mapper files were changed this round.
- Current largest mapper-related files remain unchanged:
  - `vshellDecryptDisplayRules.ts`: 264 lines,
  - `protocolToolMapper.ts`: 226 lines,
  - `vehicleMapper.ts`: 201 lines.

### Changes

- Added `analysisTone.ts` for `AnalysisTone`, `AnalysisBucket`, and tone class maps.
- Added `AnalysisCards.tsx` for stat cards, panels, mini stats, badges, empty state, and callouts.
- Added `AnalysisCollections.tsx` for bucket chart and list primitives.
- Reduced `AnalysisPrimitives.tsx` from about 279 lines to an 11-line compatibility facade.
- Tightened `AnalysisPrimitives.tsx` budget from 310 lines to 20 lines and added budgets for the split primitives.

### Validation

- `cd frontend && pnpm exec vitest run src/app/pages/TrafficGraph.test.ts src/app/pages/IndustrialAnalysis.test.tsx src/app/pages/C2Analysis.test.tsx src/app/pages/AptAnalysis.test.tsx` passed, 4 files / 8 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 127 test files / 415 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 10 / 10.
- No drift detected:
  - mapper files did not grow,
  - MISC stayed independent from unified Evidence,
  - shared analysis primitives remain UI-only and domain-neutral,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.

---

## 10-Round Self-Audit - Rounds 65-74

Time: 2026-05-11 03:56:07 +08:00  
Author: Codex

### Scope Checked

- Recent ten-round engineering arc covering capture/state helpers, sidebar/menu, core protocol/capture overview, backend lifecycle, workspace/layout, MISC shell, decoder workbench, and analysis primitive splits.

### Mainline Alignment

- Mainline preserved:
  - frontend engineering boundary cleanup,
  - state/core/UI/module responsibility reduction,
  - quality gate hardening through `pnpm run ci`, size budgets, lint, typecheck, and tests.
- No business-behavior expansion was mixed into these rounds.
- MISC remained an independent workbench and was not connected to unified Evidence.

### Mapper Discipline

- Mapper files were not used as dumping grounds during these rounds.
- `vshellDecryptDisplayRules.ts` remains the largest mapper-adjacent risk at 264 lines, but it was not increased during this cycle.
- Future mapper work should split VShell display rules by decoding, ANSI/timestamp filtering, and low-info frame rules before adding new behavior.

### Size and Boundary Progress

- `StreamDecoderWorkbench.tsx`: about 346 lines to 88 lines.
- `MiscToolsShell.tsx`: about 342 lines to 86 lines.
- `AnalysisPrimitives.tsx`: about 279 lines to 11 lines.
- `MainLayoutChrome.tsx`: about 315 lines to a compatibility export.
- `core/engine.ts` and `captureOverview.ts` now act as small facades over pure modules.
- `useBackendLifecycle.ts` and `Workspace.tsx` were reduced by extracting focused hooks.

### Remaining Risks

- `SentinelContext.tsx` remains the largest high-risk state owner at about 862 lines.
- `sidebar.tsx` remains a shared primitive risk, though menu/context pieces have already been split.
- `vshellDecryptDisplayRules.ts` should be split before any new VShell filtering logic lands.
- Some page bundles remain large because feature workflows are still wide, not because the pages are pure monoliths.

### Verdict

- No drift from the user-requested engineering mainline.
- Current engineering maturity is materially improved, but not complete.
- Next autonomous cycle should prioritize:
  1. low-risk `SentinelContext` internal helper extraction with tests,
  2. VShell display rule split if VShell UI filtering changes resume,
  3. remaining sidebar primitive split,
  4. continued strict size-budget tightening after each split.

---

## Round 75 - VShell Display Rule Split

Time: 2026-05-11 04:03:14 +08:00  
Author: Codex

### Scope

- Split the largest mapper-adjacent VShell display rule file without changing behavior.
- Preserved C2 decrypt display normalization, VShell low-info filtering, timestamp hiding, ANSI cleanup, UTF-8 hex conversion, and best-effort text extraction behavior.
- Did not change backend APIs, decrypt request shape, samples, PCAP fixtures, or public model shapes.

### Mapper Size Check

- Reduced `vshellDecryptDisplayRules.ts` from about 264 lines to about 122 lines.
- Added:
  - `vshellTextSignals.ts` for ANSI cleanup, timestamp-only detection, visible text checks, and forensic text signals.
  - `vshellHexPreview.ts` for hex parsing, strict UTF-8 decode, best-effort extraction, and low-info binary hex checks.
- Tightened `vshellDecryptDisplayRules.ts` budget from 305 lines to 130 lines.
- Added 90-line budgets for the two new VShell helper files.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations/wailsBridge.test.ts src/app/pages/C2Analysis.decrypt.test.tsx src/app/pages/C2Analysis.vshell.test.tsx` passed, 3 files / 13 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 127 test files / 415 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 1 / 10.
- No drift detected:
  - VShell logic stayed in mapper/rule layer,
  - mapper-adjacent largest file was reduced rather than enlarged,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: continue mapper size discipline on `protocolToolMapper.ts` or `vehicleMapper.ts`, unless `SentinelContext` presents a safer tested helper split.

---

## Round 76 - Protocol Tool Mapper Split

Time: 2026-05-11 04:08:09 +08:00  
Author: Codex

### Scope

- Split `protocolToolMapper.ts` into protocol-specific mapper files while preserving the existing import path.
- Kept HTTP login, SMTP, MySQL, and Shiro rememberMe mapping behavior unchanged.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, or public model shapes.

### Mapper Size Check

- Reduced `protocolToolMapper.ts` from about 226 lines to a 4-line compatibility facade.
- Added:
  - `httpLoginMapper.ts`,
  - `smtpMapper.ts`,
  - `mysqlMapper.ts`,
  - `shiroRememberMeMapper.ts`.
- Moved `optionalString` and `optionalNumber` into `mapperPrimitives.ts` for reuse.
- Added size budgets for the facade and split protocol mappers.
- Current largest mapper file is now `vehicleMapper.ts` at about 201 lines.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/protocolToolMapper.test.ts` passed, 1 file / 5 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 127 test files / 415 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 2 / 10.
- No drift detected:
  - protocol mapper behavior stayed shape-compatible,
  - mapper file growth was reduced,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: inspect `vehicleMapper.ts` for safe split; if not safe, return to tested `SentinelContext` helper extraction.

---

## Round 77 - Vehicle Mapper Split

Time: 2026-05-11 04:12:34 +08:00  
Author: Codex

### Scope

- Split `vehicleMapper.ts` into CAN and diagnostic section mappers while preserving the existing `asVehicleAnalysis` import path.
- Kept CAN, DBC, J1939, DoIP, UDS, transaction, and recommendation mapping behavior unchanged.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, or public model shapes.

### Mapper Size Check

- Reduced `vehicleMapper.ts` from about 201 lines to about 16 lines.
- Added:
  - `vehicleCanMapper.ts` for CAN frame, payload record, DBC message, and signal timeline mapping.
  - `vehicleDiagnosticMapper.ts` for J1939, DoIP, UDS message, and UDS transaction mapping.
- Added size budgets for the vehicle mapper facade and the two split mapper files.
- Current largest runtime mapper files are now `toolMapper.ts`, `packetStreamMapper.ts`, `c2SampleMapper.ts`, and `industrialMapper.ts`.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/vehicleMapper.test.ts src/app/pages/VehicleAnalysis.test.ts` passed, 2 files / 4 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 127 test files / 415 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 3 / 10.
- No drift detected:
  - mapper behavior stayed shape-compatible,
  - mapper file growth was reduced,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: inspect `toolMapper.ts` for safe split; otherwise begin low-risk `SentinelContext` helper extraction.

---

## Round 78 - Tool Mapper Split

Time: 2026-05-11 04:19:53 +08:00  
Author: Codex

### Scope

- Split `toolMapper.ts` into misc module, misc schema/table, session material, and WinRM mapper files while preserving the existing `./toolMapper` import path.
- Kept MISC module manifests/import/run results, SMB3/NTLM session material mapping, and WinRM decrypt mapping behavior unchanged.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, or public model shapes.

### Mapper Size Check

- Reduced `toolMapper.ts` from about 196 lines to a 3-line compatibility facade.
- Added:
  - `miscModuleMapper.ts` at 39 lines,
  - `miscModuleSchemaMapper.ts` at 61 lines,
  - `sessionMaterialMapper.ts` at 54 lines,
  - `winrmMapper.ts` at 17 lines.
- Added size budgets for the facade and all split mapper files.
- Avoided growing mapper files by splitting schema/table conversion separately instead of raising the misc module budget.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/toolMapper.test.ts` passed, 1 file / 5 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 127 test files / 415 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 4 / 10.
- No drift detected:
  - mapper behavior stayed shape-compatible,
  - mapper file growth was reduced,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: inspect `packetStreamMapper.ts` for safe split; if risk is higher than value, inspect `c2SampleMapper.ts` or continue tested `SentinelContext` helper extraction.

---

## Round 79 - Packet Stream Mapper Split

Time: 2026-05-11 04:23:39 +08:00  
Author: Codex

### Scope

- Split `packetStreamMapper.ts` into packet, stream, and threat mapper files while preserving the existing `./packetStreamMapper` import path.
- Kept packet time normalization, packet color feature mapping, HTTP/Binary stream chunk mapping, stream load metadata, and threat level fallback behavior unchanged.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, or public model shapes.

### Mapper Size Check

- Reduced `packetStreamMapper.ts` from about 158 lines to a 3-line compatibility facade.
- Added:
  - `packetMapper.ts` at 76 lines,
  - `streamMapper.ts` at 60 lines,
  - `threatMapper.ts` at 18 lines.
- Added size budgets for the facade and split mapper files.
- Continued mapper-size control after Round 78 without increasing existing budgets.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/packetStreamMapper.test.ts` passed, 1 file / 3 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 127 test files / 415 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 5 / 10.
- No drift detected:
  - mapper behavior stayed shape-compatible,
  - mapper file growth was reduced,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: inspect `c2SampleMapper.ts`; if it has clean C2/VShell/aggregate boundaries, split it next, otherwise target `industrialMapper.ts`.

---

## Round 80 - C2 Sample Mapper Split

Time: 2026-05-11 04:27:20 +08:00  
Author: Codex

### Scope

- Split `c2SampleMapper.ts` into C2 family, aggregate, and indicator mapper files while preserving the existing `./c2SampleMapper` import path.
- Kept CS/VShell sample analysis mapping behavior unchanged, including candidate family fallback, host/URI aggregates, DNS aggregates, stream aggregates, score factors, and notes.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, or public model shapes.

### Mapper Size Check

- Reduced `c2SampleMapper.ts` from about 150 lines to a 1-line compatibility export.
- Added:
  - `c2IndicatorMapper.ts` at 45 lines,
  - `c2AggregateMapper.ts` at 70 lines,
  - `c2FamilyMapper.ts` at 33 lines.
- Added size budgets for the facade and split C2 mapper files.
- Preserved C2/VShell analysis boundaries; no MISC/Evidence coupling introduced.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/c2SampleMapper.test.ts` passed, 1 file / 2 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 127 test files / 415 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 6 / 10.
- No drift detected:
  - mapper behavior stayed shape-compatible,
  - mapper file growth was reduced,
  - C2/VShell sample analysis stayed in C2 domain,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: inspect `industrialMapper.ts`; split only if pure mapper boundaries are clear and Modbus decoded-input behavior remains covered.

---

## Round 81 - Industrial Mapper Split

Time: 2026-05-11 04:31:06 +08:00  
Author: Codex

### Scope

- Split `industrialMapper.ts` into Modbus-specific mapping and generic industrial detail/rule mapping while preserving the existing `asIndustrialAnalysis` import path.
- Kept Modbus decoded input, transaction bit range, suspicious writes, control commands, rule hits, protocol details, and notes behavior unchanged.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, or public model shapes.

### Mapper Size Check

- Reduced `industrialMapper.ts` from about 143 lines to 17 lines.
- Added:
  - `modbusMapper.ts` at 81 lines,
  - `industrialDetailMapper.ts` at 65 lines.
- Added size budgets for the industrial composition mapper and split detail files.
- Kept the Modbus UTF-8 decoded-input path inside the industrial domain and covered by existing tests.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/industrialMapper.test.ts src/app/pages/IndustrialAnalysis.test.tsx` passed, 2 files / 3 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 127 test files / 415 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 7 / 10.
- No drift detected:
  - mapper behavior stayed shape-compatible,
  - mapper file growth was reduced,
  - industrial logic stayed in the industrial domain,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: audit remaining mapper sizes; if no mapper exceeds a useful split threshold, pivot to a tested `SentinelContext` helper extraction.

---

## Round 82 - Sentinel Runtime Hook Extraction

Time: 2026-05-11 04:37:55 +08:00  
Author: Codex

### Scope

- Extracted stream switch metric state/refs/recording from `SentinelContext.tsx` into `useStreamSwitchMetrics`.
- Extracted capture waiter ref/wake/wait callbacks from `SentinelContext.tsx` into `useCaptureSignalWaiters`.
- Kept `useSentinel()` public shape unchanged and did not split public Context.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, or public model shapes.

### State Size Check

- Reduced `SentinelContext.tsx` to 835 lines.
- Added:
  - `useStreamSwitchMetrics.ts` at 39 lines,
  - `useCaptureSignalWaiters.ts` at 16 lines,
  - focused hook tests for both hooks.
- Tightened `SentinelContext.tsx` size budget from 910 to 890 lines.
- Added budgets for the new hooks and tests.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/useStreamSwitchMetrics.test.tsx src/app/state/hooks/useCaptureSignalWaiters.test.tsx src/app/state/captureSignal.test.ts src/app/state/streamSwitchMetrics.test.ts src/app/state/streamSwitchWorkflow.test.ts src/app/pages/AnalysisCockpit.test.tsx` passed, 6 files / 13 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 129 test files / 417 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 8 / 10.
- No drift detected:
  - public `useSentinel()` contract stayed stable,
  - runtime state ownership moved into focused hooks,
  - mapper file growth remained controlled,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: continue low-risk `SentinelContext` extraction, likely recent-capture persistence or selected-packet action helpers, unless a larger risk appears during inspection.

---

## Round 83 - Recent Capture State Hook Extraction

Time: 2026-05-11 04:46:20 +08:00  
Author: Codex

### Scope

- Extracted recent capture history state and localStorage persistence from `SentinelContext.tsx` into `useRecentCapturesState`.
- Kept `useSentinel()` public shape unchanged and did not split public Context.
- Kept `recentCaptures` helper semantics unchanged: load persisted entries, deduplicate reopened paths, and persist remembered captures.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, or public model shapes.

### State Size Check

- Reduced `SentinelContext.tsx` to 828 lines.
- Added:
  - `useRecentCapturesState.ts` at 14 lines,
  - `useRecentCapturesState.test.tsx` at 33 lines.
- Added size budgets for the new hook and focused hook test.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/useRecentCapturesState.test.tsx src/app/state/recentCaptures.test.ts src/app/pages/AnalysisCockpit.test.tsx` passed, 3 files / 6 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 130 test files / 418 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 9 / 10.
- No drift detected:
  - public `useSentinel()` contract stayed stable,
  - recent capture ownership moved into a focused hook,
  - mapper file growth remained controlled,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: continue one more low-risk `SentinelContext` extraction, then perform the 10-round self-audit before choosing the next engineering boundary.

---

## Round 84 - USB Mapper Boundary Split

Time: 2026-05-11 04:52:01 +08:00  
Author: Codex

### Scope

- Split `usbMapper.ts` into domain mappers while preserving the existing `asUSBAnalysis` import path.
- Added:
  - `usbRecordMapper.ts`,
  - `usbHidMapper.ts`,
  - `usbMassStorageMapper.ts`,
  - `usbOtherMapper.ts`.
- Kept USB summary, HID keyboard/mouse events, Mass Storage read/write operations, Other USB records, notes, and default empty behavior unchanged.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### Mapper Size Check

- Reduced `usbMapper.ts` from about 130 lines to 30 lines.
- Added focused budgets:
  - `usbMapper.ts` max 45 lines,
  - `usbHidMapper.ts` max 60 lines,
  - `usbMassStorageMapper.ts` max 55 lines,
  - `usbOtherMapper.ts` max 25 lines,
  - `usbRecordMapper.ts` max 30 lines.
- Current largest mapper implementation files remain bounded; test files are larger because they hold fixtures and assertions.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/usbMapper.test.ts src/app/pages/UsbAnalysis.test.tsx` passed, 2 files / 7 tests.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 130 test files / 418 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Ten-Round Self-Audit

- Cycle counter: 10 / 10.
- Mainline status:
  - no drift from frontend engineering scope,
  - mapper size remains actively controlled,
  - `useSentinel()` public shape remains stable,
  - MISC remains independent from unified Evidence,
  - no backend API shape changes,
  - no sample PCAP, generated build output, release binary, or ignored docs archive staged,
  - `pnpm` remains the only frontend package manager path,
  - full frontend/backend gates remain green.
- Current structural risks after ten rounds:
  - `SentinelContext.tsx` remains large at 828 lines and is still the primary state-risk target,
  - `vshellDecryptDisplayRules.ts` and `mediaMapper.ts` are the next mapper/rule files to watch,
  - `sidebar.tsx` and core display rules remain later presentation/core boundaries.
- Next autonomous target: resume `SentinelContext` state extraction with a low-risk selected-packet or packet-page helper, unless mapper audit shows a higher-risk growth point.

---

## Round 85 - Selected Packet Action Hook Extraction

Time: 2026-05-11 04:55:34 +08:00  
Author: Codex

### Scope

- Extracted selected-packet action wiring from `SentinelContext.tsx` into `useSelectedPacketAction`.
- Kept the public `selectPacket(id)` behavior unchanged:
  - set selected packet id,
  - keep cached packet detail only when it matches the new selected id.
- Kept `useSentinel()` public shape unchanged and did not split public Context.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### State Size Check

- Reduced `SentinelContext.tsx` to 825 lines.
- Added:
  - `useSelectedPacketAction.ts` at 19 lines,
  - `useSelectedPacketAction.test.tsx` at 19 lines.
- Added size budgets for the new action hook and focused test.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/useSelectedPacketAction.test.tsx src/app/state/selectedPacketState.test.ts src/app/pages/AnalysisCockpit.test.tsx` passed, 3 files / 10 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 131 test files / 419 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 1 / 10.
- No drift detected:
  - selected packet behavior stayed state-compatible,
  - public `useSentinel()` contract stayed stable,
  - mapper file growth remained controlled after the USB split,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: continue low-risk `SentinelContext` extraction around packet page cancel/reset helpers or audit the next mapper/rule file if size pressure rises.

---

## Round 86 - Packet Page Cancellation Hook Extraction

Time: 2026-05-11 05:01:48 +08:00  
Author: Codex

### Scope

- Extracted packet-page cancellation wiring from `SentinelContext.tsx` into `usePacketPageCancellation`.
- Kept cancellation behavior unchanged:
  - bump packet page request sequence,
  - abort the active `packet-page` capture task,
  - clear page loading state.
- Kept `useSentinel()` public shape unchanged and did not split public Context.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### State Size Check

- `SentinelContext.tsx` is 826 lines after extraction.
- Added:
  - `usePacketPageCancellation.ts` at 18 lines,
  - `usePacketPageCancellation.test.tsx` at 27 lines.
- Added size budgets for the new cancellation hook and focused test.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/usePacketPageCancellation.test.tsx src/app/state/captureTaskReset.test.ts src/app/pages/AnalysisCockpit.test.tsx` passed, 3 files / 5 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- First `cd frontend && pnpm run ci` had a transient timeout in `MiscTools.sessions.test.tsx` MySQL case; focused rerun of that case passed.
- Second `cd frontend && pnpm run ci` passed, 132 test files / 420 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 2 / 10.
- No drift detected:
  - packet cancellation behavior stayed state-compatible,
  - public `useSentinel()` contract stayed stable,
  - mapper file growth remained controlled,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green after rerun,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: inspect `SentinelContext` for another safe packet-state extraction, or pivot to a mapper/rule file if the state extraction would become too coupled.

---

## Round 87 - Media Mapper Boundary Split

Time: 2026-05-11 05:09:46 +08:00  
Author: Codex

### Scope

- Split `mediaMapper.ts` from a broad media conversion file into a thin composition layer.
- Moved media session/artifact conversion into `mediaSessionMapper.ts`.
- Moved transcription conversion into `mediaTranscriptionMapper.ts`.
- Moved speech batch queue status conversion into `speechBatchMapper.ts`.
- Preserved existing public imports by re-exporting `asMediaTranscription` and `asSpeechBatchTaskStatus` from `mediaMapper.ts`.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### Mapper Size Check

- `mediaMapper.ts` is now 14 lines and acts only as media analysis composition.
- `mediaSessionMapper.ts` is 36 lines.
- `mediaTranscriptionMapper.ts` is 22 lines.
- `speechBatchMapper.ts` is 28 lines.
- Added explicit size budgets for all four mapper files so future media mapper growth is caught early.

### Validation

- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 132 test files / 420 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 3 / 10.
- No drift detected:
  - mapper file size stayed under explicit budgets,
  - facade export compatibility stayed intact,
  - no business behavior or transport contract changed,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: continue mapper-size pressure audit, then prefer the next small state/rule extraction only if it has a clean test seam.

---

## Round 88 - Vehicle Diagnostic Mapper Split

Time: 2026-05-11 05:14:16 +08:00  
Author: Codex

### Scope

- Split `vehicleDiagnosticMapper.ts` into protocol-specific mapper files:
  - `vehicleJ1939Mapper.ts`,
  - `vehicleDoipMapper.ts`,
  - `vehicleUdsMapper.ts`.
- Kept `vehicleDiagnosticMapper.ts` as a compatibility facade exporting the same section mappers.
- Preserved `vehicleMapper.ts` imports and public mapping shape.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### Mapper Size Check

- `vehicleDiagnosticMapper.ts` is now 3 lines.
- `vehicleJ1939Mapper.ts` is 23 lines.
- `vehicleDoipMapper.ts` is 27 lines.
- `vehicleUdsMapper.ts` is 49 lines.
- Replaced the old 110-line diagnostic mapper budget with tighter protocol-specific budgets.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/vehicleMapper.test.ts src/app/pages/VehicleAnalysis.test.ts` passed, 2 files / 4 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 132 test files / 420 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 4 / 10.
- No drift detected:
  - mapper split stayed under explicit budgets,
  - vehicle analysis model mapping stayed compatible,
  - no business behavior or transport contract changed,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: inspect remaining mapper and state files; continue only where there is a small compatibility facade or clean test seam.

---

## Round 89 - Progress Status Updater Hook Extraction

Time: 2026-05-11 05:17:46 +08:00  
Author: Codex

### Scope

- Extracted progress-status provider wiring from `SentinelContext.tsx` into `useProgressStatusUpdater`.
- Kept the existing pure workflow `updateProgressFromStatusState` unchanged.
- Added focused hook coverage for capture progress, media progress, and threat progress message wiring.
- Kept `useSentinel()` public shape unchanged and did not split public Context.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### State Size Check

- `SentinelContext.tsx` is now 823 lines.
- Added:
  - `useProgressStatusUpdater.ts` at 22 lines,
  - `useProgressStatusUpdater.test.tsx` at 49 lines.
- Added size budgets for the new progress hook and focused test.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/useProgressStatusUpdater.test.tsx src/app/state/progressStatusWorkflow.test.ts src/app/pages/AnalysisCockpit.test.tsx` passed, 3 files / 10 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 133 test files / 421 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 5 / 10.
- No drift detected:
  - progress parsing remains in the pure workflow,
  - provider only lost glue code,
  - public `useSentinel()` contract stayed stable,
  - mapper budgets remain enforced,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: continue with another small state hook only if it reduces provider glue without moving business behavior; otherwise pivot to remaining mapper budget pressure.

---

## Round 90 - Scheduled Packet Page Load Hook Extraction

Time: 2026-05-11 05:21:33 +08:00  
Author: Codex

### Scope

- Extracted delayed packet-page load scheduling from `SentinelContext.tsx` into `useScheduledPacketPageLoad`.
- Kept behavior unchanged:
  - only one pending scheduled load at a time,
  - scheduled callback reads the latest `pageStartRef.current`,
  - scheduled marker is cleared before invoking `loadPacketPage`.
- Added focused hook coverage for timer de-duplication and cursor handoff.
- Kept `useSentinel()` public shape unchanged and did not split public Context.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### State Size Check

- `SentinelContext.tsx` is now 815 lines.
- Added:
  - `useScheduledPacketPageLoad.ts` at 22 lines,
  - `useScheduledPacketPageLoad.test.tsx` at 30 lines.
- Added size budgets for the new scheduling hook and focused test.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/useScheduledPacketPageLoad.test.tsx src/app/state/packetPageLoad.test.ts src/app/pages/AnalysisCockpit.test.tsx` passed, 3 files / 8 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 134 test files / 422 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 6 / 10.
- No drift detected:
  - packet-page scheduling behavior stayed state-compatible,
  - public `useSentinel()` contract stayed stable,
  - mapper budgets remain enforced,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: continue state-provider glue extraction toward the sub-800-line target, but avoid moving capture transaction behavior without stronger test coverage.

---

## Round 91 - Stream Index Refresh Hook Extraction

Time: 2026-05-11 05:25:30 +08:00  
Author: Codex

### Scope

- Extracted stream-index refresh provider wiring from `SentinelContext.tsx` into `useStreamIndexRefresh`.
- Kept the pure workflow `refreshStreamIndexState` unchanged.
- Added focused hook coverage for HTTP/TCP/UDP stream ID loading through the pure workflow.
- Kept `useSentinel()` public shape unchanged and did not split public Context.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### State Size Check

- `SentinelContext.tsx` is now 813 lines.
- Added:
  - `useStreamIndexRefresh.ts` at 18 lines,
  - `useStreamIndexRefresh.test.tsx` at 36 lines.
- Added size budgets for the new stream-index hook and focused test.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/useStreamIndexRefresh.test.tsx src/app/state/streamIndexRefresh.test.ts src/app/state/streamSwitchWorkflow.test.ts src/app/pages/AnalysisCockpit.test.tsx` passed, 4 files / 12 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 135 test files / 423 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 7 / 10.
- No drift detected:
  - stream-index logic remains in the pure workflow,
  - provider only lost glue code,
  - public `useSentinel()` contract stayed stable,
  - mapper budgets remain enforced,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: continue toward sub-800 `SentinelContext.tsx`, prioritizing glue-only hooks over transaction-heavy capture behavior.

---

## Round 92 - Stream Payload Persistence Hook Extraction

Time: 2026-05-11 05:31:37 +08:00  
Author: Codex

### Scope

- Extracted stream-payload persistence provider wiring from `SentinelContext.tsx` into `useStreamPayloadPersistence`.
- Kept the pure workflow `persistStreamPayloadsState` unchanged.
- Added focused hook coverage for backend persistence and active HTTP-stream patching through the pure workflow.
- Kept `useSentinel()` public shape unchanged and did not split public Context.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### State Size Check

- `SentinelContext.tsx` is now 804 lines.
- Added:
  - `useStreamPayloadPersistence.ts` at 39 lines,
  - `useStreamPayloadPersistence.test.tsx` at 39 lines.
- Added size budgets for the new stream-payload persistence hook and focused test.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/useStreamPayloadPersistence.test.tsx src/app/state/streamPayloadPersist.test.ts src/app/pages/AnalysisCockpit.test.tsx` passed, 3 files / 6 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 136 test files / 424 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 8 / 10.
- No drift detected:
  - stream-payload logic remains in the pure workflow,
  - provider only lost glue code,
  - public `useSentinel()` contract stayed stable,
  - mapper budgets remain enforced,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: one more low-risk provider glue extraction to push `SentinelContext.tsx` below 800 lines before the next 10-round self-audit.

---

## Round 93 - Analysis Refresh Hook Extraction

Time: 2026-05-11 05:36:43 +08:00  
Author: Codex

### Scope

- Extracted analysis refresh provider wiring from `SentinelContext.tsx` into `useRefreshAnalysisResult`.
- Kept `useAnalysisProgress` and the underlying refresh implementation unchanged.
- Added focused hook coverage for current capture path, capture task scope, backend connectivity, and backend status setter handoff.
- Kept `useSentinel()` public shape unchanged and did not split public Context.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### State Size Check

- `SentinelContext.tsx` is now 800 lines.
- Added:
  - `useRefreshAnalysisResult.ts` at 31 lines,
  - `useRefreshAnalysisResult.test.tsx` at 33 lines.
- Added size budgets for the new analysis refresh hook and focused test.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/useRefreshAnalysisResult.test.tsx src/app/pages/AnalysisCockpit.test.tsx` passed, 2 files / 3 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 137 test files / 425 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 9 / 10.
- No drift detected:
  - analysis refresh behavior remains delegated to the existing progress hook implementation,
  - provider only lost glue code,
  - public `useSentinel()` contract stayed stable,
  - mapper budgets remain enforced,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: perform the 10-round self-audit after one more bounded engineering round, then decide whether to keep shaving provider glue or switch to sidebar/core budgets.

---

## Round 94 - Packet Page Commit Hook Extraction

Time: 2026-05-11 05:42:16 +08:00  
Author: Codex

### Scope

- Extracted packet-page commit provider wiring from `SentinelContext.tsx` into `usePacketPageCommit`.
- Kept the pure workflow `commitPacketPageState` unchanged.
- Added focused hook coverage for page cursor, packet rows, selected packet, raw/layer reset, previous/next flags, and page error reset.
- Kept `useSentinel()` public shape unchanged and did not split public Context.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### State Size Check

- `SentinelContext.tsx` is now 793 lines.
- Added:
  - `usePacketPageCommit.ts` at 40 lines,
  - `usePacketPageCommit.test.tsx` at 82 lines.
- Added size budgets for the new packet-page commit hook and focused test.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/usePacketPageCommit.test.tsx src/app/state/packetPageCommit.test.ts src/app/state/packetPageLoad.test.ts src/app/pages/AnalysisCockpit.test.tsx` passed, 4 files / 10 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- First `cd frontend && pnpm run ci` failed only on scoped Prettier formatting for `scripts/check-size.mjs`; after `pnpm exec prettier --write ...`, rerun passed.
- `cd frontend && pnpm run ci` passed, 138 test files / 426 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### 10-Round Self Audit

- Audit window: recent 10 engineering commits ending with this round.
- Work stayed on the approved engineering axis:
  - mapper-size control continued through USB, media, and vehicle mapper splits,
  - `SentinelContext.tsx` state glue was extracted through selected packet action, packet-page cancellation, progress status, packet-page scheduler, stream-index refresh, stream-payload persistence, analysis refresh, and packet-page commit hooks,
  - public `useSentinel()` shape stayed stable,
  - backend API and frontend response models stayed unchanged,
  - MISC remained an independent workbench and was not wired into unified Evidence,
  - no PCAP/sample/build artifact was staged,
  - size budgets and CI gates stayed enforced.
- Drift risk: low. The work has shifted correctly from mechanical page split to state ownership and mapper boundary control.
- Remaining risk: `SentinelContext.tsx` is below the 800-line milestone but still owns multiple domains; next work should continue hook extraction only where workflow tests already exist or can be added cheaply.
- Next cycle counter resets to 0 / 10 after this round.

### Review

- Current cycle counter: 10 / 10, self-audit completed.
- No drift detected.
- Next autonomous target: continue small provider glue extraction, likely `preparePacketStream`, then reassess whether to move to sidebar/core budgets.

---

## Round 95 - Prepare Packet Stream Hook Extraction

Time: 2026-05-11 05:45:56 +08:00  
Author: Codex

### Scope

- Extracted packet-stream preparation provider wiring from `SentinelContext.tsx` into `usePreparePacketStream`.
- Kept the pure workflow `preparePacketStreamState` unchanged.
- Added focused hook coverage for packet lookup, preferred protocol handoff, filter handoff, and active stream activation.
- Kept `useSentinel()` public shape unchanged and did not split public Context.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### State Size Check

- `SentinelContext.tsx` is now 781 lines.
- Added:
  - `usePreparePacketStream.ts` at 27 lines,
  - `usePreparePacketStream.test.tsx` at 21 lines.
- Added size budgets for the new packet-stream preparation hook and focused test.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/usePreparePacketStream.test.tsx src/app/state/packetStreamPrepare.test.ts src/app/pages/AnalysisCockpit.test.tsx` passed, 3 files / 6 tests.
- `cd frontend && pnpm run size:check` passed.
- First `cd frontend && pnpm run typecheck` / `pnpm run lint` found one stale unused `PreparedPacketStream` import; removed it and reran.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 139 test files / 427 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 1 / 10.
- No drift detected:
  - packet-stream preparation still delegates to the existing pure workflow,
  - provider only lost glue code,
  - public `useSentinel()` contract stayed stable,
  - mapper budgets remain enforced,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: continue low-risk state glue extraction only if a matching pure workflow/test exists; otherwise switch to sidebar/core budget work.

---

## Round 96 - Packet Viewport Reset Hook Extraction

Time: 2026-05-11 05:50:06 +08:00  
Author: Codex

### Scope

- Extracted packet viewport reset provider wiring from `SentinelContext.tsx` into `usePacketViewportReset`.
- Kept the pure workflow `resetPacketViewportState` unchanged.
- Added focused hook coverage for canceling in-flight packet-page loads and resetting packet list, pagination, selection, raw hex, layer data, and paging flags.
- Kept `useSentinel()` public shape unchanged and did not split public Context.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### State Size Check

- `SentinelContext.tsx` is now 779 lines.
- Added:
  - `usePacketViewportReset.ts` at 35 lines,
  - `usePacketViewportReset.test.tsx` at 67 lines.
- Added size budgets for the new packet viewport reset hook and focused test.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/usePacketViewportReset.test.tsx src/app/state/captureResetState.test.ts src/app/pages/AnalysisCockpit.test.tsx` passed, 3 files / 6 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- First `cd frontend && pnpm run ci` failed only on scoped Prettier formatting for `scripts/check-size.mjs`; after `pnpm exec prettier --write ...`, rerun passed.
- `cd frontend && pnpm run ci` passed, 140 test files / 428 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 2 / 10.
- No drift detected:
  - packet viewport reset still delegates to the existing pure workflow,
  - provider only lost glue code,
  - public `useSentinel()` contract stayed stable,
  - mapper budgets remain enforced,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: evaluate whether `loadPacketPage` or `locatePacketById` can be extracted without weakening cancellation/selection semantics; skip if coupling is too high.

---

## Round 97 - Packet Page Load Hook Extraction

Time: 2026-05-11 05:53:38 +08:00  
Author: Codex

### Scope

- Extracted packet-page load provider wiring from `SentinelContext.tsx` into `usePacketPageLoad`.
- Kept the pure workflow `loadPacketPageState` unchanged.
- Added focused hook coverage for cursor normalization, filter override handoff, backend page loading, commit callback, page loading state, filter loading completion, and status/error state stability.
- Kept `useSentinel()` public shape unchanged and did not split public Context.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### State Size Check

- `SentinelContext.tsx` is now 772 lines.
- Added:
  - `usePacketPageLoad.ts` at 47 lines,
  - `usePacketPageLoad.test.tsx` at 48 lines.
- Added size budgets for the new packet-page load hook and focused test.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/usePacketPageLoad.test.tsx src/app/state/packetPageLoad.test.ts src/app/pages/AnalysisCockpit.test.tsx` passed, 3 files / 8 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 141 test files / 429 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 3 / 10.
- No drift detected:
  - packet-page loading still delegates to the existing pure workflow,
  - provider only lost glue code,
  - public `useSentinel()` contract stayed stable,
  - mapper budgets remain enforced,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: evaluate `locatePacketById` extraction, but preserve packet selection and display-filter handoff semantics.

---

## Round 98 - Packet Locate Hook Extraction

Time: 2026-05-11 05:57:41 +08:00  
Author: Codex

### Scope

- Extracted packet locate provider wiring from `SentinelContext.tsx` into `usePacketLocateById`.
- Kept the pure workflow `locatePacketByIdWorkflow` unchanged.
- Added focused hook coverage for filter override handoff, page loading, display filter update, selected packet update, and quiet backend status path.
- Kept `useSentinel()` public shape unchanged and did not split public Context.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### State Size Check

- `SentinelContext.tsx` is now 765 lines.
- Added:
  - `usePacketLocateById.ts` at 41 lines,
  - `usePacketLocateById.test.tsx` at 45 lines.
- Added size budgets for the new packet locate hook and focused test.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/usePacketLocateById.test.tsx src/app/state/packetLocateWorkflow.test.ts src/app/pages/AnalysisCockpit.test.tsx` passed, 3 files / 9 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- First `cd frontend && pnpm run ci` failed only on scoped Prettier formatting for `scripts/check-size.mjs`; after `pnpm exec prettier --write ...`, rerun passed.
- `cd frontend && pnpm run ci` passed, 142 test files / 430 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 4 / 10.
- No drift detected:
  - packet locate behavior still delegates to the existing pure workflow,
  - provider only lost glue code,
  - public `useSentinel()` contract stayed stable,
  - mapper budgets remain enforced,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: decide whether to continue packet navigation helper hooks (`loadMorePackets`, `loadPrevPackets`, `jumpToPage`, `retryPacketPage`) or switch to `prefetchAdjacentStreams` / sidebar/core if provider extraction becomes too granular.

---

## Round 99 - Packet Page Navigation Hook Extraction

Time: 2026-05-11 06:03:54 +08:00  
Author: Codex

### Scope

- Extracted packet page navigation provider wiring from `SentinelContext.tsx` into `usePacketPageNavigation`.
- Kept pure workflows in `packetPageNavigation.ts` unchanged.
- Covered `loadMorePackets`, `loadPrevPackets`, `jumpToPage`, and `retryPacketPage` provider wiring in a focused hook test.
- Kept `useSentinel()` public shape unchanged and did not split public Context.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### State Size Check

- `SentinelContext.tsx` is now 753 lines.
- Added:
  - `usePacketPageNavigation.ts` at 35 lines,
  - `usePacketPageNavigation.test.tsx` at 33 lines.
- Added size budgets for the new packet page navigation hook and focused test.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/usePacketPageNavigation.test.tsx src/app/state/packetPageNavigation.test.ts src/app/pages/AnalysisCockpit.test.tsx` passed, 3 files / 7 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 143 test files / 431 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 5 / 10.
- No drift detected:
  - packet navigation behavior still delegates to existing pure workflows,
  - provider only lost glue code,
  - public `useSentinel()` contract stayed stable,
  - mapper budgets remain enforced,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: evaluate a slightly larger but still bounded state hook such as adjacent stream prefetch or clear-capture UI state; avoid over-splitting one-line provider wrappers.

---

## Round 100 - Stream Adjacent Prefetch Hook Extraction

Time: 2026-05-11 06:10:36 +08:00  
Author: Codex

### Scope

- Extracted adjacent stream prefetch provider wiring from `SentinelContext.tsx` into `useStreamAdjacentPrefetch`.
- Kept pure prefetch rules in `streamAdjacentPrefetch.ts`, `streamPrefetchPlan.ts`, `streamPrefetchTask.ts`, and `streamPrefetchScheduler.ts` unchanged.
- Added focused hook coverage for provider refs, capture task scope, stream caches, and bridge fetcher wiring.
- Kept production prefetch behavior unchanged by passing the existing `STREAM_PREFETCH_LIMIT` from provider into the hook.
- Kept `useSentinel()` public shape unchanged and did not split public Context.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### State Size Check

- `SentinelContext.tsx` is now 744 lines.
- Added:
  - `useStreamAdjacentPrefetch.ts` at 77 lines,
  - `useStreamAdjacentPrefetch.test.tsx` at 52 lines.
- Added size budgets for the new adjacent stream prefetch hook and focused test.

### Validation

- First focused run exposed an incorrect test assumption: production `STREAM_PREFETCH_LIMIT` is `0`, so provider default scheduling remains disabled. The hook now accepts an explicit `prefetchLimit`, with provider passing the existing constant and tests using `2` to verify wiring.
- `cd frontend && pnpm exec vitest run src/app/state/hooks/useStreamAdjacentPrefetch.test.tsx src/app/state/streamAdjacentPrefetch.test.ts src/app/state/streamPrefetchPlan.test.ts src/app/state/streamPrefetchTask.test.ts src/app/state/streamPrefetchScheduler.test.ts src/app/pages/AnalysisCockpit.test.tsx` passed, 6 files / 16 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 144 test files / 432 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 6 / 10.
- No drift detected:
  - adjacent stream prefetch still delegates to existing pure workflows,
  - production prefetch limit stayed unchanged,
  - provider only lost glue code,
  - public `useSentinel()` contract stayed stable,
  - mapper budgets remain enforced,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: consider stream switch hook extraction only if it can stay bounded; otherwise switch to `clearCaptureUiState` or sidebar/core budget work.

---

## Round 101 - Active Stream Switch Hook Extraction

Time: 2026-05-11 06:18:03 +08:00  
Author: Codex

### Scope

- Extracted active stream switch provider wiring from `SentinelContext.tsx` into `useActiveStreamSwitch`.
- Kept pure switch workflow in `streamSwitchWorkflow.ts` unchanged.
- Added focused hook coverage for provider stream caches, stream setters, switch metrics, prefetch callback, backend status, and bridge fetcher wiring.
- Kept `useSentinel()` public shape unchanged and did not split public Context.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### State Size Check

- `SentinelContext.tsx` is now 727 lines.
- Added:
  - `useActiveStreamSwitch.ts` at 89 lines,
  - `useActiveStreamSwitch.test.tsx` at 60 lines.
- Added size budgets for the active stream switch hook and focused test.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/useActiveStreamSwitch.test.tsx src/app/state/streamSwitchWorkflow.test.ts src/app/state/streamSwitchCache.test.ts src/app/state/streamSwitchCommit.test.ts src/app/state/streamSwitchTask.test.ts src/app/pages/AnalysisCockpit.test.tsx` passed, 6 files / 14 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 145 test files / 433 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 7 / 10.
- No drift detected:
  - stream switching still delegates to existing pure workflow,
  - provider only lost glue code,
  - public `useSentinel()` contract stayed stable,
  - mapper budgets remain enforced,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: avoid further tiny stream hook churn; evaluate `clearCaptureUiState` hook extraction or switch to sidebar/core budget work.

---

## Round 102 - Vehicle CAN Mapper Split

Time: 2026-05-11 06:25:34 +08:00  
Author: Codex

### Scope

- Audited mapper file sizes before continuing state work.
- Rejected a `clearCaptureUiState` hook extraction attempt because it only moved a long parameter list and did not improve ownership.
- Split `vehicleCanMapper.ts` into:
  - `vehicleCanRecordMapper.ts` for CAN payload records and frame summaries,
  - `vehicleCanDbcMapper.ts` for DBC profiles, decoded messages, and signal timelines,
  - a thin `vehicleCanMapper.ts` composition layer.
- Kept vehicle mapping output shape unchanged.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### Mapper Size Check

- `vehicleCanMapper.ts` dropped from 92 lines to 21 lines.
- Added:
  - `vehicleCanRecordMapper.ts` at 33 lines,
  - `vehicleCanDbcMapper.ts` at 42 lines.
- Tightened the `vehicleCanMapper.ts` size budget from 105 lines to 35 lines.
- Added size budgets for the two new CAN mapper files.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/vehicleMapper.test.ts` passed, 1 file / 2 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 145 test files / 433 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 8 / 10.
- No drift detected:
  - mapper-size concern was handled directly,
  - vehicle CAN output shape stayed stable,
  - public `useSentinel()` contract stayed stable,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: continue mapper budget audit, especially high-line mapper tests or remaining mapper source files, before returning to high-risk state extraction.

---

## Round 103 - Runtime Speech Mapper Dedupe

Time: 2026-05-11 06:32:22 +08:00  
Author: Codex

### Scope

- Removed duplicated `asSpeechBatchTaskStatus` implementation from `runtimeMapper.ts`.
- Kept `speechBatchMapper.ts` as the single owner for speech batch task status conversion.
- Preserved compatibility by re-exporting `asSpeechBatchTaskStatus` from `runtimeMapper.ts`.
- Kept `asToolRuntimeSnapshot` local to `runtimeMapper.ts`.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### Mapper Size Check

- `runtimeMapper.ts` dropped from 81 lines to 55 lines.
- Added a `runtimeMapper.ts` size budget at 65 lines.
- No mapper output shape changed.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/runtimeMapper.test.ts src/app/integrations/mappers/mediaMapper.test.ts` passed, 2 files / 6 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 145 test files / 433 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 9 / 10.
- No drift detected:
  - speech batch mapper now has one source of truth,
  - runtime mapper remains focused on tool runtime snapshot conversion,
  - public mapper import compatibility stayed stable,
  - public `useSentinel()` contract stayed stable,
  - MISC stayed independent from unified Evidence,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: perform one more bounded mapper/core/sidebar cleanup, then complete the 10-round self-audit and reset the cycle counter.

---

## Round 104 - Modbus Mapper Boundary Split and 10-Round Audit

Time: 2026-05-11 06:38:32 +08:00  
Author: Codex

### Scope

- Split `modbusMapper.ts` into focused Modbus detail mappers:
  - `modbusDecodedInputMapper.ts` owns decoded UTF-8/text input conversion,
  - `modbusTransactionMapper.ts` owns transaction and bit-range conversion,
  - `modbusSuspiciousWriteMapper.ts` owns suspicious write summary conversion,
  - `modbusMapper.ts` remains the summary composition layer and compatibility export point.
- Kept `asModbusSuspiciousWrites` import compatibility by re-exporting from `modbusMapper.ts`.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### Mapper Size Check

- `modbusMapper.ts` dropped from 81 lines to 19 lines.
- Added focused mapper files:
  - `modbusDecodedInputMapper.ts` at 20 lines,
  - `modbusTransactionMapper.ts` at 35 lines,
  - `modbusSuspiciousWriteMapper.ts` at 19 lines.
- Tightened `modbusMapper.ts` size budget from 110 lines to 30 lines.
- Added budgets for all new Modbus detail mappers.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/industrialMapper.test.ts` passed, 1 file / 2 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 145 test files / 433 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### 10-Round Self-Audit

- Current cycle counter reached 10 / 10; reset to 0 / 10 after this audit.
- Mainline drift check passed:
  - MISC stayed independent from unified Evidence; no new Evidence routing for MISC tools.
  - `useSentinel()` public shape stayed stable; no public Context split was attempted.
  - Backend APIs and frontend model shapes stayed stable.
  - `package-lock.json` is still absent; pnpm remains the only frontend package manager.
  - Mapper files now have tighter budgets and no known unbudgeted growth path from this round.
  - Docs archive remains ignored locally and was not staged.
  - Ignored samples, PCAPs, build outputs, release executables, and `frontend/dist` remain unstaged.
- Remaining engineering risks:
  - `vshellDecryptDisplayRules.ts` remains security-sensitive and should only be split with strong tests.
  - Large mapper tests are acceptable for now but may need fixture helpers later if test growth becomes noisy.
  - Next higher-value structural targets remain sidebar primitive split or core rule extraction, not further tiny wrapper hooks.

### Next Target

- Start a fresh 10-round cycle.
- Prefer a bounded sidebar primitive or core display-rule extraction round unless mapper audit reveals a clear ownership issue.

---

## Round 105 - Sidebar Structure Primitive Split

Time: 2026-05-11 06:43:12 +08:00  
Author: Codex

### Scope

- Moved sidebar structural primitives out of `sidebar.tsx` into `sidebarStructure.tsx`:
  - content,
  - header/footer,
  - input,
  - separator,
  - group, group label, group action, group content.
- Kept `sidebar.tsx` as the public compatibility export surface plus shell/trigger/rail/inset implementation.
- Preserved all existing imports from `components/ui/sidebar`.
- Did not add feature-specific logic to UI primitives.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, public model shapes, or visible UI behavior.

### Size Check

- `sidebar.tsx` dropped from 311 lines to 206 lines.
- Added `sidebarStructure.tsx` at 129 lines.
- Tightened `sidebar.tsx` size budget from 360 lines to 230 lines.
- Added a `sidebarStructure.tsx` budget at 145 lines.

### Validation

- `cd frontend && pnpm exec vitest run src/app/layouts/MainLayout.test.ts src/app/components/RuntimeSettingsSidebarParts.test.tsx` passed, 2 files / 8 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 145 test files / 433 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 1 / 10.
- No drift detected:
  - sidebar split stayed within UI primitive boundary,
  - public imports stayed compatible,
  - MISC stayed independent from unified Evidence,
  - `useSentinel()` public contract stayed stable,
  - quality gates remain green,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: continue a bounded primitive/core split, likely sidebar menu/action helpers or protocol core rules, depending on ownership clarity.

---

## Round 106 - Sidebar Menu Primitive Split

Time: 2026-05-11 06:47:05 +08:00  
Author: Codex

### Scope

- Split `sidebarMenu.tsx` into focused UI primitive modules:
  - `sidebarMenuButtons.tsx` owns menu button, sub-button, variants, and collapsed tooltip behavior,
  - `sidebarMenuAccessories.tsx` owns menu action, badge, and skeleton primitives,
  - `sidebarMenu.tsx` remains the public shell for list, item, sub-list, and compatibility exports.
- Preserved all existing imports from `components/ui/sidebar` and `components/ui/sidebarMenu`.
- Kept this as pure UI primitive work; no feature or domain logic was introduced.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, public model shapes, or visible UI behavior.

### Size Check

- `sidebarMenu.tsx` dropped from 225 lines to 55 lines.
- Added:
  - `sidebarMenuButtons.tsx` at 99 lines,
  - `sidebarMenuAccessories.tsx` at 77 lines.
- Tightened `sidebarMenu.tsx` size budget from 250 lines to 70 lines.
- Added size budgets for the two new sidebar menu primitive files.

### Validation

- `cd frontend && pnpm exec vitest run src/app/layouts/MainLayout.test.ts src/app/components/RuntimeSettingsSidebarParts.test.tsx` passed, 2 files / 8 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 145 test files / 433 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 2 / 10.
- No drift detected:
  - UI primitive split preserved compatibility exports,
  - MISC stayed independent from unified Evidence,
  - `useSentinel()` public contract stayed stable,
  - package manager and CI gates stayed unchanged,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: move from sidebar primitive cleanup to a small core-rule or protocol display boundary if ownership is clear.

---

## Round 107 - Protocol Layer Summary Rule Split

Time: 2026-05-11 06:52:08 +08:00  
Author: Codex

### Scope

- Split protocol layer summary rules out of `protocolLayerTree.ts` into `protocolLayerSummary.ts`.
- Kept `protocolLayerTree.ts` focused on tree recursion, layer ordering, field ordering, and byte-range assignment.
- Kept `protocolLayerSummary.ts` as a pure rule module for layer titles, frame/IP/TCP/UDP/HTTP/IGMP summaries, layer normalization, and candidate field picking.
- Preserved `engine.ts` compatibility exports and all visible protocol tree output.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### Size Check

- `protocolLayerTree.ts` dropped from 289 lines to 219 lines.
- Added `protocolLayerSummary.ts` at 73 lines.
- Tightened `protocolLayerTree.ts` size budget from 320 lines to 250 lines.
- Added a `protocolLayerSummary.ts` budget at 90 lines.

### Validation

- First focused test run exposed a missed local dependency after extraction:
  - `pickLayerValue is not defined` in `extractLayerOrder`,
  - missing `layerTitle` import for primitive layer labels,
  - initial tree budget was too tight for the remaining ordering logic.
- Fixed by exporting `pickLayerValue`, restoring `layerTitle` import, and setting the tree budget to the current split boundary.
- `cd frontend && pnpm exec vitest run src/app/core/engine.test.ts src/app/core/captureOverview.test.ts` passed, 2 files / 4 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 145 test files / 433 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 3 / 10.
- No drift detected:
  - core split remained pure and UI-free,
  - protocol display output stayed covered by existing tests,
  - MISC stayed independent from unified Evidence,
  - `useSentinel()` public contract stayed stable,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: either extract protocol layer ordering into a pure helper if useful, or move to another bounded core/display rule with clearer ownership.
---

## Round 108 - Protocol Layer Ordering Rule Split

Time: 2026-05-11 06:56:48 +08:00  
Author: Codex

### Scope

- Split protocol layer ordering rules out of `protocolLayerTree.ts` into `protocolLayerOrdering.ts`.
- Kept `protocolLayerTree.ts` focused on layer tree recursion, field tree construction, and byte-range assignment.
- Kept ordering logic pure:
  - layer ordering via frame protocol hints,
  - hidden layer filtering,
  - field ordering by semantic weight and stable label fallback.
- Preserved `engine.ts` compatibility exports and all visible protocol tree output.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, UI behavior, or public model shapes.

### Size Check

- `protocolLayerTree.ts` dropped from 219 lines to 142 lines.
- Added `protocolLayerOrdering.ts` at 73 lines.
- Tightened `protocolLayerTree.ts` size budget from 250 lines to 170 lines.
- Added a `protocolLayerOrdering.ts` budget at 90 lines.

### Validation

- `cd frontend && pnpm exec vitest run src/app/core/engine.test.ts src/app/core/captureOverview.test.ts` passed, 2 files / 4 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 145 test files / 433 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 4 / 10.
- No drift detected:
  - core split remained pure and UI-free,
  - protocol display output stayed covered by existing tests,
  - MISC stayed independent from unified Evidence,
  - `useSentinel()` public contract stayed stable,
  - package manager and CI gates stayed unchanged,
  - docs archive remains ignored locally and was not staged.
- Next autonomous target: choose a bounded core/display rule or presentation split with clear ownership; avoid tiny wrapper-only state extractions.
---

## Round 109 - Raw Stream Payload Panel Split

Time: 2026-05-11 07:01:51 +08:00  
Author: Codex

### Scope

- Split raw TCP/UDP payload rendering out of `RawStreamSections.tsx` into `RawStreamPayloadPanels.tsx`.
- Kept `RawStreamSections.tsx` as the shared title bar and compatibility export surface for TCP/UDP stream pages.
- Moved chunk grid, selected chunk panel, direction badge, load-more control, and TCP/UDP tone constants into the payload panel module.
- Preserved imports from `./RawStreamSections` for `TcpStream.tsx` and `UdpStream.tsx`; no call sites changed.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, public model shapes, stream loading behavior, or MISC/Evidence boundaries.

### Size Check

- `RawStreamSections.tsx` dropped from 254 lines to 57 lines.
- Added `RawStreamPayloadPanels.tsx` at 201 lines.
- Tightened `RawStreamSections.tsx` size budget from 285 lines to 80 lines.
- Added a `RawStreamPayloadPanels.tsx` budget at 215 lines.

### Validation

- `cd frontend && pnpm exec vitest run src/app/pages/RawStreamUtils.test.ts src/app/state/streamSwitchWorkflow.test.ts src/app/state/streamAdjacentPrefetch.test.ts` passed, 3 files / 13 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 145 test files / 433 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 5 / 10.
- No drift detected:
  - change stayed in presentation split scope,
  - compatibility exports preserved TCP/UDP page imports,
  - mapper files were inspected and left unchanged because current mapper budgets remain controlled,
  - MISC stayed independent from unified Evidence,
  - `useSentinel()` public contract stayed stable,
  - ignored docs/samples/build outputs remained unstaged.
- Next autonomous target: choose another bounded presentation/core boundary with clear ownership; avoid changing state ownership unless tests justify it.
---

## Round 110 - Shared Raw Stream Page

Time: 2026-05-11 07:05:49 +08:00  
Author: Codex

### Scope

- Consolidated duplicated TCP/UDP raw stream page orchestration into `RawStreamPage.tsx`.
- Reduced `TcpStream.tsx` and `UdpStream.tsx` to protocol-specific route wrappers.
- Preserved protocol differences through explicit config inside the shared page:
  - TCP keeps scroll-near-bottom pagination and viewport reset,
  - UDP keeps manual load behavior and sticky selected payload panel.
- Kept raw stream sections, payload panels, control bar, dialog, and utility modules unchanged in public shape.
- Did not change backend APIs, request/response shapes, samples, PCAP fixtures, MISC/Evidence boundaries, or `useSentinel()` public contract.

### Size Check

- `TcpStream.tsx` dropped from 243 lines to 4 lines.
- `UdpStream.tsx` dropped from 237 lines to 4 lines.
- Added `RawStreamPage.tsx` at 266 lines.
- Tightened route file budgets from 280/270 lines to 20 lines each.
- Added `RawStreamPage.tsx` budget at 285 lines.

### Validation

- `cd frontend && pnpm exec vitest run src/app/pages/RawStreamUtils.test.ts src/app/state/streamSwitchWorkflow.test.ts src/app/state/streamAdjacentPrefetch.test.ts` passed, 3 files / 13 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 145 test files / 433 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 6 / 10.
- No drift detected:
  - shared route work reduced duplication without changing stream behavior,
  - route wrappers now enforce thin page boundary,
  - MISC stayed independent from unified Evidence,
  - mapper files were not enlarged,
  - package manager and CI gates stayed unchanged,
  - ignored docs/samples/build outputs remained unstaged.
- Next autonomous target: continue with a bounded page/presentation split or pure display-rule split; do not move raw stream logic again unless `RawStreamPage.tsx` starts growing.
---

## Round 111 - Industrial Auxiliary Panel Split

Time: 2026-05-11 07:10:23 +08:00  
Author: Codex

### Scope

- Split industrial auxiliary tables out of `IndustrialAnalysis.tsx` into `IndustrialAuxiliaryPanels.tsx`.
- Moved rule hit rendering, cross-protocol control command rendering, protocol detail summaries, and the industrial rule level tone helper into the feature module.
- Kept `IndustrialAnalysis.tsx` focused on capture state, analysis loading, summary cards, protocol buckets, notes, and Modbus filter orchestration.
- Preserved Modbus decoded input display and existing `IndustrialModbusPanels` composition.
- Did not change backend APIs, request/response shapes, sample handling, UI behavior, public model shapes, MISC/Evidence boundaries, or mapper logic.

### Size Check

- `IndustrialAnalysis.tsx` dropped from 251 lines to 141 lines.
- Added `IndustrialAuxiliaryPanels.tsx` at 141 lines.
- Tightened `IndustrialAnalysis.tsx` size budget from 310 lines to 170 lines.
- Added `IndustrialAuxiliaryPanels.tsx` budget at 180 lines.

### Validation

- `cd frontend && pnpm exec vitest run src/app/pages/IndustrialAnalysis.test.tsx src/app/integrations/mappers/industrialMapper.test.ts` passed, 2 files / 3 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 145 test files / 433 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 7 / 10.
- No drift detected:
  - industrial page became thinner without moving backend or mapper behavior,
  - Modbus UTF-8 decoded input acceptance path stayed covered,
  - mapper file sizes stayed unchanged,
  - MISC stayed independent from unified Evidence,
  - `useSentinel()` public contract stayed stable,
  - ignored docs/samples/build outputs remained unstaged.
- Next autonomous target: inspect `Workspace.tsx` or `ThreatHuntingWorkbenchSections.tsx`; choose only if there is a real ownership boundary.
---

## Round 112 - Threat Hunting Workbench Section Split

Time: 2026-05-11 07:14:28 +08:00  
Author: Codex

### Scope

- Split `ThreatHuntingWorkbenchSections.tsx` into separate feature presentation modules:
  - `ThreatHuntingConfigPanel.tsx` for prefix/YARA runtime config form,
  - `ThreatHuntingResultPanels.tsx` for hit table, selected hit detail, and threat-level tone rules.
- Kept `ThreatHuntingWorkbenchSections.tsx` as a compatibility export surface for existing `ThreatHuntingPanels.tsx` imports.
- Preserved threat hunting page behavior, runtime config requests, packet/stream navigation actions, and UI copy.
- Did not change backend APIs, request/response shapes, sample handling, public model shapes, mapper logic, MISC/Evidence boundaries, or `useSentinel()` public contract.

### Size Check

- `ThreatHuntingWorkbenchSections.tsx` dropped from 262 lines to 2 lines.
- Added:
  - `ThreatHuntingConfigPanel.tsx` at 131 lines,
  - `ThreatHuntingResultPanels.tsx` at 132 lines.
- Tightened `ThreatHuntingWorkbenchSections.tsx` size budget from 285 lines to 15 lines.
- Added budgets for the two new hunting presentation modules.

### Validation

- `cd frontend && pnpm exec vitest run src/app/pages/ThreatHunting.test.tsx src/app/layouts/MainLayout.test.ts` ran; there is no dedicated `ThreatHunting.test.tsx`, `MainLayout.test.ts` passed, 1 file / 4 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 145 test files / 433 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 8 / 10.
- No drift detected:
  - split stayed presentation-only,
  - existing compatibility import path remained intact,
  - mapper files were not enlarged,
  - MISC stayed independent from unified Evidence,
  - `useSentinel()` public contract stayed stable,
  - ignored docs/samples/build outputs remained unstaged.
- Next autonomous target: choose a bounded feature/presentation or pure-rule extraction; avoid adding new user-visible behavior before the 10-round audit.

---

## Round 113 - Media Playback Workflow Split

Time: 2026-05-11 07:20:59 +08:00  
Author: Codex

### Scope

- Split media playback and artifact download side effects out of `useMediaTranscriptionWorkflow.ts` into `useMediaPlaybackWorkflow.ts`.
- Split pure transcription helpers into `mediaTranscriptionRules.ts`.
- Kept `useMediaTranscriptionWorkflow.ts` as the public workflow hook and re-exported existing helper functions for test/import compatibility.
- Preserved speech readiness checks, single/batch transcription, polling, copy/export behavior, playback behavior, and dependency dialog semantics.
- Did not change backend APIs, request/response shapes, sample handling, public model shapes, mapper logic, MISC/Evidence boundaries, or `useSentinel()` public contract.

### Size Check

- `useMediaTranscriptionWorkflow.ts` dropped from 272 lines to 186 lines.
- Added:
  - `useMediaPlaybackWorkflow.ts` at 79 lines,
  - `mediaTranscriptionRules.ts` at 41 lines.
- Tightened `useMediaTranscriptionWorkflow.ts` budget from 310 lines to 220 lines.
- Added budgets for playback workflow and pure transcription rules.

### Validation

- `cd frontend && pnpm exec vitest run src/app/features/media/useMediaTranscriptionWorkflow.test.ts src/app/pages/MediaAnalysis.test.tsx src/app/features/media/MediaSessionTableUtils.test.ts` passed, 2 files / 8 tests.
- `cd frontend && pnpm run size:check` passed.
- First `cd frontend && pnpm run typecheck` failed on an unused `isMediaDependencyError` import; removed it.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- First `cd frontend && pnpm run ci` failed on Prettier formatting for `scripts/check-size.mjs`; ran Prettier for that file.
- `cd frontend && pnpm run ci` passed, 145 test files / 433 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 9 / 10.
- No drift detected:
  - media workflow split reduced effect ownership without UI or API changes,
  - helper exports stayed compatible,
  - mapper files were not enlarged,
  - MISC stayed independent from unified Evidence,
  - `useSentinel()` public contract stayed stable,
  - ignored docs/samples/build outputs remained unstaged.
- Next autonomous target: one more bounded round, then mandatory 10-round self-audit.

---

## Round 114 - Workspace Title And Filter Section Split

Time: 2026-05-11 07:28:10 +08:00  
Author: Codex

### Scope

- Split workspace title-bar action composition into `WorkspaceTitleActions.tsx`.
- Split display-filter bar, syntax hint, and filter error presentation into `WorkspaceFilterSection.tsx`.
- Kept `Workspace.tsx` focused on Sentinel state wiring, filter workflow, stream navigation, and page composition.
- Preserved capture open/close, packet paging, packet locate, display filter, stream follow, and capture transaction behavior.
- Did not change backend APIs, request/response shapes, public model shapes, mapper logic, MISC/Evidence boundaries, or `useSentinel()` public contract.

### Size Check

- `Workspace.tsx` presentation responsibilities were reduced by moving title controls and filter presentation into workspace components.
- Added:
  - `WorkspaceTitleActions.tsx` at 86 lines,
  - `WorkspaceFilterSection.tsx` at 49 lines.
- Tightened `Workspace.tsx` budget from 290 lines to 275 lines.
- Added budgets for both new workspace composition components.

### Validation

- `cd frontend && pnpm exec vitest run src/app/components/workspace/WorkspacePanels.test.tsx src/app/pages/AnalysisCockpit.test.tsx` passed, 2 files / 4 tests.
- First `cd frontend && pnpm run size:check` failed because `Workspace.tsx` was still over the new budget; moved the filter section and set the budget to a still-lower 275 lines.
- First `cd frontend && pnpm run typecheck` failed on a too-narrow ref type in `WorkspaceFilterSection.tsx`; aligned it with `DisplayFilterBar`'s `Ref<HTMLInputElement>` contract.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 145 test files / 433 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Ten-Round Self-Audit

- Current cycle counter: 10 / 10; self-audit completed.
- No drift detected:
  - MISC remains independent and was not wired into unified Evidence.
  - `useSentinel()` public shape remains unchanged.
  - Backend APIs, request/response shapes, and frontend public model shapes remain unchanged.
  - `pnpm` remains the only frontend package manager; `package-lock.json` did not return.
  - Mapper files were not enlarged.
  - Size budgets were tightened or added rather than loosened to hide growth.
  - Ignored docs, samples, build output, `frontend/dist`, `node_modules`, logs, and release binaries remained unstaged.
  - Work stayed on frontend engineering boundaries, not feature drift.
- Remaining risks:
  - `SentinelContext.tsx` remains the largest state ownership risk and still needs cautious internal hook/helper extraction.
  - `useBackendLifecycle.ts`, `core/engine.ts`, `captureOverview.ts`, and `components/ui/sidebar.tsx` remain large enough to monitor.
  - Mapper tests are larger than many mapper modules; acceptable for now because mapper production files remain bounded.
- Next cycle starts at 0 / 10; next autonomous target should prioritize mapper-size guardrails or state/internal hook boundaries.

---

## Round 115 - Mapper Size Budget Guardrail

Time: 2026-05-11 07:34:03 +08:00  
Author: Codex

### Scope

- Added explicit size budgets for previously unbudgeted production mapper files:
  - `aptMapper.ts`,
  - `c2DecryptMapper.ts`,
  - `evidenceMapper.ts`,
  - `mapperPrimitives.ts`,
  - `objectMapper.ts`,
  - `pluginMapper.ts`,
  - `pluginSourceMapper.ts`,
  - `tlsMapper.ts`,
  - `trafficMapper.ts`.
- Extended `scripts/check-size.mjs` with `findUnbudgetedMapperFiles()` so new production files under `src/app/integrations/mappers` must have explicit budgets.
- Added a focused size-script test proving mapper tests are ignored while unbudgeted production mapper files fail the guardrail.
- Did not alter mapper behavior, backend APIs, request/response shapes, public model shapes, MISC/Evidence boundaries, or `useSentinel()` public contract.

### Size Check

- Mapper budget coverage is now complete for current production mapper files.
- `pnpm run size:check` now fails on either line-budget overflow or production mapper files missing budgets.
- This round intentionally controls mapper growth without splitting already small mapper modules.

### Validation

- `cd frontend && pnpm exec vitest run scripts/check-size.test.mjs` passed, 1 file / 3 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 145 test files / 434 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 1 / 10.
- No drift detected:
  - change is engineering guardrail only,
  - mapper files did not grow,
  - MISC stayed independent from unified Evidence,
  - `useSentinel()` public contract stayed stable,
  - ignored docs/samples/build outputs remained unstaged.
- Next autonomous target: continue with a bounded state/helper split or another guardrail that reduces future frontend drift.

---

## Round 116 - Frontend Capture Task Reset Hook

Time: 2026-05-11 07:38:45 +08:00  
Author: Codex

### Scope

- Added `useFrontendCaptureTaskReset.ts` to own Sentinel provider wiring for frontend capture task cancellation refs.
- Kept `cancelFrontendCaptureTasks()` as the pure state/reset function and reused it from the hook.
- Added hook coverage for invalidating capture tasks, bumping packet/threat sequences, clearing stream prefetch sets, cancelling scheduled load-more, and clearing packet page loading/error state.
- Replaced the inline `cancelAllFrontendCaptureTasks` callback in `SentinelContext.tsx` with the new hook.
- Did not change backend APIs, request/response shapes, public model shapes, MISC/Evidence boundaries, or `useSentinel()` public contract.

### Size Check

- `SentinelContext.tsx` dropped from 727 lines to 724 lines.
- Added:
  - `useFrontendCaptureTaskReset.ts` at 59 lines,
  - `useFrontendCaptureTaskReset.test.tsx` at 64 lines.
- Added size budgets for the hook and hook test.
- This is a deliberately small state-ownership extraction: low diff, high boundary clarity.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/useFrontendCaptureTaskReset.test.tsx src/app/state/captureTaskReset.test.ts src/app/state/hooks/usePacketPageCancellation.test.tsx` passed, 3 files / 4 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 146 test files / 435 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 2 / 10.
- No drift detected:
  - state extraction preserved `useSentinel()` public shape,
  - cancellation semantics stayed covered by pure-function and hook tests,
  - mapper files were not touched,
  - MISC stayed independent from unified Evidence,
  - ignored docs/samples/build outputs remained unstaged.
- Next autonomous target: continue shrinking Sentinel state wiring or split a remaining backend/runtime lifecycle helper with focused tests.

---

## Round 117 - Clear Capture UI State Hook

Time: 2026-05-11 07:44:39 +08:00  
Author: Codex

### Scope

- Added `useClearCaptureUiState.ts` to own Sentinel provider wiring for capture UI reset refs and setters.
- Kept `clearCaptureUiStateData()` as the pure reset function and reused it from the hook.
- Replaced the inline `clearCaptureUiState` callback in `SentinelContext.tsx` with the new hook.
- Added hook coverage for cache dereference, stream prefetch clearing, active capture path clearing, analysis reset, and capture revision bump.
- Did not change backend APIs, request/response shapes, public model shapes, MISC/Evidence boundaries, or `useSentinel()` public contract.

### Size Check

- `SentinelContext.tsx` moved from 724 lines to 762 lines after replacing an inline callback with explicit hook wiring; the practical win is ownership clarity and test isolation rather than immediate line reduction.
- Tightened `SentinelContext.tsx` budget from 890 lines to 790 lines, preserving a stricter cap than the previous oversized allowance.
- Added:
  - `useClearCaptureUiState.ts` at 70 lines,
  - `useClearCaptureUiState.test.tsx` at 89 lines.
- Added size budgets for the new hook and hook test.

### Validation

- First focused run failed because the hook passed stream switch ref fields with names mismatched to `clearCaptureUiStateData()`; fixed by mapping `streamSwitchDurationsRef`/`streamSwitchHitsRef` to `switchDurationsRef`/`switchHitsRef`.
- First hook test also asserted unrelated empty-stream constants; removed those assertions and kept the reset-wiring assertions focused.
- `cd frontend && pnpm exec vitest run src/app/state/hooks/useClearCaptureUiState.test.tsx src/app/state/captureClearState.test.ts src/app/state/hooks/useFrontendCaptureTaskReset.test.tsx` passed, 3 files / 3 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 147 test files / 436 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 3 / 10.
- No drift detected:
  - state extraction preserved `useSentinel()` public shape,
  - clear/reset behavior remains covered by pure-function and hook tests,
  - mapper files were not touched,
  - MISC stayed independent from unified Evidence,
  - ignored docs/samples/build outputs remained unstaged.
- Next autonomous target: keep state split bounded; consider moving capture open orchestration wiring only if tests can stay focused.

---

## Round 118 - Display Filter Workflow Hook

Time: 2026-05-11 07:52:06 +08:00  
Author: Codex

### Scope

- Added `useDisplayFilterWorkflow.ts` to own Sentinel display-filter action wiring.
- Kept `runPacketFilterAction()` and `runPacketFilterWorkflow()` as pure workflow owners.
- Replaced inline `applyFilter` and `clearFilter` callbacks in `SentinelContext.tsx` with the hook.
- Added hook tests for explicit apply, clear, and inactive-capture behavior.
- Did not change backend APIs, request/response shapes, public model shapes, MISC/Evidence boundaries, or `useSentinel()` public contract.

### Size Check

- Added `useDisplayFilterWorkflow.ts` and its focused hook test.
- Added size budgets for the hook and hook test.
- Mapper files were not touched; mapper budget guard remains active.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/useDisplayFilterWorkflow.test.tsx src/app/state/packetFilterAction.test.ts src/app/state/packetFilterWorkflow.test.ts` passed, 3 files / 11 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 148 test files / 438 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 4 / 10.
- No drift detected:
  - `useSentinel()` public shape unchanged,
  - display-filter semantics stayed covered by pure workflow and hook tests,
  - mapper files were not touched,
  - MISC stayed independent from unified Evidence,
  - ignored docs/samples/build outputs remained unstaged.
- Next autonomous target: continue bounded Sentinel ownership extraction or split one remaining lifecycle helper with focused tests.

---

## Round 119 - Capture Replacement Prepare Hook

Time: 2026-05-11 07:56:59 +08:00  
Author: Codex

### Scope

- Added `useCaptureReplacementPrepare.ts` to own Sentinel provider wiring for capture replacement preparation.
- Kept `prepareCaptureReplacementState()` as the pure behavior owner for frontend task cancellation, waiter wakeup, parse/preload reset, and backend cleanup.
- Replaced the inline `prepareForCaptureReplacement` callback in `SentinelContext.tsx` with the hook.
- Added hook tests for reset/backend cleanup wiring and latest-ref behavior without callback identity churn.
- Did not change backend APIs, request/response shapes, public model shapes, MISC/Evidence boundaries, or `useSentinel()` public contract.

### Size Check

- Added `useCaptureReplacementPrepare.ts` and its focused hook test.
- Added size budgets for both.
- Mapper files were not touched; mapper budget guard remains active.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/useCaptureReplacementPrepare.test.tsx src/app/state/captureReplacementPrepare.test.ts src/app/state/captureStartBackend.test.ts` passed, 3 files / 10 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 149 test files / 440 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 5 / 10.
- No drift detected:
  - `useSentinel()` public shape unchanged,
  - capture replacement semantics stayed covered by pure-function and hook tests,
  - mapper files were not touched,
  - MISC stayed independent from unified Evidence,
  - ignored docs/samples/build outputs remained unstaged.
- Next autonomous target: continue bounded Sentinel state ownership extraction, likely capture open orchestration only if it can stay testable without changing public shape.

---

## Round 120 - Capture Stop Workflow Hook

Time: 2026-05-11 08:01:40 +08:00  
Author: Codex

### Scope

- Added `useCaptureStopWorkflow.ts` to own Sentinel provider wiring for capture stop/close.
- Kept `stopCaptureWorkflow()` as the pure workflow owner for sequence invalidation, frontend cleanup, waiter wakeup, and backend close.
- Replaced the inline `stopCapture` callback in `SentinelContext.tsx` with the hook.
- Added hook tests for stop wiring and latest-ref behavior without callback identity churn.
- Did not change backend APIs, request/response shapes, public model shapes, MISC/Evidence boundaries, or `useSentinel()` public contract.

### Size Check

- Added `useCaptureStopWorkflow.ts` and its focused hook test.
- Added size budgets for both.
- Mapper files were not touched; mapper budget guard remains active.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/useCaptureStopWorkflow.test.tsx src/app/state/captureStopWorkflow.test.ts src/app/state/captureStopStatus.test.ts` passed, 3 files / 8 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 150 test files / 442 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 6 / 10.
- No drift detected:
  - `useSentinel()` public shape unchanged,
  - stop/close semantics stayed covered by pure-function and hook tests,
  - mapper files were not touched,
  - MISC stayed independent from unified Evidence,
  - ignored docs/samples/build outputs remained unstaged.
- Next autonomous target: audit remaining `SentinelContext.tsx` bulk and avoid moving `startCapture` until a focused hook/test boundary is clear.

---

## Round 121 - Sentinel Derived View Hook

Time: 2026-05-11 08:06:27 +08:00  
Author: Codex

### Scope

- Added `useSentinelDerivedView.ts` to own memoized packet-derived view state for the Sentinel provider.
- Kept `buildSentinelDerivedView()` as the pure owner for selected packet resolution, protocol tree, hex dump, and pagination metadata.
- Replaced inline derived-view `useMemo` in `SentinelContext.tsx` with the hook.
- Added hook coverage for memoization stability and selected-packet invalidation.
- Did not change backend APIs, request/response shapes, public model shapes, MISC/Evidence boundaries, or `useSentinel()` public contract.

### Size Check

- Added `useSentinelDerivedView.ts` and its focused hook test.
- Added size budgets for both.
- Mapper files were not touched; mapper budget guard remains active.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/useSentinelDerivedView.test.tsx src/app/state/sentinelDerivedView.test.ts src/app/state/selectedPacketState.test.ts src/app/state/packetPagination.test.ts` passed, 4 files / 15 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 151 test files / 443 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 7 / 10.
- No drift detected:
  - `useSentinel()` public shape unchanged,
  - derived-view behavior stayed covered by pure-function and hook tests,
  - mapper files were not touched,
  - MISC stayed independent from unified Evidence,
  - ignored docs/samples/build outputs remained unstaged.
- Next autonomous target: inspect whether small lifecycle/ref sync hooks remain; avoid high-risk `startCapture` migration until it has a clearer test harness.

---

## Round 122 - Has More Packet Ref Sync Cleanup

Time: 2026-05-11 08:10:14 +08:00  
Author: Codex

### Scope

- Replaced the dedicated `hasMorePacketsRef` sync `useEffect` in `SentinelContext.tsx` with the existing `useSyncedRefValue()` helper.
- Kept packet page commit/navigation ownership unchanged.
- Did not move `startCapture`; the capture-open flow remains intentionally untouched until a focused hook boundary is safer.
- Did not change backend APIs, request/response shapes, public model shapes, MISC/Evidence boundaries, or `useSentinel()` public contract.

### Size Check

- No new files were added.
- `SentinelContext.tsx` lost one bespoke effect and now reuses the same ref-sync pattern as scheduled load, analysis refresh, and progress status.
- Mapper files were not touched; mapper budget guard remains active.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/useSyncedRefValue.test.tsx src/app/state/hooks/usePacketPageCommit.test.tsx src/app/state/packetPageCommit.test.ts` passed, 3 files / 4 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 151 test files / 443 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 8 / 10.
- No drift detected:
  - `useSentinel()` public shape unchanged,
  - packet page ref behavior stayed covered by sync-ref and page commit tests,
  - mapper files were not touched,
  - MISC stayed independent from unified Evidence,
  - ignored docs/samples/build outputs remained unstaged.
- Next autonomous target: either add test scaffolding for capture-open before any extraction or move to another bounded non-mapper large-file boundary.

---

## Round 123 - Capture Task Scope Cleanup Hook

Time: 2026-05-11 08:16:28 +08:00  
Author: Codex

### Scope

- Added `useCaptureTaskScopeCleanup.ts` to own Sentinel provider unmount invalidation of capture-scoped tasks.
- Replaced inline provider cleanup effect in `SentinelContext.tsx` with the hook.
- Added hook coverage for invalidating active capture tasks on unmount.
- Did not move `startCapture`; capture-open orchestration remains untouched until a safer focused test boundary exists.
- Did not change backend APIs, request/response shapes, public model shapes, MISC/Evidence boundaries, or `useSentinel()` public contract.

### Size Check

- Added `useCaptureTaskScopeCleanup.ts` and its focused hook test.
- Added size budgets for both.
- Removed the now-unused `useEffect` React import from `SentinelContext.tsx`.
- Mapper files were not touched; mapper budget guard remains active.

### Validation

- First full frontend gate failed because `useEffect` became an unused import in `SentinelContext.tsx`; removed it and reran.
- `cd frontend && pnpm exec vitest run src/app/state/hooks/useCaptureTaskScopeCleanup.test.tsx src/app/utils/captureTaskScope.test.ts` passed, 2 files / 4 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 152 test files / 444 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 9 / 10.
- No drift detected:
  - `useSentinel()` public shape unchanged,
  - provider unmount invalidation now has focused hook coverage,
  - mapper files were not touched,
  - MISC stayed independent from unified Evidence,
  - ignored docs/samples/build outputs remained unstaged.
- Next autonomous target: perform one more bounded round, then do the required 10-round self-audit.

---

## Round 124 - Open Capture Action Hook

Time: 2026-05-11 08:21:33 +08:00  
Author: Codex

### Scope

- Added `useOpenCaptureAction.ts` to own the small UI action that clears the display filter before delegating to `startCapture`.
- Replaced the inline `openCapture` callback in `SentinelContext.tsx` with the hook.
- Added hook coverage for filter reset and `startCapture(filePath, "")` delegation.
- Did not move the high-risk `startCapture` transaction body.
- Did not change backend APIs, request/response shapes, public model shapes, MISC/Evidence boundaries, or `useSentinel()` public contract.

### Size Check

- Added budgets for `useOpenCaptureAction.ts` and its focused test.
- `SentinelContext.tsx` is now 673 lines after this round.
- `wailsBridge.ts` remains a 23-line compatibility facade.
- Mapper files were not touched; mapper budget guard remains active.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/useOpenCaptureAction.test.tsx src/app/state/hooks/useCaptureTaskScopeCleanup.test.tsx` passed, 2 files / 2 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 153 test files / 445 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Ten-Round Self-Audit

- Window audited: Round 115 through Round 124.
- Mainline stayed aligned:
  - `SentinelContext.tsx` moved from the prior oversized provider toward hook-owned state boundaries and is now under the 800-line stage target.
  - `useSentinel()` public shape stayed unchanged.
  - Backend APIs and frontend response shapes stayed unchanged.
  - MISC remained independent from unified Evidence.
  - Mapper growth was controlled by explicit mapper size-budget enforcement; this round did not touch mapper files.
  - Reports, samples, PCAPs, `frontend/dist`, logs, release binaries, and tool binaries remained ignored and unstaged.
- Remaining risk:
  - `startCapture` still owns the largest capture-open transaction and should not be moved until a stronger focused harness exists.
  - `components/ui/sidebar.tsx`, `useBackendLifecycle.ts`, and several runtime/core helpers are now better next targets than more tiny Sentinel churn.
- Next autonomous target: reset cycle counter to 0 / 10 and choose the next bounded non-mapper boundary.

---

## Round 125 - Sidebar Shell Split

Time: 2026-05-11 08:26:09 +08:00  
Author: Codex

### Scope

- Extracted `sidebarShell.tsx` to own responsive desktop/mobile sidebar container layout.
- Kept `sidebar.tsx` as the public entry and export aggregator for trigger, rail, inset, and sidebar primitives.
- Reduced `sidebar.tsx` from 206 lines to 111 lines; new `sidebarShell.tsx` is 94 lines.
- Did not change public imports from `components/ui/sidebar`.
- Did not touch mapper files, backend APIs, request/response shapes, MISC/Evidence boundaries, or `useSentinel()` public contract.

### Size Check

- Tightened `sidebar.tsx` budget from 230 to 120 lines.
- Added a dedicated `sidebarShell.tsx` budget of 130 lines.
- Mapper size-budget guard remains active and unchanged.

### Validation

- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm exec vitest run src/app/layouts/MainLayout.test.ts src/app/components/RuntimeSettingsSidebarParts.test.tsx` passed, 2 files / 8 tests.
- `cd frontend && pnpm run ci` passed, 153 test files / 445 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 1 / 10.
- Mainline intact:
  - sidebar primitive boundary is clearer,
  - public import surface unchanged,
  - mapper files untouched,
  - ignored reports/samples/build outputs remained unstaged.
- Next autonomous target: inspect another bounded non-mapper large-file boundary, likely `useBackendLifecycle.ts` or core helper extraction.

---

## Round 126 - Backend Lifecycle Startup Split

Time: 2026-05-11 08:35:47 +08:00  
Author: Codex

### Scope

- Added `useBackendLifecycleControls.ts` to own TLS config update and tool-runtime control callbacks.
- Added `useBackendLifecycleStartupEffect.ts` to own backend availability polling, startup runtime/TLS checks, retry timer, event subscription, and cleanup.
- Reduced `useBackendLifecycle.ts` from 216 lines to 163 lines.
- Preserved the existing backend lifecycle tests and added focused controls coverage for connected/offline TLS sync.
- Did not change backend APIs, request/response shapes, desktop/HTTP transport contract, MISC/Evidence boundaries, mapper files, or `useSentinel()` public contract.

### Size Check

- Tightened `useBackendLifecycle.ts` budget from 240 to 205 lines.
- Added budgets for `useBackendLifecycleControls.ts`, `useBackendLifecycleStartupEffect.ts`, and the controls test.
- Mapper size-budget guard remains active and unchanged.

### Validation

- `cd frontend && pnpm exec vitest run src/app/state/hooks/useBackendLifecycleControls.test.tsx src/app/state/hooks/useBackendLifecycle.test.tsx` passed, 2 files / 8 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 154 test files / 447 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 2 / 10.
- Mainline intact:
  - backend lifecycle hook now composes startup and control owners instead of carrying all logic inline,
  - startup retry/subscription behavior stayed covered by the existing lifecycle harness,
  - mapper files untouched,
  - ignored reports/samples/build outputs remained unstaged.
- Next autonomous target: inspect core helper or runtime/sidebar residue; avoid `startCapture` until stronger capture-open harness exists.

---

## Round 127 - Packet Coloring Rule Split

Time: 2026-05-11 08:42:50 +08:00  
Author: Codex

### Scope

- Split `packetColoring.ts` into focused pure-rule files:
  - `packetColoringRules.ts` for the Wireshark coloring text snapshot,
  - `packetColoringColors.ts` for RGB16 parsing and CSS conversion,
  - `packetColoringMatchers.ts` for rule-name to packet matcher logic,
  - `packetColoringParser.ts` for parsing rule lines.
- Kept `packetColoring.ts` as the thin application entry used by packet table rows.
- Added regression tests for bad TCP priority and HTTP/ARP protocol matching.
- Did not change row rendering, backend APIs, request/response shapes, MISC/Evidence boundaries, mapper files, or `useSentinel()` public contract.

### Size Check

- Reduced `packetColoring.ts` from 205 lines to 26 lines.
- Added budgets for all packet coloring rule/parser/matcher/color files and the focused test.
- Mapper size-budget guard remains active and unchanged.

### Validation

- `cd frontend && pnpm exec vitest run src/app/core/packetColoring.test.ts src/app/components/PacketVirtualTable.test.tsx` passed, 2 files / 7 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 155 test files / 449 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 3 / 10.
- Mainline intact:
  - packet coloring became testable pure rules,
  - packet table import surface stayed unchanged,
  - mapper files untouched,
  - ignored reports/samples/build outputs remained unstaged.
- Next autonomous target: inspect another core/runtime file with business rules that can be split without API or UI behavior changes.

---

## Round 128 - Raw Stream Route Selection Split

Time: 2026-05-11 08:50:44 +08:00  
Author: Codex

### Scope

- Added `useRawStreamRouteSelection.ts` to own route-state stream selection and selected-packet fallback selection for the shared TCP/UDP raw stream page.
- Added `RawStreamViewState.ts` to keep the raw stream view-state type and empty-state factory out of the page body.
- Reduced `RawStreamPage.tsx` from 266 lines to 245 lines.
- Added focused route-selection tests covering one-shot route consumption, selected-packet fallback, missing stream guard, and active-stream no-op.
- Did not change backend APIs, request/response shapes, MISC/Evidence boundaries, mapper files, or raw stream presentation behavior.

### Size Check

- Tightened `RawStreamPage.tsx` budget from 285 to 265 lines.
- Added budgets for `useRawStreamRouteSelection.ts`, `RawStreamViewState.ts`, and `useRawStreamRouteSelection.test.tsx`.
- Mapper size-budget guard remains active and unchanged.

### Validation

- `cd frontend && pnpm exec vitest run src/app/pages/useRawStreamRouteSelection.test.tsx src/app/pages/RawStreamUtils.test.ts` passed, 2 files / 9 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 156 test files / 453 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 4 / 10.
- Mainline intact:
  - raw stream route-selection ownership is now testable,
  - RawStream page remains the protocol orchestration shell,
  - mapper files untouched,
  - ignored reports/samples/build outputs remained unstaged.
- Next autonomous target: continue with a bounded non-mapper presentation or pure-state boundary; avoid broad state rewrites without focused harness.

---

## Round 129 - Raw Stream Page Loader Split

Time: 2026-05-11 08:56:41 +08:00  
Author: Codex

### Scope

- Added `useRawStreamPageLoader.ts` to own incremental raw stream page fetching, append merge, stale-page guard, loading state, and load-error state.
- Added focused tests for successful append, stale page ignore, and load-error reset after stream change.
- Reduced `RawStreamPage.tsx` from 245 lines to 214 lines.
- Kept the page as protocol-specific orchestration and presentation composition.
- Did not change backend APIs, request/response shapes, MISC/Evidence boundaries, mapper files, or raw stream table/payload rendering.

### Size Check

- Tightened `RawStreamPage.tsx` budget from 265 to 235 lines.
- Added budgets for `useRawStreamPageLoader.ts` and `useRawStreamPageLoader.test.tsx`.
- Mapper size-budget guard remains active and unchanged.

### Validation

- `cd frontend && pnpm exec vitest run src/app/pages/useRawStreamPageLoader.test.tsx src/app/pages/useRawStreamRouteSelection.test.tsx src/app/pages/RawStreamUtils.test.ts` passed, 3 files / 12 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 157 test files / 456 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 5 / 10.
- Mainline intact:
  - raw stream pagination ownership is now isolated and testable,
  - stale page handling remains guarded,
  - mapper files untouched,
  - ignored reports/samples/build outputs remained unstaged.
- Next autonomous target: inspect another bounded high-line component or core helper; avoid mapper expansion and broad context-shape changes.

---

## Round 130 - Workspace Navigation and Filter Action Split

Time: 2026-05-11 09:03:03 +08:00  
Author: Codex

### Scope

- Added `useWorkspaceStreamNavigation.ts` to own packet stream-id to HTTP/TCP/UDP route mapping and active-stream selection.
- Added `useWorkspaceFilterAction.ts` to own display-filter trimming, history remember, and apply/clear dispatch.
- Added focused tests for stream route mapping, no-stream guard, HTTP stream list navigation, filter apply, and filter clear.
- Reduced `Workspace.tsx` from 254 lines to 247 lines and removed direct router dependency from the page body.
- Did not change backend APIs, request/response shapes, MISC/Evidence boundaries, mapper files, `useSentinel()` shape, or workspace presentation behavior.

### Size Check

- Tightened `Workspace.tsx` budget from 275 to 250 lines.
- Added budgets for the two workspace hooks and their focused tests.
- Mapper size-budget guard remains active and unchanged.

### Validation

- `cd frontend && pnpm exec vitest run src/app/pages/useWorkspaceStreamNavigation.test.tsx src/app/pages/useWorkspaceFilterAction.test.tsx src/app/components/workspace/WorkspacePanels.test.tsx src/app/pages/AnalysisCockpit.test.tsx` passed, 4 files / 9 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 159 test files / 461 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 6 / 10.
- Mainline intact:
  - workspace route side effects and filter apply semantics are isolated and testable,
  - page still owns capture/workspace composition,
  - mapper files untouched,
  - ignored reports/samples/build outputs remained unstaged.
- Next autonomous target: prefer a similarly bounded presentation/state hook split, or inspect `useStreamDecoderWorkbench.ts` for low-risk workflow extraction.

---

## Round 131 - Decoder Workbench State Split

Time: 2026-05-11 09:17:23 +08:00  
Author: Codex

### Scope

- Added `useDecoderSettingsState.ts` to own decoder settings read/persist and source-hint merge.
- Added `useDecoderBatchRange.ts` to own selected batch ordinal and range input reset behavior.
- Reduced `useStreamDecoderWorkbench.ts` from 271 lines to 257 lines.
- Added focused tests for decoder settings hint merge and batch ordinal/range reset.
- Left the decode execution loop, bridge calls, apply/overwrite semantics, and MISC decoder workbench boundary unchanged.
- Did not change backend APIs, request/response shapes, MISC/Evidence boundaries, mapper files, or `useSentinel()` public contract.

### Size Check

- Tightened `useStreamDecoderWorkbench.ts` budget from 295 to 280 lines.
- Added budgets for the two decoder helper hooks and their tests.
- Mapper size-budget guard remains active and unchanged.

### Validation

- `cd frontend && pnpm exec vitest run src/app/components/useDecoderSettingsState.test.tsx src/app/components/useDecoderBatchRange.test.tsx src/app/components/StreamDecoderWorkbenchUtils.test.ts src/app/components/StreamDecoderToolbar.test.tsx src/app/components/StreamDecoderBatchPanel.test.tsx` passed, 5 files / 15 tests.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 161 test files / 463 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 7 / 10.
- Mainline intact:
  - decoder settings and range state now have focused ownership and tests,
  - decode workflow itself was not rewritten,
  - mapper files untouched,
  - ignored reports/samples/build outputs remained unstaged.
- Next autonomous target: continue with low-risk state/presentation boundary; avoid changing decoder semantics or WebShell heuristics during engineering-only work.

---

## Round 132 - Decoder Settings Section Split

Time: 2026-05-11 09:27:38 +08:00  
Author: Codex

### Scope

- Split the monolithic decoder settings section file into one section per WebShell family:
  - `BehinderSettingsSection.tsx`
  - `AntSwordSettingsSection.tsx`
  - `GodzillaSettingsSection.tsx`
- Kept `StreamDecoderSettingsSections.tsx` as a compatibility export layer so existing imports remain stable.
- Added `StreamDecoderSettingsSectionTypes.ts` for shared props and numeric text clamping.
- Added focused tests for Behinder, AntSword, and Godzilla settings form wiring.
- Did not change decoder execution, source-hint merge, MISC workbench behavior, backend APIs, mapper files, or `useSentinel()` public shape.

### Size Check

- Reduced `StreamDecoderSettingsSections.tsx` from 228 lines to 3 lines.
- Added separate size budgets for the three family settings sections and shared settings section types.
- Added a size budget for `StreamDecoderSettingsSections.test.tsx`.
- Mapper size-budget guard remains active and unchanged.

### Validation

- `cd frontend && pnpm exec vitest run src/app/components/StreamDecoderSettingsSections.test.tsx src/app/components/StreamDecoderToolbar.test.tsx src/app/components/StreamDecoderBatchPanel.test.tsx` passed, 3 files / 7 tests.
- `cd frontend && pnpm run format:check` passed.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 162 test files / 466 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 8 / 10.
- Mainline intact:
  - decoder settings presentation now has family-level ownership,
  - compatibility exports preserve callers,
  - mapper files untouched,
  - ignored reports/samples/build outputs remained unstaged.
- Next autonomous target: continue with another bounded presentation/state split; self-audit remains due after Round 134.

---

## Round 133 - Runtime Settings Section Split

Time: 2026-05-11 09:34:52 +08:00  
Author: Codex

### Scope

- Split runtime settings domain sections into focused presentational files:
  - `CaptureSettingsSection.tsx`
  - `YaraSettingsSection.tsx`
  - `MediaSettingsSection.tsx`
  - `SpeechSettingsSection.tsx`
- Kept `RuntimeSettingsSections.tsx` as a compatibility export layer so `RuntimeSettingsSidebar.tsx` import paths remain stable.
- Added `RuntimeSettingsSectionTypes.ts` for shared props.
- Added focused tests covering section rendering, setter wiring, speech dependency summary, and missing issue chips.
- Did not change runtime save/refresh orchestration, backend runtime APIs, mapper files, MISC/Evidence boundaries, or `useSentinel()` public shape.

### Size Check

- Reduced `RuntimeSettingsSections.tsx` from 228 lines to 4 lines.
- Added separate size budgets for the four runtime section files and shared section types.
- Added a size budget for `RuntimeSettingsSections.test.tsx`.
- Mapper size-budget guard remains active and unchanged.

### Validation

- `cd frontend && pnpm exec vitest run src/app/components/RuntimeSettingsSections.test.tsx src/app/components/RuntimeSettingsSidebarParts.test.tsx` passed, 2 files / 6 tests.
- `cd frontend && pnpm run format:check` passed.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 163 test files / 468 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 9 / 10.
- Mainline intact:
  - runtime sidebar orchestration unchanged,
  - runtime section presentation now has domain ownership,
  - mapper files untouched,
  - ignored reports/samples/build outputs remained unstaged.
- Next autonomous target: one more bounded round, then perform the scheduled 10-round self-audit after Round 134.

---

## Round 134 - Stream Navigation Controls Split

Time: 2026-05-11 09:39:44 +08:00  
Author: Codex

### Scope

- Split stream workbench control primitives into focused files:
  - `StreamNavigator.tsx`
  - `StreamSearchBar.tsx`
  - `ViewModeToggle.tsx`
  - `StreamControlBar.tsx`
- Kept `StreamNavigationControls.tsx` as a compatibility export layer so existing stream workbench imports remain stable.
- Preserved stream id normalization, Enter-submit behavior, search summary, disabled navigation, and view-mode selection behavior.
- Did not change stream routing, payload display, backend APIs, mapper files, MISC/Evidence boundaries, or `useSentinel()` public shape.

### Size Check

- Reduced `StreamNavigationControls.tsx` from 196 lines to 4 lines.
- Added separate size budgets for navigator, search bar, view toggle, and control bar.
- Existing `StreamNavigationControls.test.tsx` continues to cover the compatibility export surface.
- Mapper size-budget guard remains active and unchanged.

### Validation

- `cd frontend && pnpm exec vitest run src/app/components/stream/StreamNavigationControls.test.tsx` passed, 1 file / 3 tests.
- `cd frontend && pnpm run format:check` passed.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 163 test files / 468 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 10 / 10.
- Mainline intact:
  - stream UI primitives now have narrower file ownership,
  - compatibility exports preserve callers,
  - mapper files untouched,
  - ignored reports/samples/build outputs remained unstaged.
- Required next step: perform the scheduled 10-round self-audit before continuing.

---

## Cycle Self-Audit - Rounds 125-134

Time: 2026-05-11 09:41:12 +08:00  
Author: Codex

### Scope Review

- Reviewed the last 10 commits:
  - `e1ed248 refactor(frontend): split sidebar shell`
  - `0053f07 refactor(frontend): split backend lifecycle hooks`
  - `f3a8ab3 refactor(frontend): split packet coloring rules`
  - `33c39fc refactor(frontend): extract raw stream route selection`
  - `d5593eb refactor(frontend): extract raw stream page loader`
  - `1b0ea6c refactor(frontend): extract workspace actions`
  - `2104191 refactor(frontend): split decoder workbench state`
  - `72dc00f refactor(frontend): split decoder settings sections`
  - `f75e929 refactor(frontend): split runtime settings sections`
  - `f2e664a refactor(frontend): split stream controls`
- All 10 rounds stayed inside frontend engineering boundaries: presentation split, hook split, pure-rule extraction, compatibility barrels, and size-budget tightening.
- No backend business API, C2/VShell/WebShell semantics, MISC/Evidence wiring, or `useSentinel()` public contract was changed in this cycle.

### Guardrail Review

- `cd frontend && pnpm run size:check` passed after Round 134.
- Mapper budget guard remains active.
- Largest mapper files remain inside budget; top mapper files are still `vshellDecryptDisplayRules.ts`, `c2DecryptDisplayMapper.ts`, `vshellTextSignals.ts`, `vshellHexPreview.ts`, and `packetMapper.ts`.
- `git status --short --ignored` showed no tracked worktree changes after commit; only ignored local samples, reports, build output, logs, tool binaries, and editor/worktree folders.
- Reports remain in ignored docs archive and were not staged.

### Drift Decision

- No drift found.
- Mainline remains: frontend engineering, state/presentation boundary tightening, mapper size control, CI/size budget preservation.
- Next cycle counter resets to 0 / 10.
- Next autonomous target should continue low-risk frontend boundary work, with priority on state ownership or presentation files still above roughly 190-220 lines.

---

## Round 135 - Raw Stream Payload Panel Split

Time: 2026-05-11 09:44:37 +08:00  
Author: Codex

### Scope

- Split raw stream payload support out of `RawStreamPayloadPanels.tsx`:
  - `RawStreamTone.ts` for TCP/UDP tone constants and type.
  - `RawStreamLoadMore.tsx` for incremental loading UI.
  - `RawStreamDirectionBadge.tsx` for direction badge presentation.
- Kept `RawStreamPayloadGrid` and `RawStreamSelectedPanel` behavior stable.
- Updated `RawStreamSections.tsx` to re-export tone constants from the new tone module.
- Did not change raw stream routing, page-loader behavior, stream rendering, backend APIs, mapper files, MISC/Evidence boundaries, or `useSentinel()` public shape.

### Size Check

- Reduced `RawStreamPayloadPanels.tsx` from 201 lines to 139 lines.
- Added size budgets for raw stream tone constants, load-more control, and direction badge.
- Mapper size-budget guard remains active and unchanged.

### Validation

- `cd frontend && pnpm exec vitest run src/app/pages/RawStreamUtils.test.ts src/app/components/stream/StreamNavigationControls.test.tsx` passed, 2 files / 8 tests.
- `cd frontend && pnpm run format:check` passed.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 163 test files / 468 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 1 / 10.
- Mainline intact:
  - raw stream payload UI gained narrower presentation boundaries,
  - no mapper files changed,
  - ignored reports/samples/build outputs remained unstaged.
- Next autonomous target: continue bounded frontend split or start state ownership work where focused tests already exist.

---

## Round 136 - Workspace Top Controls Split

Time: 2026-05-11 09:52:10 +08:00  
Author: Codex

### Scope

- Split workspace top controls into focused control modules:
  - `WorkspaceCaptureFileControls.tsx` owns capture path input and open/stop actions.
  - `WorkspacePacketPagingControls.tsx` owns packet paging, page jump, and pager buttons.
  - `WorkspacePacketLocatorControls.tsx` owns packet id normalization and locate action.
- Reduced `WorkspaceTopControls.tsx` to a compatibility export layer.
- Added focused tests for capture file, paging, and locator wiring.
- Did not change workspace behavior, capture lifecycle, backend APIs, mapper files, MISC/Evidence boundaries, or `useSentinel()` public shape.

### Size Check

- Reduced `WorkspaceTopControls.tsx` from 203 lines to 3 lines.
- Added size budgets for the three extracted control modules and their focused test.
- Mapper size-budget guard remains active and unchanged.

### Validation

- `cd frontend && pnpm exec vitest run src/app/components/workspace/WorkspaceTopControls.test.tsx src/app/components/workspace/WorkspacePanels.test.tsx` passed.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run format:check` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 164 test files / 471 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 2 / 10.
- Mainline intact:
  - workspace top controls gained narrower presentation boundaries,
  - no mapper files changed,
  - ignored reports/samples/build outputs remained unstaged.
- Next autonomous target: continue low-risk frontend boundary split, preferably a presentation module with existing tests.

---

## Round 137 - Threat Hunting Metric Cards Split

Time: 2026-05-11 09:58:19 +08:00  
Author: Codex

### Scope

- Split top-level threat hunting metric cards out of `ThreatHunting.tsx` into `ThreatHuntingMetricCards.tsx`.
- Added a focused metric-card rendering test for total, high-risk, and category count presentation.
- Kept `ThreatHunting.tsx` responsible for runtime config, hunt execution, navigation, and feature-section composition.
- Did not change threat hunting behavior, backend APIs, mapper files, MISC/Evidence boundaries, or `useSentinel()` public shape.

### Size Check

- Reduced `ThreatHunting.tsx` from 249 lines to 227 lines.
- Added size budgets for `ThreatHuntingMetricCards.tsx` and its focused test.
- Tightened the `ThreatHunting.tsx` budget from 280 lines to 230 lines.
- Mapper size-budget guard remains active and unchanged.

### Validation

- `cd frontend && pnpm exec vitest run src/app/features/hunting/ThreatHuntingMetricCards.test.tsx` passed, 1 file / 1 test.
- `cd frontend && pnpm run format:check` passed.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 165 test files / 472 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 3 / 10.
- Mainline intact:
  - threat hunting page gained a narrower presentation boundary,
  - no mapper files changed,
  - ignored reports/samples/build outputs remained unstaged.
- Next autonomous target: continue bounded frontend split or take another small state/presentation boundary with focused tests.

---

## Round 138 - Capture Mission Overview Hook Split

Time: 2026-05-11 10:05:04 +08:00  
Author: Codex

### Scope

- Extracted capture mission overview fetch/cache state from `CaptureMissionControl.tsx` into `useCaptureMissionOverviewBundle.ts`.
- Added focused hook tests for overview fetch/cache reuse and unavailable-capture clearing.
- Kept `CaptureMissionControl.tsx` focused on overview composition, navigation, recommendation actions, and selected packet stream handoff.
- Did not change capture mission behavior, backend APIs, mapper files, MISC/Evidence boundaries, or `useSentinel()` public shape.

### Size Check

- Reduced `CaptureMissionControl.tsx` from 221 lines to 174 lines.
- Added size budgets for `useCaptureMissionOverviewBundle.ts` and its focused test.
- Tightened the `CaptureMissionControl.tsx` budget from 230 lines to 180 lines.
- Mapper size-budget guard remains active and unchanged.

### Validation

- `cd frontend && pnpm exec vitest run src/app/components/useCaptureMissionOverviewBundle.test.tsx src/app/pages/AnalysisCockpit.test.tsx` passed, 2 files / 4 tests.
- `cd frontend && pnpm run format:check` passed.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 166 test files / 474 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 4 / 10.
- Mainline intact:
  - capture mission state ownership became narrower and test-covered,
  - no mapper files changed,
  - ignored reports/samples/build outputs remained unstaged.
- Next autonomous target: continue low-risk frontend boundary work or pick another small state helper with focused tests.

---

## Round 139 - Raw Stream Protocol Config Split

Time: 2026-05-11 10:10:53 +08:00  
Author: Codex

### Scope

- Extracted TCP/UDP raw-stream presentation switches from `RawStreamPage.tsx` into `RawStreamProtocolConfig.ts`.
- Added a focused config test for TCP incremental scroll loading and UDP static panel behavior.
- Kept raw stream page responsible for route selection, stream state, chunk filtering, export, and panel composition.
- Did not change raw stream loading behavior, backend APIs, mapper files, MISC/Evidence boundaries, or `useSentinel()` public shape.

### Size Check

- Reduced `RawStreamPage.tsx` from 221 lines to 216 lines.
- Added size budgets for `RawStreamProtocolConfig.ts` and its focused test.
- Tightened the `RawStreamPage.tsx` budget from 235 lines to 220 lines.
- Mapper size-budget guard remains active and unchanged.

### Validation

- `cd frontend && pnpm exec vitest run src/app/pages/RawStreamProtocolConfig.test.ts src/app/pages/RawStreamUtils.test.ts src/app/pages/useRawStreamPageLoader.test.tsx src/app/pages/useRawStreamRouteSelection.test.tsx` passed, 4 files / 13 tests.
- `cd frontend && pnpm run format:check` passed.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 167 test files / 475 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 5 / 10.
- Mainline intact:
  - raw stream protocol display constants moved out of page orchestration,
  - no mapper files changed,
  - ignored reports/samples/build outputs remained unstaged.
- Next autonomous target: continue low-risk frontend boundary work; self-audit due after five more rounds.

---

## Round 140 - Traffic Graph Presentation and Filter Rules Split

Time: 2026-05-11 10:16:31 +08:00  
Author: Codex

### Scope

- Extracted traffic graph bucket chart rendering into `TrafficSimpleBarChart.tsx`.
- Extracted traffic graph bucket-to-display-filter rules into `trafficGraphFilters.ts`.
- Added focused tests for protocol, IP, domain, and port filter construction.
- Kept `TrafficGraph.tsx` focused on stats loading, panel composition, refresh, and workspace navigation.
- Did not change traffic analysis behavior, backend APIs, mapper files, MISC/Evidence boundaries, or `useSentinel()` public shape.

### Size Check

- Reduced `TrafficGraph.tsx` from 214 lines to 105 lines.
- Added size budgets for the new traffic chart and filter rule modules plus the focused rule test.
- Added a 115-line budget for `TrafficGraph.tsx`.
- Mapper size-budget guard remains active and unchanged.

### Validation

- `cd frontend && pnpm exec vitest run src/app/pages/TrafficGraph.test.ts src/app/features/traffic/trafficGraphFilters.test.ts` passed, 2 files / 3 tests.
- `cd frontend && pnpm run format:check` passed.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 168 test files / 477 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 6 / 10.
- Mainline intact:
  - traffic graph rules and presentation now have clearer ownership,
  - no mapper files changed,
  - ignored reports/samples/build outputs remained unstaged.
- Next autonomous target: continue bounded frontend boundary work; self-audit due after four more rounds.

---

## Round 141 - Workspace View Rules Split

Time: 2026-05-11 10:24:14 +08:00  
Author: Codex

### Scope

- Extracted workspace preload percent, pager item, and filter blank-state helpers into `workspaceViewRules.ts`.
- Added `getWorkspaceFilterPanelState` to consolidate filter loading title/detail/error state in `workspaceStatus.ts`.
- Added focused tests for workspace view rules and filter panel state.
- Kept `Workspace.tsx` focused on state wiring, title/action composition, capture transaction rendering, and panel composition.
- Did not change workspace behavior, backend APIs, mapper files, MISC/Evidence boundaries, or `useSentinel()` public shape.

### Size Check

- Reduced `Workspace.tsx` from 246 lines to 239 lines.
- Added budgets for `workspaceViewRules.ts`, `workspaceStatus.ts`, and their focused tests.
- Tightened the `Workspace.tsx` budget from 250 lines to 240 lines.
- Mapper size-budget guard remains active and unchanged.

### Validation

- `cd frontend && pnpm exec vitest run src/app/pages/workspaceViewRules.test.ts src/app/pages/workspaceStatus.test.ts src/app/pages/useWorkspaceFilterAction.test.tsx src/app/components/workspace/WorkspacePanels.test.tsx` passed, 4 files / 8 tests.
- `cd frontend && pnpm run format:check` passed.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run lint` passed.
- `cd frontend && pnpm run ci` passed, 170 test files / 481 tests.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.

### Review

- Current cycle counter: 7 / 10.
- Mainline intact:
  - workspace display helpers became pure and test-covered,
  - no mapper files changed,
  - ignored reports/samples/build outputs remained unstaged.
- Pausing after this round per user request.

---

## Round 142 - Mainline Report Schema and Regression Gate

Time: 2026-05-11 11:27:28 +08:00  
Author: Codex

### Scope

- Pulled the current round back toward mainline engineering instead of continuing presentation-only frontend splits.
- Added a shared structured investigation report schema covering four sections: `摘要 / 证据 / 明细 / 建议`.
- Applied the first wave of the schema to:
  - HTTP 登录分析
  - SMTP 会话重建
  - MySQL 会话重建
  - Shiro rememberMe 分析
  - 工控分析
  - 车机流量分析
- Added regression coverage for report contracts, mixed desktop/http bridge fallback, and bundled public sample baselines.

### Changes

- Backend:
  - Added `backend/internal/model/analysis_report.go` with shared `InvestigationReport` / `InvestigationReportItem`.
  - Added `backend/internal/engine/analysis_report.go` to build unified reports for HTTP login, SMTP, MySQL, Shiro, Industrial, and Vehicle analyses.
  - Attached `report` payloads to the corresponding analysis responses.
  - Added `backend/internal/engine/analysis_report_test.go` for protocol/workbench report generation.
  - Added `backend/internal/engine/public_protocol_sample_test.go` for bundled public SMTP / MySQL / Industrial / Vehicle sample regression.
- Frontend:
  - Added `frontend/src/app/core/types/report.ts` and shared mapper support via `investigationReportMapper.ts`.
  - Updated protocol, industrial, and vehicle type/mapping paths to carry the shared report payload.
  - Added `frontend/src/app/components/InvestigationReportPanel.tsx` and reused it across protocol modules plus industrial / vehicle pages.
  - Unified export text rendering through `investigationReportText.ts` so TXT export also consumes the shared schema.
  - Added `InvestigationReportPanel.test.tsx` and expanded protocol mapper + desktop bridge tests.
- Documentation:
  - Split 2026-05-11 records out of the 2026-05-10 frontend report into a dedicated 2026-05-11 archive.
  - Added a new 2026-05-11 mainline audit / roadmap document and archive index.

### Validation

- `cd backend && go test ./internal/engine/...` - passed.
- `cd frontend && pnpm exec vitest run src/app/integrations/mappers/protocolToolMapper.test.ts src/app/components/InvestigationReportPanel.test.tsx src/app/integrations/desktopBridge.test.ts` - passed, 3 files / 9 tests.
- `cd frontend && pnpm run size:check` - passed.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run lint` - passed.
- `cd frontend && pnpm run format:check` - passed.

### Review

- This round intentionally changes the development center of gravity:
  - less page-thinning,
  - more shared report contract,
  - more sample-backed and bridge-backed regression coverage.
- The new report schema does not replace the rich domain pages; it standardizes the reusable investigation layer that can be filtered, exported, reviewed, and regression-tested consistently.
- Mainline boundaries stay intact:
  - MISC remains outside unified Evidence ingestion,
  - industrial / vehicle stay in the mainline investigation path,
  - report generation now emphasizes actionable packet-linked evidence rather than isolated presentation fragments.
- Next preferred direction:
  - extend the same schema to additional mainline modules where stable evidence already exists,
  - add more public sample assertions for false-positive suppression,
  - then revisit `SentinelContext.tsx` and bridge lifecycle code only where it blocks mainline delivery.

---

## Round 143 - Mainline Report Schema Wave 2

Time: 2026-05-11 11:47:50 +08:00  
Author: Codex

### Scope

- Continued the mainline-first rollout after Round 142 instead of returning to presentation-only frontend splitting.
- Extended the shared investigation report schema into the next stable surfaces:
  - USB 分析
  - C2 family analysis（CS / VShell family-level reports）
  - 对象导出页（frontend-derived report）
  - 威胁狩猎页（frontend-derived report）
- Strengthened bundled sample regression and mapper coverage for the new report-bearing surfaces.

### Changes

- Backend:
  - Added structured report generation for `USBAnalysis`.
  - Added structured family-level report generation for `C2FamilyAnalysis`.
  - Wired report payloads into USB and C2 analysis responses.
  - Extended backend tests to cover USB report generation and C2 family report generation.
  - Extended bundled public sample regression with USB create-file and delete baseline checks.
- Frontend:
  - Added shared report fields to USB and C2 types/mappers/hooks.
  - Rendered the shared `InvestigationReportPanel` on USB and C2 pages.
  - Added frontend-derived report builders for:
    - `ObjectExport`
    - `ThreatHunting`
  - Rendered the same shared panel on those pages without inventing a second report UI path.
  - Added focused tests for object/threat report builders plus updated USB/C2 mapper tests.
- Stability:
  - Fixed a flaky MISC payload test path by extending the module expansion wait window so the full frontend CI suite remains deterministic under heavier concurrency.

### Validation

- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.
- `cd frontend && pnpm run ci` - passed.
- Frontend full suite result after this round:
  - 173 test files
  - 484 tests passed

### Review

- This wave makes the shared report contract feel like a real cross-module investigation layer rather than a protocol-only experiment.
- Mainline progress is now visible in two dimensions:
  - more modules expose the same reviewable report structure,
  - more public sample baselines are executable instead of only documented.
- Threat Hunting and Object Export currently derive reports on the frontend because they already consume stable list-shaped results; this keeps the UI contract unified without forcing unnecessary backend shape churn in the same round.
- Recommended next direction:
  - align shared report + unified evidence more tightly,
  - extend benign and false-positive sample gates for object / HTTP / USB / hunting,
  - then revisit high-coupling state/bridge areas only where they block mainline feature delivery.

---

## Round 144 - Evidence/Report Convergence and Benign Baselines

Time: 2026-05-11 11:56:18 +08:00  
Author: Codex

### Scope

- Tightened the connection between unified Evidence and the shared investigation report contract.
- Added more benign/public sample regression around threat-hunting quiet baselines and object extraction baselines.
- Kept the work mainline-oriented: no new presentation-only page splits.

### Changes

- Frontend:
  - Added `frontend/src/app/features/evidence/evidenceInvestigationReport.ts` so unified evidence records can be summarized into the shared `摘要 / 证据 / 明细 / 建议` report shape.
  - Added `frontend/src/app/features/evidence/useEvidencePanelModel.ts` so Evidence page orchestration stays thin while still deriving filtered rows, severity counts, export actions, and the shared report.
  - Updated `frontend/src/app/pages/EvidencePanel.tsx` to render `InvestigationReportPanel` above the evidence table.
  - Added `frontend/src/app/features/evidence/evidenceInvestigationReport.test.ts` and updated `EvidencePanel.test.tsx` to cover the new report layer.
- Backend:
  - Extended bundled public sample regression with:
    - benign HTTP threat-hunting quiet baseline,
    - object extraction baseline on public HTTP/JPEG traffic,
    - existing USB baseline checks retained.
  - Continued to keep regression coverage inside `backend/internal/engine/public_protocol_sample_test.go`.
- Test stability:
  - Evidence page tests now account for duplicate summary text appearing both in the report panel and the evidence table, which is expected after convergence.

### Validation

- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.
- `cd frontend && pnpm run ci` - passed.
- Frontend full suite result after this round:
  - 174 test files
  - 485 tests passed

### Review

- Evidence is no longer only a flat searchable/exportable list; it now also exposes the same investigation-oriented summary language as protocol, industrial, vehicle, USB, C2, object, and hunting surfaces.
- This is the clearest convergence point so far between:
  - unified cross-module evidence,
  - packet-linked report summaries,
  - benign/public sample regression.
- Next preferred direction:
  - add transport-boundary contract checks for report/evidence payloads,
  - continue expanding benign sample assertions for object and hunting edge cases,
  - only then revisit state/bridge refactors when they block the next mainline feature slice.

---

## Round 145 - Transport Contract Lock and CI Stability Hardening

Time: 2026-05-11 16:35:51 +08:00  
Author: Codex

### Scope

- Continued the next autonomous mainline round after Evidence/report convergence.
- Focused on two bounded follow-up tasks:
  - lock report/evidence payload contracts at transport boundaries,
  - harden the slowest frontend CI tests so autonomous iteration can keep using full `pnpm run ci` as a dependable gate.

### Changes

- Transport contract tests:
  - Added `frontend/src/app/integrations/clients/analysisClient.test.ts`.
  - Verified that transport JSON payloads preserve report-bearing shapes for:
    - USB analysis
    - C2 family analysis
    - Evidence module filtering
  - Extended `frontend/src/app/integrations/desktopBridge.test.ts` so fallback-only desktop bridge paths also preserve evidence payloads.
- CI stability:
  - Increased timeout headroom for the slowest MISC payload/session tests under full-suite contention.
  - Slightly relaxed the `MiscTools.test.tsx` size budget in `frontend/scripts/check-size.mjs` because the file now includes explicit stability-oriented assertions and per-test timeout guards, while still remaining bounded and focused on payload workflows.
- Validation discipline:
  - Re-ran frontend full CI until the updated timeout/budget settings proved stable under the complete suite instead of only under focused test runs.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations/clients/analysisClient.test.ts src/app/integrations/desktopBridge.test.ts` - passed.
- `cd frontend && pnpm run typecheck` - passed.
- `cd frontend && pnpm run ci` - passed.
- Current frontend full-suite result after this round:
  - 175 test files
  - 487 tests passed

### Review

- This round did not expand product surface area; it tightened delivery safety.
- The important gain is that shared report/evidence payloads are now better defended exactly where drift usually appears first: transport and mapper boundaries.
- With the MISC slow tests hardened, autonomous iteration can keep using full frontend CI without repeatedly getting derailed by timeout-only failures unrelated to the current feature slice.
- Next preferred autonomous target:
  - continue benign/false-positive baseline expansion for object/hunting/USB,
  - or tighten bridge-surface contract coverage one layer higher at `createHttpBridge` aggregation boundaries if that becomes the sharper risk.

---

## Round 146 - Benign Baseline Calibration for USB and Object Paths

Time: 2026-05-11 16:41:07 +08:00  
Author: Codex

### Scope

- Continued the autonomous regression-expansion track after transport contract hardening.
- Focused on tightening benign/public baseline expectations for USB and object extraction without expanding product surface area.

### Changes

- Backend public-sample regression updates in `backend/internal/engine/public_protocol_sample_test.go`:
  - Added a USB mount-baseline assertion using `usb/usb_memory_stick.pcap`.
  - Calibrated the assertion to the real sample behavior: mount/normal storage traffic may still contain write-like operations, but must stay below high/critical severity in unified USB evidence.
  - Added an object gzip baseline assertion using `object/http_gzip.cap` to ensure public HTTP object extraction does not drift into executable classification.
- Stability retained from the previous autonomous round:
  - transport/client contract tests remain active,
  - frontend full CI remains green after the MISC timeout/budget hardening.

### Validation

- `cd backend && go test ./internal/engine/...` - passed.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.
- Latest known frontend full CI from the immediately preceding autonomous round remains passed:
  - 175 test files
  - 487 tests passed

### Review

- This round improves an important nuance in baseline work: not every non-benign-looking write-like artifact should be modeled as zero activity; some public traces include ordinary housekeeping writes, so the safer invariant is bounded severity rather than forced emptiness.
- The object gzip baseline now adds one more guard against false executable classification drift in lightweight HTTP object captures.
- Next preferred autonomous target:
  - continue expanding benign/false-positive baselines for hunting/object/USB edge cases,
  - or add one higher-level `createHttpBridge` aggregation contract check if transport composition becomes the sharper risk.

---

## Round 147 - Object/Hunting Client Contracts and Additional Benign Samples

Time: 2026-05-11 17:16:52 +08:00  
Author: Codex

### Scope

- Continued the autonomous regression-first path with two small guardrails:
  - transport-client contract coverage for object/hunting paths,
  - another benign/public baseline expansion for hunting and object extraction.

### Changes

- Frontend transport client coverage:
  - Added `frontend/src/app/integrations/clients/objectClient.test.ts`.
  - Added `frontend/src/app/integrations/clients/huntingClient.test.ts`.
  - Verified request paths, payload encoding, response mapping, and download side effects for object and hunting transport clients.
- Backend benign/public baseline coverage:
  - Added benign SMTP threat-hunting quiet baseline.
  - Added a TFTP object baseline that confirms no fabricated executable classification if objects are present.
  - Kept the earlier gzip/JPEG object baselines and USB severity calibration intact.
- No product-surface expansion this round; changes stayed inside regression and contract guardrails.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations/clients/objectClient.test.ts src/app/integrations/clients/huntingClient.test.ts` - passed.
- `cd backend && go test ./internal/engine/...` - passed.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- Object and hunting now have the same kind of transport-boundary defense already added for analysis/evidence paths, reducing the risk that future mapper or request-shape drift silently breaks mainline investigative workflows.
- The TFTP object baseline showed a useful calibration detail: some public traces do not necessarily produce extracted objects under the current heuristic, so the safe invariant is “no fabricated executable classification” rather than “must always extract.”
- Next preferred autonomous target:
  - continue false-positive calibration for hunting/object/USB edge cases,
  - or move one level higher to explicit `createHttpBridge` aggregation composition contract tests if transport wiring becomes the sharper risk.

---

## Round 148 - HttpBridge Aggregation Contracts and Edge-Case Baselines

Time: 2026-05-11 17:20:24 +08:00  
Author: Codex

### Scope

- Continued the autonomous mainline loop without switching back to broad structural refactors.
- Focused on:
  - one higher-level transport composition guardrail at `createHttpBridge`,
  - another small benign/public baseline expansion for object/hunting edges.

### Changes

- Frontend transport aggregation coverage:
  - Added `frontend/src/app/integrations/httpBridgeAggregation.test.ts`.
  - Verified that aggregated bridge composition preserves delegation for:
    - USB analysis
    - C2 analysis
    - filtered unified evidence
    - object listing / download
    - hunting hit listing
    - event subscription wiring
- Backend benign/public baseline coverage:
  - Added benign SMTP threat-hunting quiet baseline.
  - Added a TFTP object baseline that enforces a bounded invariant: no fabricated executable classification when objects are present, without assuming the sample must always yield extracted objects under the current heuristic.
- Validation discipline:
  - Re-ran full frontend CI after adding aggregation-level tests to ensure the transport-guardrail layer stays compatible with the hardened autonomous workflow.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations/httpBridgeAggregation.test.ts` - passed.
- `cd frontend && pnpm run ci` - passed.
- `cd backend && go test ./internal/engine/...` - passed.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.
- Frontend full-suite result after this round:
  - 178 test files
  - 493 tests passed

### Review

- This round closes a useful gap: report/evidence transport contracts are now checked both at lower-level clients and at the aggregated bridge composition layer used by the app.
- The new SMTP/TFTP baselines continue the same philosophy used in earlier USB/object calibration: prefer realistic bounded expectations over idealized “must always extract” or “must be fully silent” assumptions.
- Next preferred autonomous target:
  - keep extending false-positive edge calibration for object/hunting/USB paths,
  - or, if transport wiring remains stable, shift attention toward another evidence/report contract seam with similar bounded regression value.

---

## Round 149 - BridgeFactory Guardrail and Additional Benign Calibration

Time: 2026-05-11 17:59:51 +08:00  
Author: Codex

### Scope

- Continued autonomous iteration without stopping, selecting one more small anti-drift slice:
  - harden the top-level bridge factory composition contract,
  - extend benign/public baseline calibration for MySQL hunting quiet paths and object evidence severity.

### Changes

- Frontend contract coverage:
  - Extended `frontend/src/app/integrations/bridgeFactory.test.ts`.
  - The bridge factory test now verifies that when desktop binding exists, the composed desktop bridge receives an http fallback that still exposes core mainline investigative entrypoints such as:
    - `getEvidenceWithFilter`
    - `listObjects`
    - `listThreatHits`
- Backend benign/public baseline coverage:
  - Added a benign MySQL threat-hunting quiet baseline using `samples/public-pcaps/benign/mysql_complete.pcap`.
  - Added a public JPEG object-evidence baseline asserting object evidence remains informational severity on that benign sample.
- Validation continuity:
  - Kept the earlier transport-client, http-bridge aggregation, and MISC CI-stability guardrails intact while re-running full validation.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations/bridgeFactory.test.ts` - passed.
- `cd frontend && pnpm run ci` - passed.
- `cd backend && go test ./internal/engine/...` - passed.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.
- Frontend full-suite result after this round:
  - 178 test files
  - 494 tests passed

### Review

- The transport stack now has another useful composition-level invariant: the final bridge wiring keeps the mainline evidence/object/hunting capability surface intact even when wrapped for desktop use.
- The new MySQL and JPEG baselines continue the same calibration style already established for HTTP/SMTP/USB/TFTP:
  - benign samples may still produce structured outputs,
  - but they must not drift into inappropriate hunting hits or elevated evidence severity.
- Next preferred autonomous target:
  - continue false-positive calibration for remaining object/hunting/USB edge cases,
  - or locate the next highest-value contract seam adjacent to unified evidence/report composition.

---

## Round 150 - Object Evidence Severity Calibration

Time: 2026-05-11 19:29:41 +08:00  
Author: Codex

### Scope

- Continued autonomous mainline work by tightening one concrete evidence/report seam instead of expanding UI surface area.
- Focused on calibrating object evidence severity so executable objects stand out more clearly while benign image/object baselines stay informational.

### Changes

- Backend:
  - Updated `backend/internal/engine/evidence.go` so object evidence is no longer uniformly `info`.
  - Added object evidence profiling based on MIME / magic heuristics:
    - executable objects -> medium severity with confidence
    - archive/document objects -> informational/low-signal handling
    - benign image/text objects -> informational
  - Added caveat text so elevated object evidence still explicitly requires source/magic/context review.
- Tests:
  - Updated `backend/internal/engine/evidence_test.go` to verify executable object evidence now carries calibrated severity/tags/confidence.
  - Added a benign image object evidence test to ensure JPEG-style objects remain informational.
- Validation:
  - Re-ran focused and full backend validation after the severity calibration.

### Validation

- `cd backend && go test ./internal/engine -run TestGatherEvidence -count=1` - passed.
- `cd backend && go test ./internal/engine -run TestBundledPublic -count=1 -v` - passed.
- `go test -tags dev ./...` - passed.
- `cd backend && go test ./...` - passed.

### Review

- This round improves the usefulness of unified object evidence without overreacting to benign file captures.
- The calibration now better matches investigator expectations:
  - executable objects are more visible in the mainline evidence view,
  - JPEG/text-style objects still remain informational,
  - caveats preserve the rule that extracted objects are not self-proving malicious.
- Next preferred autonomous target:
  - keep calibrating remaining object/hunting/USB false-positive edges,
  - or tighten one more evidence/report composition contract if a bounded seam offers better anti-drift value.

---

## Round 151 - CI Gates, Backend Skeleton Split, and Frontend Boundaries

Time: 2026-05-11 20:45:20 +08:00  
Author: Codex

### Scope

- Implemented the engineering evaluation plan as executable guardrails instead of another UI-only split.
- Focused on:
  - backend CI/check-all gate expansion,
  - backend architecture boundary checks,
  - frontend import-boundary checks,
  - backend evidence/report skeleton split,
  - Evidence / Investigation Report contract coverage.

### Changes

- CI and local checks:
  - Added root `go test -tags dev ./...` to GitHub Actions backend job.
  - Added backend architecture boundary and focused contract test steps to CI.
  - Updated `scripts/check-all.ps1` so local checks mirror CI gates.
  - Added `pnpm run boundary:check` to frontend CI.
- Backend architecture:
  - Added `backend/internal/architecture` boundary tests for model, transport, report builder, and evidence file dependencies.
  - Removed direct `tshark` imports from transport by routing TShark status/config access through `engine.Service`.
  - Split `analysis_report.go` into domain report builders and shared helpers; each report file is now below the 250-line target.
  - Split `evidence.go` into aggregation, collectors, and object/USB/vehicle/shared rule files; each evidence file is now below the 250-line target.
- Frontend architecture:
  - Added `frontend/scripts/check-boundaries.mjs`.
  - Enforced pages -> mapper, mapper -> UI/rules, client -> feature/UI, and `components/ui` -> domain-layer import boundaries.
  - Moved shared evidence types to `core/types/evidence.ts` so transport clients and mappers no longer depend on feature schema.
- Mainline contract:
  - Added Evidence / Investigation Report alignment coverage for USB and C2 severity plus packet/stream linkage.
  - Aligned report confidence severity thresholds with evidence severity thresholds.
  - Fixed JPEG object magic handling so `jpeg` no longer matches executable `pe` heuristics.

### Validation

- `cd backend && go test ./internal/architecture -run TestBackendArchitectureBoundaries -count=1 -v` passed.
- `cd backend && go test ./internal/engine -run "TestGatherEvidence|Test.*InvestigationReport|TestBundledPublic" -count=1 -v` passed.
- `go test -tags dev ./...` passed.
- `cd backend && go test ./...` passed.
- `cd frontend && pnpm run boundary:check` passed.
- `cd frontend && pnpm run ci` passed, 178 test files / 494 tests.
- `./scripts/check-all.ps1` passed with the new backend/frontend boundary gates.

### Review

- This round turns the evaluation rubric into enforceable checks:
  - backend has CI-visible dev-tag, boundary, and contract gates,
  - frontend has CI-visible import boundary checks,
  - evidence/report severity drift now has a focused regression test,
  - large backend rule files have been split below the agreed size target.
- MISC remains outside unified Evidence.
- Ignored reports, samples, build outputs, and frontend dist artifacts remained unstaged.

---

## Round 152 - Bridge Domain Type Split

Time: 2026-05-11 22:03:24 +08:00  
Author: Codex

### Scope

- Started the new optimization plan from the BackendBridge abstraction problem.
- Split the monolithic `BackendBridge` type into domain client interfaces while preserving the existing aggregate `BackendBridge` compatibility surface.
- Kept runtime behavior unchanged: `createHttpBridge`, `createDesktopBridge`, `createBridge`, and the exported `bridge` object still satisfy the same aggregate contract.
- Did not change backend APIs, transport implementation, request/response shapes, MISC/Evidence boundaries, or `useSentinel()` public contract.

### Changes

- Added domain-level frontend bridge interfaces in `frontend/src/app/integrations/bridgeTypes.ts`:
  - `RuntimeClient`
  - `CaptureClient`
  - `PacketClient`
  - `HuntingClient`
  - `ObjectClient`
  - `StreamClient`
  - `AnalysisClient`
  - `EvidenceClient`
  - `MediaClient`
  - `VehicleDBCClient`
  - `PluginClient`
  - `SecurityMaterialClient`
  - `MiscModuleClient`
- Re-declared `BackendBridge` as the composition of those domain interfaces.
- This establishes the type boundary needed for later page-by-page migration away from full backend capability access.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations/bridgeFactory.test.ts src/app/integrations/desktopBridge.test.ts src/app/integrations/httpBridgeAggregation.test.ts` passed, 3 files / 8 tests.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run boundary:check` passed.
- `cd frontend && pnpm run size:check` passed.
- `cd frontend && pnpm run ci` passed, 178 test files / 494 tests.

### Review

- This is the first bridge-abstraction slice from the new plan: implementation files were already split, and now the public type surface has domain seams.
- No call sites were migrated yet; that is intentional. The aggregate bridge remains intact so later rounds can move consumers safely behind focused domain clients.
- Mainline boundaries stayed intact:
  - MISC remains outside unified Evidence.
  - `useSentinel()` public shape is unchanged.
  - Backend APIs and frontend response models are unchanged.
  - Mapper files were not touched.
- Next target: add explicit domain-client projection helpers so pages/hooks can start depending on narrowed clients without receiving the full `BackendBridge`.

---

## Round 153 - Bridge Domain Projection Helpers

Time: 2026-05-11 22:11:47 +08:00  
Author: Codex

### Scope

- Continued the bridge-abstraction plan by adding a concrete projection layer over the compatibility bridge.
- Introduced a `BackendClients` shape and a `createBackendClients()` helper so domain-facing code can consume narrowed clients instead of the full `BackendBridge` directly.
- Kept all existing bridge behavior unchanged; the new helper is a pure projection over the same compatibility bridge object.

### Changes

- Added `frontend/src/app/integrations/bridgeDomains.ts` with `createBackendClients(bridge)`.
- Exported a new `backendClients` projection from `frontend/src/app/integrations/wailsBridge.ts`.
- Extended `frontend/src/app/integrations/bridgeTypes.ts` with `BackendClients` to make the domain projection explicit.
- Added a focused regression test in `frontend/src/app/integrations/bridgeDomains.test.ts` to confirm the projection preserves object identity for each domain client.
- Tightened `frontend/scripts/check-size.mjs` with a budget for the new projection helper.

### Validation

- `cd frontend && pnpm exec vitest run src/app/integrations/bridgeDomains.test.ts src/app/integrations/wailsBridge.test.ts src/app/integrations/bridgeFactory.test.ts` passed, 3 files / 11 tests.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run boundary:check` passed.
- `cd frontend && pnpm run size:check` passed.

### Review

- This round does not migrate any page yet; it creates the seam that later page and hook migrations can use.
- The aggregate bridge remains compatible, but the new projection layer makes the intended domain dependency model explicit and testable.
- Mainline boundaries stayed intact:
  - `useSentinel()` public shape is unchanged.
  - MISC remains outside unified Evidence.
  - Backend APIs and frontend response models are unchanged.
  - Mapper files were not touched.
- Next target: start migrating one low-risk consumer to a domain client projection, likely runtime or evidence, before touching high-coupling workspace/capture flows.

---

## Round 154 - Evidence Hook Domain Client Migration

Time: 2026-05-11 23:30:54 +08:00  
Author: Codex

### Scope

- Continued the bridge domain migration with a low-risk evidence consumer.
- Moved `useEvidence()` from the full compatibility `bridge` to the narrowed `backendClients.evidence` projection.
- Kept the hook API, cache behavior, request cancellation behavior, and evidence endpoint contract unchanged.

### Changes

- Updated `frontend/src/app/features/evidence/useEvidence.ts` to call `backendClients.evidence.getEvidenceWithFilter(...)`.
- Updated `frontend/src/app/pages/EvidencePanel.test.tsx` to mock the narrowed evidence client instead of the aggregate bridge.

### Validation

- `cd frontend && pnpm exec vitest run src/app/pages/EvidencePanel.test.tsx src/app/integrations/bridgeDomains.test.ts` passed, 2 files / 3 tests.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run boundary:check` passed.
- `cd frontend && pnpm run size:check` passed.

### Review

- This round intentionally migrates only one consumer to keep the dependency shift easy to inspect.
- Evidence loading now depends on an explicit evidence-domain client, reducing accidental access to unrelated bridge methods.
- Mainline boundaries stayed intact:
  - `useSentinel()` public shape is unchanged.
  - MISC remains outside unified Evidence.
  - Backend APIs and frontend response models are unchanged.
  - Mapper files were not touched.
- Next target: migrate another isolated feature hook or page to a narrow client, preferably one with a single-domain method set and existing tests.

---

## Round 155 - Object Export Domain Client Migration

Time: 2026-05-11 23:40:05 +08:00  
Author: Codex

### Scope

- Continued the bridge domain migration with the object-export surface.
- Moved object listing and zip download calls from the aggregate `bridge` to `backendClients.object`.
- Kept object filtering, grouping, report generation, fallback loading, and download behavior unchanged.

### Changes

- Updated `frontend/src/app/features/object/useObjectExport.ts` to call `backendClients.object.listObjects()`.
- Updated `frontend/src/app/pages/ObjectExport.tsx` to call `backendClients.object.downloadObjectsZip(...)`.

### Validation

- `cd frontend && pnpm exec vitest run src/app/features/object/objectExportRules.test.ts src/app/features/object/objectInvestigationReport.test.ts src/app/integrations/bridgeDomains.test.ts` passed, 3 files / 5 tests.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run boundary:check` passed.
- `cd frontend && pnpm run size:check` passed.

### Review

- This round stays within one domain and avoids touching capture or stream state ownership.
- Object export now advertises its dependency on object-only backend methods instead of receiving the full bridge surface.
- Mainline boundaries stayed intact:
  - `useSentinel()` public shape is unchanged.
  - MISC remains outside unified Evidence.
  - Backend APIs and frontend response models are unchanged.
  - Mapper files were not touched.
- Next target: continue migrating isolated feature hooks (`media`, `traffic`, or `analysis`) while avoiding high-coupling lifecycle paths until more domain consumers are narrowed.

---

## Round 156 - Media Analysis Domain Client Migration

Time: 2026-05-12 00:00:27 +08:00  
Author: Codex

### Scope

- Continued the bridge domain migration with the media analysis loading hook.
- Moved the media analysis request from the aggregate `bridge` to `backendClients.media`.
- Kept media cache keys, preload gating, abort handling, loading state, and error behavior unchanged.

### Changes

- Updated `frontend/src/app/features/media/useMediaAnalysis.ts` to call `backendClients.media.getMediaAnalysis(false, signal)`.

### Validation

- `cd frontend && pnpm exec vitest run src/app/features/media/MediaOverviewPanels.test.tsx src/app/features/media/MediaSessionCells.test.tsx src/app/features/media/MediaSessionTableUtils.test.ts src/app/integrations/bridgeDomains.test.ts` passed, 4 files / 13 tests.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run boundary:check` passed.
- `cd frontend && pnpm run size:check` passed.

### Review

- This round intentionally migrated only the media analysis loader, not playback or transcription workflows, because those mix media calls with runtime dependency checks.
- Media analysis now declares a media-domain dependency without exposing unrelated bridge methods to the hook.
- Mainline boundaries stayed intact:
  - `useSentinel()` public shape is unchanged.
  - MISC remains outside unified Evidence.
  - Backend APIs and frontend response models are unchanged.
  - Mapper files were not touched.
- Next target: migrate another isolated analysis hook, or split mixed media workflows between `backendClients.media` and `backendClients.runtime` once the lower-risk single-domain hooks are complete.

---

## Round 157 - Industrial Analysis Domain Client Migration

Time: 2026-05-12 00:08:03 +08:00  
Author: Codex

### Scope

- Continued the bridge domain migration with the industrial analysis loading hook.
- Moved the industrial analysis request from the aggregate `bridge` to `backendClients.analysis`.
- Kept industrial cache keys, preload gating, abort handling, loading state, report data, and error behavior unchanged.

### Changes

- Updated `frontend/src/app/features/industrial/useIndustrialAnalysis.ts` to call `backendClients.analysis.getIndustrialAnalysis(signal)`.
- Updated `frontend/src/app/pages/IndustrialAnalysis.test.tsx` to mock the narrowed analysis client instead of the aggregate bridge.

### Validation

- Initial targeted validation caught the old test mock shape, confirming the migration path needed test coverage updates.
- `cd frontend && pnpm exec vitest run src/app/pages/IndustrialAnalysis.test.tsx src/app/integrations/bridgeDomains.test.ts` passed after updating the mock, 2 files / 2 tests.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run boundary:check` passed.
- `cd frontend && pnpm run size:check` passed.

### Review

- This round intentionally migrated one analysis hook rather than all analysis hooks together, keeping any regression isolated to the industrial surface.
- Industrial analysis now declares an analysis-domain dependency without exposing unrelated bridge methods.
- Mainline boundaries stayed intact:
  - `useSentinel()` public shape is unchanged.
  - MISC remains outside unified Evidence.
  - Backend APIs and frontend response models are unchanged.
  - Mapper files were not touched.
- Next target: continue with another single-method analysis hook such as USB, APT, or vehicle, then reserve Round 160 for the required 10-round self-audit.

---

## Round 158 - USB Analysis Domain Client Migration

Time: 2026-05-12 00:23:32 +08:00  
Author: Codex

### Scope

- Continued the bridge domain migration with the USB analysis loading hook.
- Moved the USB analysis request from the aggregate `bridge` to `backendClients.analysis`.
- Kept USB cache keys, preload gating, abort handling, loading state, tab behavior, and error behavior unchanged.

### Changes

- Updated `frontend/src/app/features/usb/useUsbAnalysis.ts` to call `backendClients.analysis.getUSBAnalysis(signal)`.
- Updated `frontend/src/app/pages/UsbAnalysis.test.tsx` to mock the narrowed analysis client instead of the aggregate bridge.

### Validation

- `cd frontend && pnpm exec vitest run src/app/pages/UsbAnalysis.test.tsx src/app/features/usb/UsbTablesSplit.test.tsx src/app/integrations/bridgeDomains.test.ts` passed, 3 files / 8 tests.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run boundary:check` passed.
- `cd frontend && pnpm run size:check` passed.

### Review

- This round keeps the same one-hook migration pattern used for media and industrial analysis.
- USB analysis now declares an analysis-domain dependency without exposing unrelated bridge methods.
- Mainline boundaries stayed intact:
  - `useSentinel()` public shape is unchanged.
  - MISC remains outside unified Evidence.
  - Backend APIs and frontend response models are unchanged.
  - Mapper files were not touched.
- Next target: migrate APT or vehicle analysis hook, then reserve Round 160 for the required 10-round self-audit and drift check.

---

## Round 159 - APT Analysis Domain Client Migration

Time: 2026-05-12 00:43:37 +08:00  
Author: Codex

### Scope

- Continued the bridge domain migration with the APT analysis loading hook.
- Moved the APT analysis request from the aggregate `bridge` to `backendClients.analysis`.
- Kept APT cache keys, preload gating, abort handling, active actor selection, navigation helpers, and error behavior unchanged.

### Changes

- Updated `frontend/src/app/features/apt/useAPTAnalysis.ts` to call `backendClients.analysis.getAPTAnalysis(signal)`.
- Updated `frontend/src/app/pages/AptAnalysis.test.tsx` to mock the narrowed analysis client instead of the aggregate bridge.

### Validation

- `cd frontend && pnpm exec vitest run src/app/pages/AptAnalysis.test.tsx src/app/integrations/bridgeDomains.test.ts` passed, 2 files / 3 tests.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run boundary:check` passed.
- `cd frontend && pnpm run size:check` passed.

### Review

- This round keeps the analysis-hook migration sequence narrow and reversible.
- APT analysis now declares an analysis-domain dependency without exposing unrelated bridge methods.
- Mainline boundaries stayed intact:
  - `useSentinel()` public shape is unchanged.
  - MISC remains outside unified Evidence.
  - Backend APIs and frontend response models are unchanged.
  - Mapper files were not touched.
- Next target: Round 160 self-audit and drift check, then continue the remaining vehicle/mixed-domain bridge migrations if the audit confirms alignment.

---

## Round 160 - Ten-Round Self-Audit

Time: 2026-05-12 00:46:40 +08:00  
Author: Codex

### Scope

- Performed the required 10-round self-audit to check for plan drift.
- Reviewed the latest 10 commits, current working tree state, remaining aggregate `bridge` imports, and adopted `backendClients.*` consumers.
- No production behavior changes were made in this round.

### Audit Findings

- Recent commits remain aligned with the current plan:
  - Split aggregate bridge types into domain interfaces.
  - Added domain client projections.
  - Migrated low-risk evidence, object, media, industrial, USB, and APT consumers to narrowed domain clients.
  - Kept each migration small, tested, and reversible.
- No drift detected toward unrelated UI redesign, backend API changes, mapper rewrites, or MISC/Evidence coupling.
- Current direct `bridge` imports in `frontend/src` are down to 28 files.
- Current `backendClients.*` production consumers are 7 files:
  - `useEvidence.ts`
  - `useObjectExport.ts`
  - `ObjectExport.tsx`
  - `useMediaAnalysis.ts`
  - `useIndustrialAnalysis.ts`
  - `useUsbAnalysis.ts`
  - `useAPTAnalysis.ts`

### Validation

- `git status --short` was clean before the audit report edit.
- `git log --oneline -10` confirmed recent commits are bridge-domain and boundary-related.
- `grep` checks confirmed the remaining direct bridge import list and current domain-client adoption list.

### Review

- Continue the same migration direction.
- Preferred next low-risk target: `frontend/src/app/features/vehicle/useVehicleAnalysis.ts` using `backendClients.analysis.getVehicleAnalysis(signal)`.
- After remaining single-domain hooks are migrated, move to mixed-domain workflows carefully:
  - media playback/transcription should split between `backendClients.media` and `backendClients.runtime`.
  - stream decoder/payload workflows should use `backendClients.stream`.
  - lifecycle/capture state should be delayed until simpler consumers are complete.
- Mainline boundaries remain intact:
  - `useSentinel()` public shape is unchanged.
  - MISC remains outside unified Evidence.
  - Backend APIs and frontend response models are unchanged.
  - Mapper files were not touched.

---

## Round 161 - Vehicle Analysis Hook Domain Client Migration

Time: 2026-05-12 00:48:39 +08:00  
Author: Codex

### Scope

- Continued the bridge domain migration after the Round 160 self-audit confirmed alignment.
- Moved the vehicle analysis hook request from the aggregate `bridge` to `backendClients.analysis`.
- Kept vehicle cache keys, DBC-aware cache invalidation, preload gating, abort handling, loading state, and error behavior unchanged.

### Changes

- Updated `frontend/src/app/features/vehicle/useVehicleAnalysis.ts` to call `backendClients.analysis.getVehicleAnalysis(signal)`.
- Left `frontend/src/app/pages/VehicleAnalysis.tsx` DBC operations on the aggregate bridge for now because the page mixes analysis, DBC profile persistence, and desktop file-pick behavior.

### Validation

- `cd frontend && pnpm exec vitest run src/app/pages/VehicleAnalysis.test.ts src/app/integrations/bridgeDomains.test.ts` passed, 2 files / 3 tests.
- `cd frontend && pnpm run typecheck` passed.
- `cd frontend && pnpm run boundary:check` passed.
- `cd frontend && pnpm run size:check` passed.

### Review

- This round intentionally migrated only the vehicle hook's analysis call and did not mix in DBC page operations.
- Vehicle analysis now declares an analysis-domain dependency without exposing unrelated bridge methods to the hook.
- Mainline boundaries stayed intact:
  - `useSentinel()` public shape is unchanged.
  - MISC remains outside unified Evidence.
  - Backend APIs and frontend response models are unchanged.
  - Mapper files were not touched.
- Next target: begin mixed-domain migrations cautiously, starting with small pages/hooks where method ownership is clear (`VehicleAnalysis.tsx` DBC calls, media playback/transcription, or stream payload tools).
