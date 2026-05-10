import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const sourceSizeBudgets = [
  {
    path: "src/app/integrations/wailsBridge.ts",
    maxLines: 380,
    reason: "bridge facade should keep shrinking as domain clients move out",
  },
  {
    path: "src/app/integrations/mappers/c2DecryptDisplayMapper.ts",
    maxLines: 110,
    reason: "C2 decrypt display mapper should stay focused on result-level record filtering and notes",
  },
  {
    path: "src/app/integrations/mappers/vshellDecryptDisplayRules.ts",
    maxLines: 305,
    reason:
      "VShell decrypt display rules should keep preview decoding, ANSI cleanup, timestamp hiding, and low-info frame checks isolated",
  },
  {
    path: "src/app/state/SentinelContext.tsx",
    maxLines: 910,
    reason: "provider remains oversized and should keep moving task reset, packet, stream, and capture domains out",
  },
  {
    path: "src/app/state/sentinelDerivedView.ts",
    maxLines: 45,
    reason:
      "sentinel derived view helper should keep selected packet, protocol tree, hex, and pagination derivation only",
  },
  {
    path: "src/app/state/hooks/useSelectedPacketResources.ts",
    maxLines: 70,
    reason: "selected packet resources hook should only compose detail, raw hex, and layers artifact loading",
  },
  {
    path: "src/app/state/captureClearState.ts",
    maxLines: 140,
    reason: "capture clear state helper should stay focused on UI, preload, stream runtime, and metadata clearing",
  },
  {
    path: "src/app/state/captureStartState.ts",
    maxLines: 75,
    reason:
      "capture start state helper should stay focused on preload reset, parse runtime, and pending transaction setup",
  },
  {
    path: "src/app/state/captureStartBackend.ts",
    maxLines: 125,
    reason:
      "capture start backend helper should keep opened-capture resolution, replacement init, and backend start task",
  },
  {
    path: "src/app/state/capturePreloadProbe.ts",
    maxLines: 185,
    reason:
      "capture preload probe should keep first-page validation, polling, stale guards, and timeout errors together",
  },
  {
    path: "src/app/state/captureCommitState.ts",
    maxLines: 125,
    reason:
      "capture commit state helper should stay focused on packet, stream, file meta, and first page commit effects",
  },
  {
    path: "src/app/state/captureFinalizeWorkflow.ts",
    maxLines: 140,
    reason: "capture finalize workflow should keep validated commit, stream refresh, and done status outside provider",
  },
  {
    path: "src/app/state/formatBytes.ts",
    maxLines: 10,
    reason: "byte formatting helper should remain a tiny shared compatibility utility",
  },
  {
    path: "src/app/state/captureReplacementPrepare.ts",
    maxLines: 55,
    reason: "capture replacement prepare should keep pre-replacement reset and backend cleanup outside the provider",
  },
  {
    path: "src/app/state/captureStopWorkflow.ts",
    maxLines: 70,
    reason: "capture stop workflow should keep frontend cleanup and backend close orchestration outside the provider",
  },
  {
    path: "src/app/state/captureTaskReset.ts",
    maxLines: 60,
    reason:
      "capture task reset helper should stay focused on invalidating frontend capture work and clearing pending loads",
  },
  {
    path: "src/app/state/packetPageLoad.ts",
    maxLines: 85,
    reason:
      "packet page loading helper should keep request lifecycle, stale guards, and error mapping outside the provider",
  },
  {
    path: "src/app/state/packetPageCommit.ts",
    maxLines: 75,
    reason: "packet page commit helper should stay focused on cursor, page, selected packet, and page flags",
  },
  {
    path: "src/app/state/packetPageNavigation.ts",
    maxLines: 70,
    reason: "packet page navigation should keep next, previous, jump, and retry cursor actions outside the provider",
  },
  {
    path: "src/app/state/packetFilterWorkflow.ts",
    maxLines: 90,
    reason:
      "packet filter workflow should keep sequence guards, viewport reset, polling, and status finalization outside the provider",
  },
  {
    path: "src/app/state/packetFilterAction.ts",
    maxLines: 55,
    reason: "packet filter action should keep display-filter sync and workflow dispatch outside the provider",
  },
  {
    path: "src/app/state/packetLocateWorkflow.ts",
    maxLines: 95,
    reason:
      "packet locate workflow should keep locate task scope, filter override, page load, and status mapping outside the provider",
  },
  {
    path: "src/app/state/streamIndexRefresh.ts",
    maxLines: 60,
    reason:
      "stream index refresh should keep stream id loading, stale capture guards, and status mapping outside the provider",
  },
  {
    path: "src/app/state/streamPayloadPersist.ts",
    maxLines: 70,
    reason: "stream payload persist should keep backend update and local stream patch commit outside the provider",
  },
  {
    path: "src/app/state/packetStreamPrepare.ts",
    maxLines: 45,
    reason: "packet stream prepare should keep packet location to active stream resolution outside the provider",
  },
  {
    path: "src/app/state/progressStatusWorkflow.ts",
    maxLines: 85,
    reason:
      "progress status workflow should keep media, threat, and capture preload progress updates outside the provider",
  },
  {
    path: "src/app/state/streamAdjacentPrefetch.ts",
    maxLines: 70,
    reason:
      "stream adjacent prefetch should keep target selection and protocol-specific scheduling outside the provider",
  },
  {
    path: "src/app/state/streamSwitchWorkflow.ts",
    maxLines: 115,
    reason: "stream switch workflow should keep cache, fetch, metric, stale, and abort behavior outside the provider",
  },
  {
    path: "src/app/components/StreamDecoderWorkbench.tsx",
    maxLines: 375,
    reason:
      "decoder workbench should keep rendering panes, toolbar, batch controls, settings panels, and pure rules in sibling modules",
  },
  {
    path: "src/app/components/StreamDecoderWorkbenchUtils.ts",
    maxLines: 40,
    reason: "decoder utility compatibility layer should stay as exports only",
  },
  {
    path: "src/app/components/StreamDecoderTypes.ts",
    maxLines: 95,
    reason: "decoder settings and shared types should stay declarative",
  },
  {
    path: "src/app/components/StreamDecoderHintUtils.ts",
    maxLines: 205,
    reason: "decoder hint merging should remain pure and separate from payload or storage helpers",
  },
  {
    path: "src/app/components/StreamDecoderPayloadUtils.ts",
    maxLines: 75,
    reason: "decoder payload normalization should remain pure and small",
  },
  {
    path: "src/app/components/StreamDecoderSettingsStorage.ts",
    maxLines: 45,
    reason: "decoder settings persistence should stay isolated from hint and payload logic",
  },
  {
    path: "src/app/components/StreamDecoderToolbar.tsx",
    maxLines: 80,
    reason: "decoder toolbar should stay focused on decoder actions and settings entry points",
  },
  {
    path: "src/app/components/StreamDecoderBatchPanel.tsx",
    maxLines: 115,
    reason: "decoder batch panel should stay focused on range, progress, and failure display",
  },
  {
    path: "src/app/components/StreamDecoderCandidatePanel.tsx",
    maxLines: 145,
    reason:
      "decoder candidate panel should stay focused on inspection summary, apply mode, and candidate grid orchestration",
  },
  {
    path: "src/app/components/StreamDecoderCandidateCard.tsx",
    maxLines: 115,
    reason: "decoder candidate cards should keep badge, preview, and decoder hint rendering local",
  },
  {
    path: "src/app/components/StreamDecoderSettingsPanel.tsx",
    maxLines: 45,
    reason: "decoder settings panel should stay focused on selecting the active settings section",
  },
  {
    path: "src/app/components/StreamDecoderSettingsSections.tsx",
    maxLines: 240,
    reason: "decoder settings sections should keep webshell-specific form fields and update rules local",
  },
  {
    path: "src/app/components/StreamDecoderWorkbenchParts.tsx",
    maxLines: 20,
    reason: "decoder parts compatibility layer should stay as exports only",
  },
  {
    path: "src/app/components/StreamDecoderControls.tsx",
    maxLines: 185,
    reason: "decoder controls should keep buttons and small form primitives separate from payload rendering",
  },
  {
    path: "src/app/components/StreamDecoderPayloadPane.tsx",
    maxLines: 130,
    reason: "decoder payload pane should stay focused on result display and export actions",
  },
  {
    path: "src/app/components/StreamDecoderPayloadGrid.tsx",
    maxLines: 65,
    reason: "decoder payload grid should stay focused on raw/candidate/result pane composition",
  },
  {
    path: "src/app/components/StreamDecoderWorkbenchHeader.tsx",
    maxLines: 45,
    reason: "decoder workbench header should stay focused on title and toolbar wiring",
  },
  {
    path: "src/app/components/stream/StreamWorkbench.tsx",
    maxLines: 20,
    reason: "stream workbench should stay as a compatibility export layer",
  },
  {
    path: "src/app/components/stream/StreamNavigationControls.tsx",
    maxLines: 210,
    reason: "stream navigation controls should stay focused on stream switching, view mode, and search UI",
  },
  {
    path: "src/app/components/stream/StreamPayloadPanels.tsx",
    maxLines: 20,
    reason: "stream payload panels should stay as a compatibility export layer",
  },
  {
    path: "src/app/components/stream/StreamPayloadHighlight.tsx",
    maxLines: 45,
    reason: "stream payload highlight logic should stay pure and separate from panel layout",
  },
  {
    path: "src/app/components/stream/StreamCurrentChunkPanel.tsx",
    maxLines: 95,
    reason: "stream current chunk panel should stay focused on selected chunk display",
  },
  {
    path: "src/app/components/stream/StreamChunkCard.tsx",
    maxLines: 80,
    reason: "stream chunk card should stay focused on chunk preview and open action wiring",
  },
  {
    path: "src/app/components/stream/StreamPayloadDialog.tsx",
    maxLines: 110,
    reason: "stream payload dialog should stay focused on metadata, copy, export, and full payload display",
  },
  {
    path: "src/app/components/analysis/AnalysisPrimitives.tsx",
    maxLines: 310,
    reason: "analysis primitives should stay focused on small shared cards, badges, charts, and lists",
  },
  {
    path: "src/app/components/analysis/AnalysisDataTable.tsx",
    maxLines: 190,
    reason: "analysis data table should keep generic table rendering separate from primitive cards and charts",
  },
  {
    path: "src/app/pages/C2Analysis.tsx",
    maxLines: 250,
    reason: "C2 page should only orchestrate analysis loading, tabs, and feature-section composition",
  },
  {
    path: "src/app/features/c2/C2DecryptWorkbench.tsx",
    maxLines: 175,
    reason: "C2 decrypt workbench should own decrypt form state and keep result display in sibling components",
  },
  {
    path: "src/app/features/c2/C2DecryptFormControls.tsx",
    maxLines: 250,
    reason: "C2 decrypt form controls should keep key-mode UI and field primitives separate from request orchestration",
  },
  {
    path: "src/app/features/c2/C2BeaconPatternList.tsx",
    maxLines: 45,
    reason: "C2 beacon pattern list should remain a small display component",
  },
  {
    path: "src/app/features/c2/C2CandidateTable.tsx",
    maxLines: 160,
    reason: "C2 candidate table should keep table orchestration separate from detail, action, and pure rules modules",
  },
  {
    path: "src/app/features/c2/C2CandidateTableDetails.tsx",
    maxLines: 80,
    reason: "C2 candidate detail panel should stay focused on expanded record presentation",
  },
  {
    path: "src/app/features/c2/C2CandidateTableRules.ts",
    maxLines: 85,
    reason: "C2 candidate pure rules should stay separate from rendering and action components",
  },
  {
    path: "src/app/features/c2/C2CandidateActions.tsx",
    maxLines: 45,
    reason: "C2 candidate filter actions should stay focused on protocol-specific display filter wiring",
  },
  {
    path: "src/app/pages/UsbAnalysis.tsx",
    maxLines: 205,
    reason: "USB page should only compose analysis loading, primary tabs, and domain panels",
  },
  {
    path: "src/app/features/usb/UsbHidPanel.tsx",
    maxLines: 135,
    reason: "USB HID panel should own keyboard/mouse presentation without reintroducing page orchestration",
  },
  {
    path: "src/app/features/usb/useUsbHidState.ts",
    maxLines: 190,
    reason: "USB HID state hook should own device filters, replay cursor, stats, and derived preview text",
  },
  {
    path: "src/app/features/usb/UsbHidPanels.tsx",
    maxLines: 20,
    reason: "USB HID panels should stay as a compatibility export layer",
  },
  {
    path: "src/app/features/usb/UsbKeyboardReplay.tsx",
    maxLines: 150,
    reason: "USB keyboard replay should keep playback controls and current-event presentation local",
  },
  {
    path: "src/app/features/usb/UsbMouseTrajectory.tsx",
    maxLines: 70,
    reason: "USB mouse trajectory should stay focused on path rendering and legend",
  },
  {
    path: "src/app/features/usb/UsbMouseHeatmap.tsx",
    maxLines: 95,
    reason: "USB mouse heatmap should stay focused on density and click hotspot rendering",
  },
  {
    path: "src/app/features/usb/UsbMouseBehaviorList.tsx",
    maxLines: 45,
    reason: "USB mouse behavior list should stay focused on compact recent-event display",
  },
  {
    path: "src/app/features/usb/UsbHidEmptyState.tsx",
    maxLines: 15,
    reason: "USB HID empty state should remain a tiny shared display helper",
  },
  {
    path: "src/app/features/usb/usbHidRules.ts",
    maxLines: 45,
    reason: "USB HID rules should keep replay token, mouse badges, and point normalization pure",
  },
  {
    path: "src/app/features/usb/UsbOverviewPanel.tsx",
    maxLines: 85,
    reason: "USB overview panel should stay limited to summary cards and primary domain navigation",
  },
  {
    path: "src/app/features/usb/UsbAnalysisControls.tsx",
    maxLines: 130,
    reason: "USB shared controls should stay generic and avoid domain-specific analysis logic",
  },
  {
    path: "src/app/features/usb/UsbMassStoragePanel.tsx",
    maxLines: 120,
    reason: "USB mass-storage panel should keep overview and read/write table wiring scoped",
  },
  {
    path: "src/app/features/usb/UsbOtherPanel.tsx",
    maxLines: 105,
    reason: "USB other-domain panel should stay focused on control/raw record presentation",
  },
  {
    path: "src/app/pages/MediaAnalysis.tsx",
    maxLines: 145,
    reason: "media page should only compose analysis state, workflow hook, and display panels",
  },
  {
    path: "src/app/features/media/useMediaTranscriptionWorkflow.ts",
    maxLines: 310,
    reason:
      "media transcription workflow should own playback, batch polling, dependency dialogs, and copy/export effects",
  },
  {
    path: "src/app/features/media/MediaOverviewPanels.tsx",
    maxLines: 165,
    reason: "media overview panels should stay presentational and avoid playback or transcription side effects",
  },
  {
    path: "src/app/features/media/MediaDisplayPanels.tsx",
    maxLines: 20,
    reason: "media display panel compatibility layer should stay as exports only",
  },
  {
    path: "src/app/features/media/MediaAnalysisProgressPanel.tsx",
    maxLines: 95,
    reason: "media analysis progress panel should stay focused on phase and recent progress display",
  },
  {
    path: "src/app/features/media/BatchTranscriptionStatusPanel.tsx",
    maxLines: 65,
    reason: "media batch transcription status should stay focused on queue progress display",
  },
  {
    path: "src/app/features/media/MediaPlaybackDialog.tsx",
    maxLines: 85,
    reason: "media playback dialog should stay focused on audio and video playback presentation",
  },
  {
    path: "src/app/features/media/MediaDependencyDialogs.tsx",
    maxLines: 80,
    reason: "media dependency dialogs should stay focused on ffmpeg and speech dependency messages",
  },
  {
    path: "src/app/components/ui/sidebar.tsx",
    maxLines: 360,
    reason: "shared sidebar primitive should keep provider state in sidebarContext and avoid feature-specific logic",
  },
  {
    path: "src/app/components/ui/sidebarMenu.tsx",
    maxLines: 250,
    reason: "sidebar menu primitives should stay separate from sidebar shell/provider concerns",
  },
  {
    path: "src/app/components/ui/sidebarContext.tsx",
    maxLines: 160,
    reason: "sidebar context should stay focused on provider state, cookie persistence, and keyboard toggle behavior",
  },
  {
    path: "src/app/pages/VehicleAnalysis.tsx",
    maxLines: 160,
    reason: "vehicle page should only orchestrate DBC state, analysis loading, and feature-section composition",
  },
  {
    path: "src/app/features/vehicle/VehicleProtocolPanels.tsx",
    maxLines: 135,
    reason: "vehicle protocol panels should keep CAN/J1939/DoIP/UDS summaries and security notes presentational",
  },
  {
    path: "src/app/features/vehicle/VehicleDetailPanels.tsx",
    maxLines: 180,
    reason: "vehicle detail panels should keep CAN, DBC, DoIP, and UDS table wiring outside the page",
  },
  {
    path: "src/app/features/vehicle/VehicleOverviewPanel.tsx",
    maxLines: 80,
    reason: "vehicle overview panel should stay limited to summary cards, conversations, and plan hints",
  },
  {
    path: "src/app/features/vehicle/VehicleCanDataBoard.tsx",
    maxLines: 160,
    reason: "vehicle CAN data board should stay focused on grouping and rendering raw CAN payload values",
  },
  {
    path: "src/app/features/vehicle/VehicleDbcPanel.tsx",
    maxLines: 110,
    reason: "vehicle DBC panel should stay focused on profile import and removal UI",
  },
  {
    path: "src/app/features/vehicle/VehicleUdsTransactionsPanel.tsx",
    maxLines: 220,
    reason: "vehicle UDS transaction panel should keep filtering and table rendering local",
  },
  {
    path: "src/app/core/engine.ts",
    maxLines: 10,
    reason: "core engine should remain a compatibility facade over split protocol tree modules",
  },
  {
    path: "src/app/core/protocolTree.ts",
    maxLines: 75,
    reason: "base protocol tree builder should stay separate from tshark layer tree expansion",
  },
  {
    path: "src/app/core/protocolLayerTree.ts",
    maxLines: 320,
    reason: "tshark layer tree builder should stay pure and avoid packet byte layout or display registry growth",
  },
  {
    path: "src/app/core/protocolLayerFormat.ts",
    maxLines: 65,
    reason: "protocol layer formatting helpers should stay pure and separate from tree construction",
  },
  {
    path: "src/app/core/captureOverview.ts",
    maxLines: 80,
    reason: "capture overview should orchestrate split pure rules without absorbing scoring or filter logic",
  },
  {
    path: "src/app/core/captureOverviewTypes.ts",
    maxLines: 70,
    reason: "capture overview model types should stay separate from scoring and rendering rules",
  },
  {
    path: "src/app/core/captureOverviewRecommendations.ts",
    maxLines: 100,
    reason: "capture overview recommendations should stay focused on scoring routes and not render UI",
  },
  {
    path: "src/app/core/captureOverviewQuickFilters.ts",
    maxLines: 95,
    reason: "capture overview quick filters should stay focused on filter suggestions only",
  },
  {
    path: "src/app/core/captureOverviewFilters.ts",
    maxLines: 60,
    reason: "capture overview filter registry should stay static and reusable",
  },
  {
    path: "src/app/core/packetByteLayout.ts",
    maxLines: 95,
    reason: "packet byte layout and hex dump helpers should stay pure and separate from protocol tree rendering",
  },
  {
    path: "src/app/core/protocolDisplay.ts",
    maxLines: 95,
    reason: "protocol display registries should stay static and avoid taking on parsing behavior",
  },
  {
    path: "src/app/pages/AptAnalysis.tsx",
    maxLines: 230,
    reason: "APT page should keep actor orchestration only and leave attribution views in feature modules",
  },
  {
    path: "src/app/pages/UpdateCenter.tsx",
    maxLines: 130,
    reason: "update center page should only orchestrate update status loading and actions",
  },
  {
    path: "src/app/pages/ObjectExport.tsx",
    maxLines: 90,
    reason: "object export page should only orchestrate filtering, selection, and download actions",
  },
  {
    path: "src/app/pages/EvidencePanel.tsx",
    maxLines: 85,
    reason: "evidence page should only orchestrate loading, filters, and export actions",
  },
  {
    path: "src/app/features/evidence/EvidencePanelSections.tsx",
    maxLines: 20,
    reason: "evidence panel sections should stay as a compatibility export layer",
  },
  {
    path: "src/app/features/evidence/EvidenceHero.tsx",
    maxLines: 55,
    reason: "evidence hero should stay focused on heading, summary, and module chips",
  },
  {
    path: "src/app/features/evidence/EvidenceFilters.tsx",
    maxLines: 150,
    reason: "evidence filters should keep severity, module, search, and export controls local",
  },
  {
    path: "src/app/features/evidence/EvidenceResults.tsx",
    maxLines: 140,
    reason: "evidence results should keep loading/error state, table columns, and tag cells local",
  },
  {
    path: "src/app/features/evidence/EvidenceCaveats.tsx",
    maxLines: 35,
    reason: "evidence caveats should stay focused on deduplicated caution display",
  },
  {
    path: "src/app/features/evidence/evidencePanelRules.ts",
    maxLines: 130,
    reason: "evidence panel rules should keep filtering, sorting, labels, counts, and export formatting pure",
  },
  {
    path: "src/app/features/object/ObjectExportPanels.tsx",
    maxLines: 250,
    reason: "object export panels should stay focused on hero, filters, grouped grid, and footer presentation",
  },
  {
    path: "src/app/features/object/objectExportRules.ts",
    maxLines: 135,
    reason: "object export rules should keep classification, labels, filtering, and grouping pure",
  },
  {
    path: "src/app/features/update/UpdateCenterPanels.tsx",
    maxLines: 260,
    reason: "update center panels should keep status, diagnostics, release, and step presentation scoped",
  },
  {
    path: "src/app/features/update/UpdateReleaseMarkdown.tsx",
    maxLines: 85,
    reason: "update release markdown renderers should stay declarative and separate from update state",
  },
  {
    path: "src/app/features/update/updateCenterUtils.ts",
    maxLines: 15,
    reason: "update center utilities should remain tiny and pure",
  },
  {
    path: "src/app/features/apt/APTAttributionPanel.tsx",
    maxLines: 250,
    reason: "APT attribution panel should keep explanation and missing-evidence helpers scoped",
  },
  {
    path: "src/app/features/apt/APTEvidenceTimeline.tsx",
    maxLines: 80,
    reason: "APT evidence timeline should stay focused on ordering and compact evidence rendering",
  },
  {
    path: "src/app/features/apt/APTEvidencePanel.tsx",
    maxLines: 230,
    reason: "APT evidence panel should stay focused on source tabs, table rendering, and tab matching rules",
  },
  {
    path: "src/app/layouts/MainLayout.tsx",
    maxLines: 245,
    reason: "main layout should own route shell state and delegate header, sidebar, footer, and settings chrome",
  },
  {
    path: "src/app/layouts/MainLayoutChrome.tsx",
    maxLines: 330,
    reason: "main layout chrome should own menu, sidebar nav, settings shell, and footer presentation only",
  },
  {
    path: "src/app/layouts/mainLayoutConfig.ts",
    maxLines: 130,
    reason: "main layout route and theme registries should stay static and avoid workflow code",
  },
  {
    path: "src/app/layouts/dragGuard.ts",
    maxLines: 45,
    reason: "browser drag guard should stay as a small DOM safety helper",
  },
  {
    path: "src/app/components/CaptureMissionControl.tsx",
    maxLines: 230,
    reason: "capture mission control should stay focused on overview loading and navigation orchestration",
  },
  {
    path: "src/app/components/CaptureMissionOverviewHeader.tsx",
    maxLines: 160,
    reason: "capture mission overview header should keep cockpit title, protocol chips, and metric cards scoped",
  },
  {
    path: "src/app/components/CaptureMissionPanels.tsx",
    maxLines: 20,
    reason: "capture mission panel compatibility layer should stay as exports only",
  },
  {
    path: "src/app/components/CaptureMissionQuickFilters.tsx",
    maxLines: 60,
    reason: "capture quick filters should stay focused on filter chip presentation",
  },
  {
    path: "src/app/components/CaptureMissionRecommendationPanels.tsx",
    maxLines: 125,
    reason: "capture recommendations should stay focused on recommendation card presentation",
  },
  {
    path: "src/app/components/CaptureMissionThreatPanels.tsx",
    maxLines: 115,
    reason: "capture threat hits should stay focused on hit list presentation and action wiring",
  },
  {
    path: "src/app/components/CaptureMissionPayloadPanel.tsx",
    maxLines: 130,
    reason: "capture payload shortcut panel should stay focused on selected packet context and MISC handoff",
  },
  {
    path: "src/app/components/PacketVirtualTable.tsx",
    maxLines: 240,
    reason: "packet table should stay focused on virtualization, scrolling, resizing, and state orchestration",
  },
  {
    path: "src/app/components/PacketVirtualTableColumns.tsx",
    maxLines: 160,
    reason: "packet table column config, persistence, and cell rules should stay separate from virtualization",
  },
  {
    path: "src/app/components/PacketVirtualTableHeader.tsx",
    maxLines: 90,
    reason: "packet table header should stay focused on column settings and resize handles",
  },
  {
    path: "src/app/components/PacketVirtualTableRows.tsx",
    maxLines: 115,
    reason: "packet table rows should stay focused on row coloring and cell rendering",
  },
  {
    path: "src/app/components/PacketVirtualTableMenu.tsx",
    maxLines: 75,
    reason: "packet table context menu should stay focused on follow-stream actions",
  },
  {
    path: "src/app/pages/ThreatHunting.tsx",
    maxLines: 280,
    reason: "threat hunting page should stay focused on runtime config, data loading, and navigation orchestration",
  },
  {
    path: "src/app/features/hunting/ThreatHuntingPanels.tsx",
    maxLines: 125,
    reason: "threat hunting display panels should compose category, progress, and workbench sections only",
  },
  {
    path: "src/app/features/hunting/ThreatHuntingSummaryPanels.tsx",
    maxLines: 120,
    reason: "threat hunting summary panels should keep category and progress presentation scoped",
  },
  {
    path: "src/app/features/hunting/ThreatHuntingWorkbenchSections.tsx",
    maxLines: 285,
    reason:
      "threat hunting workbench sections should keep config form, hits table, and selected detail presentation scoped",
  },
  {
    path: "src/app/pages/Workspace.tsx",
    maxLines: 350,
    reason: "workspace page should stay focused on state wiring, navigation, and selection orchestration",
  },
  {
    path: "src/app/components/workspace/WorkspacePanels.tsx",
    maxLines: 190,
    reason: "workspace panels should stay presentational and avoid capture/filter state ownership",
  },
  {
    path: "src/app/components/workspace/WorkspacePacketErrorPanel.tsx",
    maxLines: 70,
    reason: "workspace packet error panel should stay focused on data-plane failure diagnostics",
  },
  {
    path: "src/app/components/workspace/useWorkspaceFilterHistory.ts",
    maxLines: 105,
    reason: "workspace filter history should only own local suggestions and persistence",
  },
  {
    path: "src/app/components/workspace/workspaceSelection.ts",
    maxLines: 60,
    reason: "workspace selection helpers should stay pure and small",
  },
  {
    path: "src/app/state/packetPageStatus.ts",
    maxLines: 20,
    reason: "packet page status helpers should stay as tiny message builders",
  },
  {
    path: "src/app/pages/IndustrialAnalysis.tsx",
    maxLines: 310,
    reason: "industrial page should stay focused on analysis loading and high-level protocol orchestration",
  },
  {
    path: "src/app/features/industrial/IndustrialModbusPanels.tsx",
    maxLines: 60,
    reason: "industrial Modbus panels should only compose focused Modbus panel modules",
  },
  {
    path: "src/app/features/industrial/ModbusSuspiciousWritesPanel.tsx",
    maxLines: 125,
    reason: "Modbus suspicious writes panel should stay focused on write aggregation display",
  },
  {
    path: "src/app/features/industrial/ModbusDecodedInputsPanel.tsx",
    maxLines: 95,
    reason: "Modbus decoded inputs panel should stay focused on reconstructed UTF-8 input display",
  },
  {
    path: "src/app/features/industrial/ModbusTransactionsPanel.tsx",
    maxLines: 220,
    reason: "Modbus transactions panel should keep transaction filters, table, and summary cells local",
  },
  {
    path: "src/app/features/c2/C2AggregateTables.tsx",
    maxLines: 20,
    reason: "C2 aggregate table barrel should stay as compatibility exports only",
  },
  {
    path: "src/app/features/c2/CSHostURIAggregates.tsx",
    maxLines: 180,
    reason: "CS Host/URI aggregate table should stay focused on one table section",
  },
  {
    path: "src/app/features/c2/CSDNSAggregates.tsx",
    maxLines: 185,
    reason: "CS DNS aggregate table should stay focused on DNS beacon aggregation rows and expansion",
  },
  {
    path: "src/app/features/c2/VShellStreamAggregates.tsx",
    maxLines: 185,
    reason: "VShell stream aggregate table should stay focused on stream-level C2 signal rows and expansion",
  },
  {
    path: "src/app/features/c2/C2AggregateTableStyles.ts",
    maxLines: 20,
    reason: "C2 aggregate table style constants should stay static and tiny",
  },
  {
    path: "src/app/pages/HttpStream.tsx",
    maxLines: 180,
    reason:
      "HTTP stream page should keep stream state orchestration separate from chunk helpers and presentation sections",
  },
  {
    path: "src/app/pages/TcpStream.tsx",
    maxLines: 280,
    reason: "TCP stream page should keep state and pagination orchestration separate from raw stream sections",
  },
  {
    path: "src/app/pages/UdpStream.tsx",
    maxLines: 270,
    reason: "UDP stream page should keep state and pagination orchestration separate from raw stream sections",
  },
  {
    path: "src/app/pages/RawStreamUtils.ts",
    maxLines: 140,
    reason: "raw TCP/UDP stream helpers should stay pure and own shared chunk search/export/dialog helpers",
  },
  {
    path: "src/app/pages/RawStreamSections.tsx",
    maxLines: 285,
    reason: "raw stream sections should keep shared TCP/UDP title, payload grid, and selected panel rendering scoped",
  },
  {
    path: "src/app/pages/RawStreamControlBar.tsx",
    maxLines: 130,
    reason: "raw stream control bar should stay focused on stream navigation, search, view mode, and export actions",
  },
  {
    path: "src/app/pages/RawStreamDialog.tsx",
    maxLines: 65,
    reason: "raw stream dialog should stay focused on expanded payload display and MISC handoff action",
  },
  {
    path: "src/app/pages/HttpStreamUtils.ts",
    maxLines: 165,
    reason: "HTTP stream formatting helpers should stay pure and avoid page orchestration",
  },
  {
    path: "src/app/pages/HttpStreamChunks.ts",
    maxLines: 80,
    reason: "HTTP stream chunk helpers should stay pure and avoid rendering concerns",
  },
  {
    path: "src/app/pages/HttpStreamSections.tsx",
    maxLines: 20,
    reason: "HTTP stream sections should stay as compatibility exports only",
  },
  {
    path: "src/app/pages/HttpStreamTitleBar.tsx",
    maxLines: 165,
    reason:
      "HTTP stream title and toolbar should keep stream navigation, view mode, search, and export controls scoped",
  },
  {
    path: "src/app/pages/HttpStreamPayloadGrid.tsx",
    maxLines: 170,
    reason: "HTTP stream payload grid should keep chunk cards and selected preview presentation scoped",
  },
  {
    path: "src/app/pages/HttpStreamDialog.tsx",
    maxLines: 75,
    reason: "HTTP stream dialog should stay focused on expanded payload display and MISC handoff action",
  },
  {
    path: "src/app/features/media/MediaSessionTable.tsx",
    maxLines: 240,
    reason: "media session table should keep row cell rendering in sibling modules",
  },
  {
    path: "src/app/features/media/MediaSessionCells.tsx",
    maxLines: 220,
    reason: "media session cells should stay scoped to type, transcription, and export actions",
  },
  {
    path: "src/app/features/media/MediaSessionTableUtils.ts",
    maxLines: 115,
    reason: "media session table helpers should remain pure and small",
  },
  {
    path: "src/app/components/RuntimeSettingsSidebar.tsx",
    maxLines: 130,
    reason: "runtime settings sidebar should keep state wiring separate from presentational controls",
  },
  {
    path: "src/app/components/RuntimeSettingsSections.tsx",
    maxLines: 240,
    reason: "runtime settings domain sections should stay presentational and avoid save or refresh orchestration",
  },
  {
    path: "src/app/components/RuntimeSettingsShell.tsx",
    maxLines: 105,
    reason: "runtime settings shell should stay focused on header, actions, and footer chrome",
  },
  {
    path: "src/app/components/RuntimeSettingsSidebarParts.tsx",
    maxLines: 145,
    reason: "runtime settings presentational controls and helpers should stay small",
  },
  {
    path: "src/app/features/usb/UsbTables.tsx",
    maxLines: 210,
    reason: "USB tables barrel should keep HID and mass-storage table sections in sibling files",
  },
  {
    path: "src/app/features/usb/UsbHidTables.tsx",
    maxLines: 175,
    reason: "USB HID tables should stay focused on keyboard and mouse event presentation",
  },
  {
    path: "src/app/features/usb/UsbMassStorageTables.tsx",
    maxLines: 175,
    reason: "USB mass-storage tables should keep filters and operation rows scoped",
  },
  {
    path: "src/app/features/usb/UsbTableStyles.ts",
    maxLines: 20,
    reason: "USB table style constants should stay static and tiny",
  },
  {
    path: "src/app/features/usb/UsbTableUtils.ts",
    maxLines: 20,
    reason: "USB table helpers should stay pure and tiny",
  },
];

export const testSizeBudgets = [
  {
    path: "src/app/state/captureTaskReset.test.ts",
    maxLines: 75,
    reason:
      "capture task reset tests should stay focused on cancellation, sequence bumps, prefetch cleanup, and timer clearing",
  },
  {
    path: "src/app/state/captureReplacementPrepare.test.ts",
    maxLines: 75,
    reason:
      "capture replacement prepare tests should stay focused on local reset, backend cleanup, and disconnect skips",
  },
  {
    path: "src/app/state/captureStopWorkflow.test.ts",
    maxLines: 85,
    reason: "capture stop workflow tests should stay focused on frontend reset, disconnect skip, and close errors",
  },
  {
    path: "src/app/state/captureStartState.test.ts",
    maxLines: 90,
    reason:
      "capture start state tests should stay focused on reset, runtime, pending transaction, and recent capture effects",
  },
  {
    path: "src/app/state/captureStartBackend.test.ts",
    maxLines: 110,
    reason:
      "capture start backend tests should cover path resolution, dialog fallback, stale start, and preload status",
  },
  {
    path: "src/app/state/capturePreloadProbe.test.ts",
    maxLines: 125,
    reason: "capture preload probe tests should cover success, polling, stale, empty parse, and timeout behavior",
  },
  {
    path: "src/app/state/captureCommitState.test.ts",
    maxLines: 170,
    reason:
      "capture commit state tests should stay focused on packet reset, stream runtime reset, metadata, and first page commit",
  },
  {
    path: "src/app/state/captureFinalizeWorkflow.test.ts",
    maxLines: 95,
    reason: "capture finalize workflow tests should cover success and stale finalization behavior",
  },
  {
    path: "src/app/state/sentinelDerivedView.test.ts",
    maxLines: 65,
    reason: "sentinel derived view tests should cover selected packet, pagination, hex, and layer tree derivation only",
  },
  {
    path: "src/app/state/hooks/useSelectedPacketResources.test.tsx",
    maxLines: 70,
    reason: "selected packet resources hook tests should stay focused on composed detail, raw, and layer loading",
  },
  {
    path: "src/app/state/captureClearState.test.ts",
    maxLines: 195,
    reason:
      "capture clear state tests should stay focused on UI, preload, stream runtime, and metadata clearing effects",
  },
  {
    path: "src/app/state/captureTransactionStatus.test.ts",
    maxLines: 75,
    reason: "capture transaction status tests should stay focused on failure reason and fallback capture fields",
  },
  {
    path: "src/app/state/packetPageLoad.test.ts",
    maxLines: 115,
    reason:
      "packet page load tests should stay focused on success, disconnected, failure, abort, and stale result behavior",
  },
  {
    path: "src/app/state/packetPageCommit.test.ts",
    maxLines: 130,
    reason: "packet page commit tests should stay focused on page commit and selected packet retention or clearing",
  },
  {
    path: "src/app/state/packetPageNavigation.test.ts",
    maxLines: 75,
    reason: "packet page navigation tests should stay focused on cursor actions and retry status",
  },
  {
    path: "src/app/state/packetFilterWorkflow.test.ts",
    maxLines: 125,
    reason: "packet filter workflow tests should stay focused on run, poll, clear, skip, and stale behaviors",
  },
  {
    path: "src/app/state/packetFilterAction.test.ts",
    maxLines: 85,
    reason: "packet filter action tests should cover sync, clear, current-value, and inactive-capture behavior",
  },
  {
    path: "src/app/state/packetLocateWorkflow.test.ts",
    maxLines: 125,
    reason:
      "packet locate workflow tests should stay focused on found, missing, override, invalid, abort, and failure behavior",
  },
  {
    path: "src/app/state/streamIndexRefresh.test.ts",
    maxLines: 90,
    reason: "stream index refresh tests should stay focused on load, skip, stale, abort, and failure behavior",
  },
  {
    path: "src/app/state/streamPayloadPersist.test.ts",
    maxLines: 115,
    reason: "stream payload persist tests should stay focused on backend update, skip guards, and failure behavior",
  },
  {
    path: "src/app/state/packetStreamPrepare.test.ts",
    maxLines: 70,
    reason: "packet stream prepare tests should stay focused on locate, preferred protocol, and missing stream guards",
  },
  {
    path: "src/app/state/progressStatusWorkflow.test.ts",
    maxLines: 125,
    reason:
      "progress workflow tests should stay focused on non-progress, malformed, media, threat, and capture progress",
  },
  {
    path: "src/app/state/streamAdjacentPrefetch.test.ts",
    maxLines: 105,
    reason: "stream adjacent prefetch tests should stay focused on guard, scheduling, protocol, and cache behavior",
  },
  {
    path: "src/app/state/streamSwitchWorkflow.test.ts",
    maxLines: 130,
    reason: "stream switch workflow tests should stay focused on guard, cache hit, fetch commit, and error behavior",
  },
  {
    path: "src/app/pages/MiscTools.testFixtures.ts",
    maxLines: 120,
    reason: "MISC shared test fixtures should only reset mocks and coordinate module expansion",
  },
  {
    path: "src/app/pages/MiscTools.mockData.ts",
    maxLines: 20,
    reason: "MISC mock data barrel should only re-export domain fixture files",
  },
  {
    path: "src/app/pages/MiscTools.sessionMockData.ts",
    maxLines: 230,
    reason: "MISC session mock data should split by protocol if new session fixtures are added",
  },
  {
    path: "src/app/pages/MiscTools.moduleMockData.ts",
    maxLines: 140,
    reason: "MISC module registry mock data should stay separate from result payloads",
  },
  {
    path: "src/app/pages/MiscTools.payloadMockData.ts",
    maxLines: 90,
    reason: "MISC payload mock data should stay focused on inspector and decoder fixtures",
  },
  {
    path: "src/app/pages/MiscTools.test.tsx",
    maxLines: 270,
    reason: "MISC base page tests should not absorb session or custom module workflows",
  },
  {
    path: "src/app/pages/MiscTools.payloadHints.test.tsx",
    maxLines: 180,
    reason: "MISC payload hint precedence tests should stay focused on source-vs-inspection behavior",
  },
  {
    path: "src/app/pages/C2Analysis.vshell.test.tsx",
    maxLines: 330,
    reason: "VShell workflow tests should split again if new decrypt or table flows are added",
  },
  {
    path: "src/app/pages/C2Analysis.test.tsx",
    maxLines: 320,
    reason: "C2 base page tests should keep decrypt and candidate flows in sibling test files",
  },
  {
    path: "src/app/pages/UsbAnalysis.testFixtures.ts",
    maxLines: 240,
    reason: "USB fixtures should stay reusable and avoid mixing page assertions",
  },
  {
    path: "src/app/pages/MiscTools.sessions.test.tsx",
    maxLines: 165,
    reason: "MISC session tests should remain focused on candidate loading and selection",
  },
  {
    path: "src/app/pages/MiscTools.smb3.test.tsx",
    maxLines: 170,
    reason: "MISC SMB3 tests should stay isolated from other session candidate workflows",
  },
  {
    path: "src/app/pages/C2Analysis.decrypt.test.tsx",
    maxLines: 220,
    reason: "C2 decrypt tests should stay focused on request and result-table behavior",
  },
  {
    path: "src/app/pages/UsbAnalysis.test.tsx",
    maxLines: 160,
    reason: "USB page tests should use fixtures instead of inline protocol records",
  },
  {
    path: "src/app/pages/C2Analysis.candidates.test.tsx",
    maxLines: 190,
    reason: "C2 candidate tests should keep row navigation and detail assertions scoped",
  },
  {
    path: "src/app/pages/HttpStreamUtils.test.ts",
    maxLines: 100,
    reason: "HTTP stream helper tests should stay focused on formatting and binary-body parsing",
  },
  {
    path: "src/app/pages/HttpStreamChunks.test.ts",
    maxLines: 60,
    reason: "HTTP stream chunk helper tests should stay focused on fallback, filtering, match counts, and export text",
  },
  {
    path: "src/app/features/media/MediaOverviewPanels.test.tsx",
    maxLines: 130,
    reason: "media overview panel tests should stay focused on stats, notes, and batch action wiring",
  },
  {
    path: "src/app/features/media/MediaSessionTableUtils.test.ts",
    maxLines: 145,
    reason: "media session table helper tests should stay focused on playback and transcription state rules",
  },
  {
    path: "src/app/features/media/MediaSessionCells.test.tsx",
    maxLines: 150,
    reason: "media session cell tests should stay focused on transcription and artifact actions",
  },
  {
    path: "src/app/features/media/useMediaTranscriptionWorkflow.test.ts",
    maxLines: 120,
    reason: "media workflow helper tests should stay focused on merge and dependency classification rules",
  },
  {
    path: "src/app/features/update/updateCenterUtils.test.ts",
    maxLines: 30,
    reason: "update center utility tests should only cover formatting fallbacks",
  },
  {
    path: "src/app/features/object/objectExportRules.test.ts",
    maxLines: 55,
    reason: "object export rule tests should stay focused on classification, filtering, and grouping",
  },
  {
    path: "src/app/features/evidence/evidencePanelRules.test.ts",
    maxLines: 80,
    reason: "evidence panel rule tests should stay focused on filtering, sorting, counts, and exports",
  },
  {
    path: "src/app/components/RuntimeSettingsSidebarParts.test.tsx",
    maxLines: 110,
    reason: "runtime settings helper tests should stay focused on normalization and dependency status rules",
  },
  {
    path: "src/app/components/StreamDecoderBatchPanel.test.tsx",
    maxLines: 70,
    reason: "decoder batch panel tests should stay focused on clamping, progress, and failures",
  },
  {
    path: "src/app/components/StreamDecoderToolbar.test.tsx",
    maxLines: 70,
    reason: "decoder toolbar tests should stay focused on action wiring and running state",
  },
  {
    path: "src/app/components/stream/StreamNavigationControls.test.tsx",
    maxLines: 90,
    reason: "stream navigation control tests should stay focused on input, search, and view toggles",
  },
  {
    path: "src/app/components/stream/StreamPayloadPanels.test.tsx",
    maxLines: 90,
    reason: "stream payload panel tests should stay focused on highlight, card actions, and dialog metadata",
  },
  {
    path: "src/app/features/c2/CSHostURIAggregates.test.tsx",
    maxLines: 85,
    reason: "CS Host/URI aggregate tests should stay focused on empty state and table wiring",
  },
  {
    path: "src/app/features/usb/UsbTablesSplit.test.tsx",
    maxLines: 115,
    reason: "USB split table tests should stay focused on barrel compatibility and row wiring",
  },
  {
    path: "src/app/components/workspace/WorkspacePanels.test.tsx",
    maxLines: 80,
    reason: "workspace panel tests should stay focused on table, loading, and diagnostic panel wiring",
  },
  {
    path: "src/app/state/packetPageStatus.test.ts",
    maxLines: 30,
    reason: "packet page status tests should stay focused on message formatting",
  },
];

export const sizeBudgets = [...sourceSizeBudgets, ...testSizeBudgets];

export function countLines(text) {
  if (text.length === 0) {
    return 0;
  }
  return text.split(/\r\n|\r|\n/).length;
}

export function findSizeBudgetFailures({ frontendRoot = root, budgets = sizeBudgets } = {}) {
  const failures = [];

  for (const budget of budgets) {
    const absolutePath = resolve(frontendRoot, budget.path);
    const lines = countLines(readFileSync(absolutePath, "utf8"));
    if (lines > budget.maxLines) {
      failures.push({ ...budget, lines });
    }
  }

  return failures;
}

function runCli() {
  const failures = findSizeBudgetFailures();

  if (failures.length > 0) {
    console.error("Frontend size budget exceeded:");
    for (const failure of failures) {
      console.error(`- ${failure.path}: ${failure.lines}/${failure.maxLines} lines. ${failure.reason}`);
    }
    process.exit(1);
  }

  console.log("Frontend size budget passed.");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runCli();
}
