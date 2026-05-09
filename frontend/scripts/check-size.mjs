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
    path: "src/app/state/SentinelContext.tsx",
    maxLines: 1450,
    reason: "provider remains oversized and should not absorb new state domains",
  },
  {
    path: "src/app/components/StreamDecoderWorkbench.tsx",
    maxLines: 405,
    reason: "decoder workbench should keep toolbar, batch controls, settings panels, and pure rules in sibling modules",
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
    maxLines: 260,
    reason: "decoder settings panels should stay focused on webshell decoder options",
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
    maxLines: 285,
    reason: "stream payload panels should keep current chunk, card, highlight, and dialog rendering local",
  },
  {
    path: "src/app/pages/C2Analysis.tsx",
    maxLines: 410,
    reason: "C2 page should move forms, tables, and result panels into feature components",
  },
  {
    path: "src/app/pages/UsbAnalysis.tsx",
    maxLines: 510,
    reason: "USB page should keep domain panels and shared controls in feature components",
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
    maxLines: 390,
    reason: "media page should keep overview panels and table display in feature components",
  },
  {
    path: "src/app/features/media/MediaOverviewPanels.tsx",
    maxLines: 165,
    reason: "media overview panels should stay presentational and avoid playback or transcription side effects",
  },
  {
    path: "src/app/components/ui/sidebar.tsx",
    maxLines: 630,
    reason: "shared sidebar primitive should keep provider state in sidebarContext and avoid feature-specific logic",
  },
  {
    path: "src/app/components/ui/sidebarContext.tsx",
    maxLines: 160,
    reason: "sidebar context should stay focused on provider state, cookie persistence, and keyboard toggle behavior",
  },
  {
    path: "src/app/pages/VehicleAnalysis.tsx",
    maxLines: 460,
    reason: "vehicle page should move larger protocol panels into feature components",
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
    maxLines: 520,
    reason: "core engine should keep protocol tree and hex layout logic separate from display registries",
  },
  {
    path: "src/app/core/protocolDisplay.ts",
    maxLines: 95,
    reason: "protocol display registries should stay static and avoid taking on parsing behavior",
  },
  {
    path: "src/app/pages/AptAnalysis.tsx",
    maxLines: 435,
    reason: "APT page should keep heavy actor views and tables in feature modules",
  },
  {
    path: "src/app/features/apt/APTEvidencePanel.tsx",
    maxLines: 230,
    reason: "APT evidence panel should stay focused on source tabs, table rendering, and tab matching rules",
  },
  {
    path: "src/app/layouts/MainLayout.tsx",
    maxLines: 450,
    reason: "main layout should not grow into page or workflow orchestration",
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
    maxLines: 300,
    reason: "capture mission control should stay focused on overview loading and navigation orchestration",
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
    maxLines: 380,
    reason: "threat hunting display panels should stay presentational and avoid backend or route orchestration",
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
    path: "src/app/pages/IndustrialAnalysis.tsx",
    maxLines: 310,
    reason: "industrial page should stay focused on analysis loading and high-level protocol orchestration",
  },
  {
    path: "src/app/features/industrial/IndustrialModbusPanels.tsx",
    maxLines: 310,
    reason: "industrial Modbus panels should keep write, decoded-input, and transaction tables local",
  },
  {
    path: "src/app/features/c2/C2AggregateTables.tsx",
    maxLines: 340,
    reason: "C2 aggregate table barrel should keep large table sections in sibling files",
  },
  {
    path: "src/app/features/c2/CSHostURIAggregates.tsx",
    maxLines: 180,
    reason: "CS Host/URI aggregate table should stay focused on one table section",
  },
  {
    path: "src/app/features/c2/C2AggregateTableStyles.ts",
    maxLines: 20,
    reason: "C2 aggregate table style constants should stay static and tiny",
  },
  {
    path: "src/app/pages/HttpStream.tsx",
    maxLines: 350,
    reason: "HTTP stream page should keep formatting helpers and payload transforms in sibling modules",
  },
  {
    path: "src/app/pages/HttpStreamUtils.ts",
    maxLines: 165,
    reason: "HTTP stream formatting helpers should stay pure and avoid page orchestration",
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
