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
    maxLines: 520,
    reason: "decoder workbench should keep settings panels and pure rules in sibling modules",
  },
  {
    path: "src/app/components/StreamDecoderCandidatePanel.tsx",
    maxLines: 250,
    reason: "decoder candidate panel should stay focused on inspection results and candidate selection UI",
  },
  {
    path: "src/app/components/StreamDecoderSettingsPanel.tsx",
    maxLines: 260,
    reason: "decoder settings panels should stay focused on webshell decoder options",
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
    maxLines: 320,
    reason: "capture mission display panels should stay presentational and avoid data loading logic",
  },
  {
    path: "src/app/components/PacketVirtualTable.tsx",
    maxLines: 360,
    reason: "packet table should stay focused on virtualization, scrolling, resizing, and context menus",
  },
  {
    path: "src/app/components/PacketVirtualTableColumns.tsx",
    maxLines: 160,
    reason: "packet table column config, persistence, and cell rules should stay separate from virtualization",
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
    maxLines: 485,
    reason: "C2 aggregate tables should keep row helpers and detail panels separated",
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
    maxLines: 365,
    reason: "media session table should keep playback panels and row helper logic in sibling modules",
  },
  {
    path: "src/app/features/media/MediaSessionTableUtils.ts",
    maxLines: 115,
    reason: "media session table helpers should remain pure and small",
  },
  {
    path: "src/app/components/RuntimeSettingsSidebar.tsx",
    maxLines: 470,
    reason: "runtime settings sidebar should not grow into workflow-specific settings",
  },
  {
    path: "src/app/features/usb/UsbTables.tsx",
    maxLines: 460,
    reason: "USB tables should keep HID and mass-storage sections modular",
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
