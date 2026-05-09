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
    maxLines: 900,
    reason: "decoder workbench should keep UI parts and pure rules in sibling modules",
  },
  {
    path: "src/app/pages/C2Analysis.tsx",
    maxLines: 410,
    reason: "C2 page should move forms, tables, and result panels into feature components",
  },
  {
    path: "src/app/pages/UsbAnalysis.tsx",
    maxLines: 720,
    reason: "USB page is near the large-page threshold",
  },
  {
    path: "src/app/pages/MediaAnalysis.tsx",
    maxLines: 450,
    reason: "media page is near the large-page threshold",
  },
  {
    path: "src/app/components/ui/sidebar.tsx",
    maxLines: 750,
    reason: "shared sidebar primitive should stay stable and avoid feature-specific logic",
  },
  {
    path: "src/app/pages/VehicleAnalysis.tsx",
    maxLines: 650,
    reason: "vehicle page should move larger protocol panels into feature components",
  },
  {
    path: "src/app/core/engine.ts",
    maxLines: 600,
    reason: "core engine registry should avoid absorbing page-specific behavior",
  },
  {
    path: "src/app/pages/AptAnalysis.tsx",
    maxLines: 580,
    reason: "APT page should keep heavy actor views and tables in feature modules",
  },
  {
    path: "src/app/layouts/MainLayout.tsx",
    maxLines: 570,
    reason: "main layout should not grow into page or workflow orchestration",
  },
  {
    path: "src/app/components/CaptureMissionControl.tsx",
    maxLines: 520,
    reason: "capture mission control should keep larger panels in sibling components",
  },
  {
    path: "src/app/components/PacketVirtualTable.tsx",
    maxLines: 520,
    reason: "packet table should keep virtualization and row helpers separated",
  },
  {
    path: "src/app/pages/ThreatHunting.tsx",
    maxLines: 510,
    reason: "threat hunting page should move complex result views into feature components",
  },
  {
    path: "src/app/pages/Workspace.tsx",
    maxLines: 510,
    reason: "workspace page should avoid taking on capture lifecycle internals",
  },
  {
    path: "src/app/pages/IndustrialAnalysis.tsx",
    maxLines: 490,
    reason: "industrial page should keep decoded protocol panels in feature components",
  },
  {
    path: "src/app/features/c2/C2AggregateTables.tsx",
    maxLines: 485,
    reason: "C2 aggregate tables should keep row helpers and detail panels separated",
  },
  {
    path: "src/app/pages/HttpStream.tsx",
    maxLines: 485,
    reason: "HTTP stream page should avoid absorbing decoder or evidence workflows",
  },
  {
    path: "src/app/features/media/MediaSessionTable.tsx",
    maxLines: 470,
    reason: "media session table should keep playback panels and row helpers split",
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
    maxLines: 330,
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
    maxLines: 220,
    reason: "MISC session tests should remain focused on candidate loading and selection",
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
