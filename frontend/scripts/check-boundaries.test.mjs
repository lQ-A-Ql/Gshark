import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { findBoundaryViolations } from "./check-boundaries.mjs";

function writeFixtureFile(frontendRoot, relativePath, content) {
  const absolutePath = resolve(frontendRoot, relativePath);
  mkdirSync(resolve(absolutePath, ".."), { recursive: true });
  writeFileSync(absolutePath, content);
}

describe("check-boundaries script", () => {
  it("rejects production imports from the wails bridge facade", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "gshark-boundary-check-"));
    writeFixtureFile(
      frontendRoot,
      "src/app/features/demo/useDemo.ts",
      'import { backendClients } from "../../integrations/wailsBridge";',
    );

    expect(findBoundaryViolations({ frontendRoot })).toEqual([
      "src/app/features/demo/useDemo.ts imports ../../integrations/wailsBridge; production code must use integrations/backendClients or bridgeTypes",
    ]);
  });

  it("rejects app-layer imports from aggregate bridge types", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "gshark-boundary-check-"));
    writeFixtureFile(
      frontendRoot,
      "src/app/state/useDemo.ts",
      'import type { BackendClients } from "../integrations/bridgeTypes";',
    );

    expect(findBoundaryViolations({ frontendRoot })).toEqual([
      "src/app/state/useDemo.ts imports ../integrations/bridgeTypes; use concrete client type modules instead",
    ]);
  });

  it("allows integration-layer bridge type composition", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "gshark-boundary-check-"));
    writeFixtureFile(
      frontendRoot,
      "src/app/integrations/backendClients.ts",
      'import type { BackendBridge } from "./bridgeTypes";',
    );

    expect(findBoundaryViolations({ frontendRoot })).toEqual([]);
  });

  it("rejects app-layer imports from bridge composition internals", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "gshark-boundary-check-"));
    writeFixtureFile(
      frontendRoot,
      "src/app/pages/Demo.tsx",
      'import { createBridge } from "../integrations/bridgeFactory";',
    );
    writeFixtureFile(
      frontendRoot,
      "src/app/features/demo/useDemo.ts",
      'import { createHttpBridge } from "../../integrations/httpBridge";',
    );
    writeFixtureFile(frontendRoot, "src/app/integrations/bridgeFactory.ts", "export function createBridge() {}");
    writeFixtureFile(frontendRoot, "src/app/integrations/httpBridge.ts", "export function createHttpBridge() {}");

    expect(findBoundaryViolations({ frontendRoot }).sort()).toEqual(
      [
        "src/app/pages/Demo.tsx imports ../integrations/bridgeFactory; app code must depend on backendClients domain projections",
        "src/app/features/demo/useDemo.ts imports ../../integrations/httpBridge; app code must depend on backendClients domain projections",
      ].sort(),
    );
  });

  it("rejects page and feature imports from aggregate bridge type contracts", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "gshark-boundary-check-"));
    writeFixtureFile(
      frontendRoot,
      "src/app/pages/Demo.tsx",
      'import type { BackendBridge } from "../integrations/bridgeTypes";',
    );

    expect(findBoundaryViolations({ frontendRoot })).toEqual([
      "src/app/pages/Demo.tsx imports ../integrations/bridgeTypes; use concrete client type modules instead",
    ]);
  });

  it("rejects state imports from UI layers", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "gshark-boundary-check-"));
    writeFixtureFile(frontendRoot, "src/app/state/useDemo.ts", 'import { DemoPanel } from "../components/DemoPanel";');
    writeFixtureFile(frontendRoot, "src/app/components/DemoPanel.tsx", "export function DemoPanel() { return null; }");

    expect(findBoundaryViolations({ frontendRoot })).toEqual([
      "src/app/state/useDemo.ts imports UI layer ../components/DemoPanel; state code must stay UI-free",
    ]);
  });
});
