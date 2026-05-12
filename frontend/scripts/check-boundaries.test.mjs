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
});
