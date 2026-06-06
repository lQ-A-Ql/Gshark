import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { findPreloadBoundaryViolations } from "./check-preload-boundaries.mjs";

function writeFixtureFile(frontendRoot, relativePath, content) {
  const absolutePath = resolve(frontendRoot, relativePath);
  mkdirSync(resolve(absolutePath, ".."), { recursive: true });
  writeFileSync(absolutePath, content);
}

describe("check-preload-boundaries", () => {
  it("rejects preload imports from bridge internals", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "meow-preload-boundary-"));
    writeFixtureFile(frontendRoot, "src/app/preload/bad.ts", 'import { bridge } from "../integrations/desktopBridge";');
    writeFixtureFile(frontendRoot, "src/app/integrations/desktopBridge.ts", "export const bridge = {};");

    expect(findPreloadBoundaryViolations({ frontendRoot })).toEqual([
      "src/app/preload/bad.ts imports ../integrations/desktopBridge; preload must not import bridge internals",
    ]);
  });

  it("rejects pages importing preload internals", () => {
    const frontendRoot = mkdtempSync(resolve(tmpdir(), "meow-preload-boundary-"));
    writeFixtureFile(
      frontendRoot,
      "src/app/pages/Demo.tsx",
      'import { schedulePreload } from "../preload/preloadScheduler";',
    );
    writeFixtureFile(frontendRoot, "src/app/preload/preloadScheduler.ts", "export function schedulePreload() {}");

    expect(findPreloadBoundaryViolations({ frontendRoot })).toEqual([
      "src/app/pages/Demo.tsx imports preload internal ../preload/preloadScheduler; pages must use feature hooks/contracts",
    ]);
  });
});
