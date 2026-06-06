import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { findPreloadBudgetViolations } from "./check-preload-budget.mjs";

function writeTargets(content) {
  const root = mkdtempSync(resolve(tmpdir(), "meow-preload-budget-"));
  const file = resolve(root, "preloadTargets.ts");
  mkdirSync(resolve(file, ".."), { recursive: true });
  writeFileSync(file, content);
  return file;
}

describe("check-preload-budget", () => {
  it("rejects high default-on target", () => {
    const file = writeTargets(`
      export const PRELOAD_TARGETS = [];
      const heavyTargets = [{
        targetId: "heavy:/c2",
        routePath: "/c2",
        kind: "heavy-analysis",
        cost: "high",
        enabledByDefault: true,
        triggers: ["hover"],
        requiresCapture: true,
        timeoutMs: 15000,
        canAbort: true,
        featureFlag: "VITE_PRELOAD_HEAVY_WARMUP",
      }];
    `);

    expect(findPreloadBudgetViolations({ preloadTargetsPath: file })).toContain(
      "heavy:/c2: HIGH target must be default off",
    );
  });

  it("rejects missing timeout on non-low target", () => {
    const file = writeTargets(`
      export const PRELOAD_TARGETS = [];
      const lightTargets = [{
        targetId: "light:/traffic",
        routePath: "/traffic",
        kind: "light-data",
        cost: "medium",
        enabledByDefault: false,
        triggers: ["route-enter"],
        requiresCapture: true,
        canAbort: true,
      }];
    `);

    expect(findPreloadBudgetViolations({ preloadTargetsPath: file })).toContain("light:/traffic: missing timeoutMs");
  });
});
