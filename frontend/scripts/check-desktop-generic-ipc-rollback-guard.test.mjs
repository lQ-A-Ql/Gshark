import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { findDesktopGenericIpcRollbackGuardViolations } from "./check-desktop-generic-ipc-rollback-guard.mjs";

function createFixture({ policy, policyTest, bridgeTest, exitPlan, packageJson } = {}) {
  const rootDir = mkdtempSync(resolve(tmpdir(), "gshark-generic-ipc-rollback-"));
  writeFixture(rootDir, "frontend/src/app/integrations/desktopGenericIpcPolicy.ts", policy ?? validPolicy());
  writeFixture(
    rootDir,
    "frontend/src/app/integrations/desktopGenericIpcPolicy.test.ts",
    policyTest ?? validPolicyTest(),
  );
  writeFixture(rootDir, "frontend/src/app/integrations/desktopBridge.test.ts", bridgeTest ?? validBridgeTest());
  writeFixture(rootDir, "docs/desktop-ipc-old-binding-exit-plan.md", exitPlan ?? validExitPlan());
  writeFixture(rootDir, "frontend/package.json", JSON.stringify(packageJson ?? validPackageJson()));
  return rootDir;
}

function writeFixture(rootDir, relativePath, content) {
  const path = resolve(rootDir, relativePath);
  mkdirSync(resolve(path, ".."), { recursive: true });
  writeFileSync(path, content);
}

function validPolicy() {
  return `
    export function resolveDesktopGenericIpcPolicy(env = import.meta.env) {
      const explicitPolicy = String(env.VITE_DESKTOP_GENERIC_IPC_POLICY ?? "").trim().toLowerCase();
      if (explicitPolicy === "disabled") return "disabled";
      if (explicitPolicy === "compat") return "compat";
      return String(env.VITE_DESKTOP_DISABLE_GENERIC_IPC ?? "").trim() === "1" ? "disabled" : "compat";
    }
  `;
}

function validPolicyTest() {
  return `
    it("lets an explicit compat policy override the legacy disable alias", () => {
      const env = { VITE_DESKTOP_GENERIC_IPC_POLICY: "compat", VITE_DESKTOP_DISABLE_GENERIC_IPC: "1" };
      expect(resolveDesktopGenericIpcPolicy(env)).toBe("compat");
    });
  `;
}

function validBridgeTest() {
  return `
    it("keeps explicit compat policy adapter-enabled even when the legacy disable alias is set", () => {
      vi.stubEnv("VITE_DESKTOP_GENERIC_IPC_POLICY", "compat");
      vi.stubEnv("VITE_DESKTOP_DISABLE_GENERIC_IPC", "1");
    });
  `;
}

function validExitPlan() {
  return [
    "VITE_DESKTOP_GENERIC_IPC_POLICY=disabled",
    "VITE_DESKTOP_GENERIC_IPC_POLICY=compat",
    "rollback",
    "Do not remove browser-dev HTTP/SSE debugging",
  ].join("\n");
}

function validPackageJson() {
  return {
    scripts: {
      "desktop-generic-ipc-rollback:check": "node scripts/check-desktop-generic-ipc-rollback-guard.mjs",
      ci: "pnpm run desktop-generic-ipc-rollback:check",
    },
  };
}

describe("check-desktop-generic-ipc-rollback-guard script", () => {
  it("accepts the explicit compat rollback contract", () => {
    const rootDir = createFixture();

    expect(findDesktopGenericIpcRollbackGuardViolations({ rootDir })).toEqual([]);
  });

  it("requires a policy test for explicit compat overriding the legacy disable alias", () => {
    const rootDir = createFixture({
      policyTest: `it("does not cover rollback", () => {});`,
    });

    expect(findDesktopGenericIpcRollbackGuardViolations({ rootDir })).toContain(
      "frontend/src/app/integrations/desktopGenericIpcPolicy.test.ts: missing rollback guard token lets an explicit compat policy override the legacy disable alias",
    );
  });

  it("requires the exit plan to document the compat rollback switch", () => {
    const rootDir = createFixture({
      exitPlan: ["VITE_DESKTOP_GENERIC_IPC_POLICY=disabled", "rollback"].join("\n"),
    });

    expect(findDesktopGenericIpcRollbackGuardViolations({ rootDir })).toContain(
      "docs/desktop-ipc-old-binding-exit-plan.md: missing rollback guard token VITE_DESKTOP_GENERIC_IPC_POLICY=compat",
    );
  });

  it("requires frontend CI to run the rollback guard", () => {
    const rootDir = createFixture({
      packageJson: {
        scripts: {
          "desktop-generic-ipc-rollback:check": "node scripts/check-desktop-generic-ipc-rollback-guard.mjs",
          ci: "pnpm run desktop-generic-ipc-retirement:check",
        },
      },
    });

    expect(findDesktopGenericIpcRollbackGuardViolations({ rootDir })).toContain(
      "frontend/package.json: ci must run desktop-generic-ipc-rollback:check",
    );
  });
});
