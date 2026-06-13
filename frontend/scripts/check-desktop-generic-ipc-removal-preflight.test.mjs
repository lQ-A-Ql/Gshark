import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { findDesktopGenericIpcRemovalPreflightViolations } from "./check-desktop-generic-ipc-removal-preflight.mjs";

function createFixture({ tracker = validTracker(), extraSource = "", packageJson = validPackageJson() } = {}) {
  const rootDir = mkdtempSync(resolve(tmpdir(), "meow-traffic-generic-ipc-removal-preflight-"));
  writeFixture(rootDir, "frontend/src/app/integrations/desktopBridge.ts", validDesktopBridge());
  writeFixture(rootDir, "frontend/src/app/integrations/desktopTransportBindingShell.ts", validBindingShell());
  writeFixture(rootDir, "frontend/wailsjs/go/main/DesktopApp.d.ts", validGeneratedDts());
  writeFixture(rootDir, "frontend/wailsjs/go/main/DesktopApp.js", validGeneratedJs());
  writeFixture(rootDir, "frontend/src/app/integrations/clients/example.ts", extraSource);
  writeFixture(rootDir, "docs/desktop-ipc-iteration-status.json", JSON.stringify(tracker));
  writeFixture(rootDir, "docs/desktop-ipc-migration-plan.md", validPlan());
  writeFixture(rootDir, "docs/desktop-ipc-old-binding-exit-plan.md", validPlan());
  writeFixture(rootDir, "frontend/package.json", JSON.stringify(packageJson));
  return rootDir;
}

function writeFixture(rootDir, relativePath, content) {
  const path = resolve(rootDir, relativePath);
  mkdirSync(resolve(path, ".."), { recursive: true });
  writeFileSync(path, content);
}

function validDesktopBridge() {
  return `
    export function bridge(desktopApp) {
      return desktopApp ? "typed-only" : null;
    }
  `;
}

function validBindingShell() {
  return `
    export interface DesktopShellBinding {
      GetBackendAuthToken?: () => Promise<string>;
    }
  `;
}

function validGeneratedDts() {
  return `
    export function ListObjects():Promise<any>;
  `;
}

function validGeneratedJs() {
  return `
    export function ListObjects() { return window.go.main.DesktopApp.ListObjects(); }
  `;
}

function validTracker() {
  return {
    domains: {
      genericIpcAdapterDefaultDisabledReleaseCandidate: {
        adapterRemoved: false,
        observation: {
          requiredConsecutiveGreenRoundsBeforeRemoval: 3,
          currentConsecutiveGreenRounds: 3,
          removalAllowed: true,
          rounds: [
            validObservationRound("round-25"),
            validObservationRound("round-26"),
            validObservationRound("round-27"),
          ],
        },
      },
      genericIpcAdapterRemovalPreflight: {
        status: "preflight-completed",
        adapterRemoved: false,
        inventory: {
          productionSource: [
            "frontend/src/app/integrations/desktopBridge.ts",
            "frontend/src/app/integrations/desktopTransportBindingShell.ts",
          ],
          generatedBindings: ["frontend/wailsjs/go/main/DesktopApp.d.ts", "frontend/wailsjs/go/main/DesktopApp.js"],
        },
        rollbackRequirements: ["VITE_DESKTOP_GENERIC_IPC_POLICY=compat", "browser-dev HTTP/SSE"],
        reversibleDeletionPlan: ["remove adapter in one branch", "restore adapter files if smoke fails"],
      },
    },
  };
}

function validObservationRound(id) {
  return {
    id,
    genericIpcPolicy: "disabled",
    compatRollbackPolicy: "compat",
    directBackendApiRequestCount: 0,
    browserDevOk: true,
    adapterRemoved: false,
  };
}

function validPlan() {
  return [
    "adapter removal preflight",
    "removed InvokeBackendJSON",
    "removed InvokeBackendBlob",
    "removed InvokeBackendText",
    "createIpcBackendTransport",
    "VITE_DESKTOP_GENERIC_IPC_POLICY=compat",
    "browser-dev HTTP/SSE",
    "reversible deletion plan",
  ].join("\n");
}

function validPackageJson() {
  return {
    scripts: {
      "desktop-generic-ipc-removal-preflight:check": "node scripts/check-desktop-generic-ipc-removal-preflight.mjs",
      "ci:desktop": "pnpm run desktop-generic-ipc-removal-preflight:check",
      ci: "pnpm run ci:desktop",
    },
  };
}

describe("check-desktop-generic-ipc-removal-preflight script", () => {
  it("accepts a completed three-round preflight with adapter and generated generic bindings removed", () => {
    const rootDir = createFixture();

    expect(findDesktopGenericIpcRemovalPreflightViolations({ rootDir })).toEqual([]);
  });

  it("accepts the candidate-completed contract after frontend adapter construction removal", () => {
    const tracker = validTracker();
    tracker.domains.genericIpcAdapterRemovalPreflight.status = "candidate-completed";
    tracker.domains.genericIpcAdapterRemovalPreflight.frontendAdapterConstructionRemoved = true;
    const rootDir = createFixture({ tracker });

    expect(findDesktopGenericIpcRemovalPreflightViolations({ rootDir })).toEqual([]);
  });

  it("accepts the deletion-completed contract after backend/generated cleanup", () => {
    const tracker = validTracker();
    tracker.domains.genericIpcAdapterRemovalPreflight.status = "deletion-completed";
    tracker.domains.genericIpcAdapterRemovalPreflight.frontendAdapterConstructionRemoved = true;
    tracker.domains.genericIpcAdapterRemovalPreflight.adapterRemoved = true;
    tracker.domains.genericIpcBackendGeneratedBindingCleanupPreflight = {
      backendGeneratedBindingsRemoved: true,
    };
    const rootDir = createFixture({ tracker });

    expect(findDesktopGenericIpcRemovalPreflightViolations({ rootDir })).toEqual([]);
  });

  it("requires three green default-disabled observation rounds", () => {
    const tracker = validTracker();
    tracker.domains.genericIpcAdapterDefaultDisabledReleaseCandidate.observation.currentConsecutiveGreenRounds = 2;
    const rootDir = createFixture({ tracker });

    expect(findDesktopGenericIpcRemovalPreflightViolations({ rootDir })).toContain(
      "docs/desktop-ipc-iteration-status.json: removal preflight requires currentConsecutiveGreenRounds = 3",
    );
  });

  it("rejects adapterRemoved before backend/generated cleanup deletion", () => {
    const tracker = validTracker();
    tracker.domains.genericIpcAdapterRemovalPreflight.adapterRemoved = true;
    const rootDir = createFixture({ tracker });

    expect(findDesktopGenericIpcRemovalPreflightViolations({ rootDir })).toContain(
      "docs/desktop-ipc-iteration-status.json: genericIpcAdapterRemovalPreflight.adapterRemoved must remain false before backend/generated cleanup deletion",
    );
  });

  it("rejects desktopBridge adapter construction after the candidate removal", () => {
    const rootDir = createFixture();
    writeFixture(
      rootDir,
      "frontend/src/app/integrations/desktopBridge.ts",
      `
        export function bridge(desktopApp) {
          return desktopApp.InvokeBackendJSON ? "bad" : null;
        }
      `,
    );

    expect(findDesktopGenericIpcRemovalPreflightViolations({ rootDir })).toContain(
      "frontend/src/app/integrations/desktopBridge.ts: generic IPC adapter construction must be removed for the candidate",
    );
  });

  it("requires adapterRemoved after backend/generated cleanup deletion", () => {
    const tracker = validTracker();
    tracker.domains.genericIpcBackendGeneratedBindingCleanupPreflight = {
      backendGeneratedBindingsRemoved: true,
    };
    tracker.domains.genericIpcAdapterRemovalPreflight.adapterRemoved = false;
    const rootDir = createFixture({ tracker });

    expect(findDesktopGenericIpcRemovalPreflightViolations({ rootDir })).toContain(
      "docs/desktop-ipc-iteration-status.json: genericIpcAdapterRemovalPreflight.adapterRemoved must be true after backend/generated cleanup deletion",
    );
  });

  it("rejects new generic IPC adapter references outside the inventory", () => {
    const rootDir = createFixture({
      extraSource: "export const leak = desktopApp.InvokeBackendJSON;",
    });

    expect(findDesktopGenericIpcRemovalPreflightViolations({ rootDir })).toContain(
      "frontend/src/app/integrations/clients/example.ts: unexpected generic IPC adapter token InvokeBackendJSON",
    );
  });

  it("requires the compat policy value and reversible deletion plan to be recorded in tracker", () => {
    const tracker = validTracker();
    tracker.domains.genericIpcAdapterRemovalPreflight.rollbackRequirements = [];
    tracker.domains.genericIpcAdapterRemovalPreflight.reversibleDeletionPlan = [];
    const rootDir = createFixture({ tracker });

    expect(findDesktopGenericIpcRemovalPreflightViolations({ rootDir })).toEqual(
      expect.arrayContaining([
        "docs/desktop-ipc-iteration-status.json: genericIpcAdapterRemovalPreflight.rollbackRequirements must be non-empty",
        "docs/desktop-ipc-iteration-status.json: genericIpcAdapterRemovalPreflight.reversibleDeletionPlan must be non-empty",
      ]),
    );
  });

  it("requires frontend CI to run the preflight guardrail", () => {
    const rootDir = createFixture({
      packageJson: {
        scripts: {
          "desktop-generic-ipc-removal-preflight:check": "node scripts/check-desktop-generic-ipc-removal-preflight.mjs",
          ci: "pnpm run desktop-generic-ipc-retirement:check",
        },
      },
    });

    expect(findDesktopGenericIpcRemovalPreflightViolations({ rootDir })).toContain(
      "frontend/package.json: ci must run desktop-generic-ipc-removal-preflight:check",
    );
  });
});
