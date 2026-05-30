import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { findDesktopGenericIpcRetirementReadinessViolations } from "./check-desktop-generic-ipc-retirement-readiness.mjs";

function createFixture({ bridge, smoke, exitPlan, tracker, packageJson }) {
  const rootDir = mkdtempSync(resolve(tmpdir(), "meow-traffic-generic-ipc-retirement-"));
  writeFixture(rootDir, "frontend/src/app/integrations/desktopBridge.ts", bridge ?? validBridge());
  writeFixture(rootDir, "frontend/src/app/integrations/desktopGenericIpcPolicy.ts", validPolicy());
  writeFixture(
    rootDir,
    "frontend/src/app/integrations/desktopDisabledGenericIpcTransport.ts",
    validDisabledTransport(),
  );
  writeFixture(rootDir, "scripts/check-desktop-ipc-smoke.ps1", smoke ?? validSmokeScript());
  writeFixture(rootDir, "docs/desktop-ipc-old-binding-exit-plan.md", exitPlan ?? validExitPlan());
  writeFixture(rootDir, "docs/desktop-ipc-iteration-status.json", JSON.stringify(tracker ?? validTracker()));
  writeFixture(rootDir, "frontend/package.json", JSON.stringify(packageJson ?? validPackageJson()));
  return rootDir;
}

function writeFixture(rootDir, relativePath, content) {
  const path = resolve(rootDir, relativePath);
  mkdirSync(resolve(path, ".."), { recursive: true });
  writeFileSync(path, content);
}

function validBridge() {
  return `
    import { isDesktopGenericIpcDisabled } from "./desktopGenericIpcPolicy";
    import { createDisabledGenericIpcBackendTransport } from "./desktopDisabledGenericIpcTransport";
    export function isDesktopGenericIpcDisableExperimentEnabled() {
      return String(import.meta.env.VITE_DESKTOP_DISABLE_GENERIC_IPC ?? "").trim() === "1";
    }
    export const genericIpcDisabled = isDesktopGenericIpcDisabled();
  `;
}

function validPolicy() {
  return `
    export function resolveDesktopGenericIpcPolicy(env = import.meta.env) {
      const policy = String(env.VITE_DESKTOP_GENERIC_IPC_POLICY ?? "").trim().toLowerCase();
      const explicitPolicy = policy;
      if (explicitPolicy === "compat") return "compat";
      String(env.VITE_DESKTOP_DISABLE_GENERIC_IPC ?? "").trim() === "1";
      return "disabled";
    }
    export function isDesktopGenericIpcDisabled(env = import.meta.env) {
      resolveDesktopGenericIpcPolicy(env);
      return true;
    }
  `;
}

function validDisabledTransport() {
  return `
    export const code = "generic_ipc_disabled";
    import { subscribeDesktopEvents } from "./desktopEventTransport";
    export function createDisabledGenericIpcBackendTransport() { return { subscribeEvents: subscribeDesktopEvents }; }
  `;
}

function validSmokeScript() {
  return `
    param([switch]$DisableGenericIpcAdapterExperiment)
    $env:MEOW_TRAFFIC_DESKTOP_DISABLE_GENERIC_IPC_EXPERIMENT = "1"
    $result.genericIpcPolicy
    $result.genericIpcDisableExperimentRequested
    $result.genericIpcDisableExperimentBuildFlag
  `;
}

function validExitPlan() {
  return [
    "VITE_DESKTOP_DISABLE_GENERIC_IPC=1",
    "VITE_DESKTOP_GENERIC_IPC_POLICY=disabled",
    "VITE_DESKTOP_GENERIC_IPC_POLICY=compat",
    "DisableGenericIpcAdapterExperiment",
    "three consecutive default-disabled observation rounds",
    "genericIpcDisableExperimentBuildFlag = true",
    "Do not remove browser-dev HTTP/SSE debugging",
  ].join("\n");
}

function validTracker() {
  return {
    domains: {
      genericIpcAdapterDisableExperiment: {
        status: "release-candidate-default-disabled",
        flag: "VITE_DESKTOP_DISABLE_GENERIC_IPC=1",
        failureCode: "generic_ipc_disabled",
        lastExperimentSmoke: {
          genericIpcDisableExperimentBuildFlag: true,
          desktopWebviewDirectBackendApiRequestCount: 0,
          browserDevOk: true,
        },
      },
      genericIpcAdapterDefaultDisabledReleaseCandidate: {
        rollbackPolicy: "VITE_DESKTOP_GENERIC_IPC_POLICY=compat",
        adapterRemoved: false,
        observation: {
          requiredConsecutiveGreenRoundsBeforeRemoval: 3,
          currentConsecutiveGreenRounds: 1,
          rounds: [
            {
              id: "round-25",
              genericIpcPolicy: "disabled",
              compatRollbackPolicy: "compat",
              directBackendApiRequestCount: 0,
              browserDevOk: true,
              adapterRemoved: false,
            },
          ],
        },
      },
    },
  };
}

function validPackageJson() {
  return {
    scripts: {
      "desktop-generic-ipc-retirement:check": "node scripts/check-desktop-generic-ipc-retirement-readiness.mjs",
      ci: "pnpm run desktop-generic-ipc-retirement:check",
    },
  };
}

describe("check-desktop-generic-ipc-retirement-readiness script", () => {
  it("accepts the default-disabled release-candidate contract with compat policy value", () => {
    const rootDir = createFixture({});

    expect(findDesktopGenericIpcRetirementReadinessViolations({ rootDir })).toEqual([]);
  });

  it("rejects tracker evidence that does not prove the disabled-adapter smoke was built with the flag", () => {
    const tracker = validTracker();
    tracker.domains.genericIpcAdapterDisableExperiment.lastExperimentSmoke.genericIpcDisableExperimentBuildFlag = false;
    const rootDir = createFixture({ tracker });

    expect(findDesktopGenericIpcRetirementReadinessViolations({ rootDir })).toContain(
      "docs/desktop-ipc-iteration-status.json: lastExperimentSmoke.genericIpcDisableExperimentBuildFlag must record true evidence",
    );
  });

  it("rejects promoting the legacy desktop bridge disablement alias to the default", () => {
    const rootDir = createFixture({
      bridge: `
        import { createDisabledGenericIpcBackendTransport } from "./desktopDisabledGenericIpcTransport";
        export function isDesktopGenericIpcDisableExperimentEnabled() {
          return String(import.meta.env.VITE_DESKTOP_DISABLE_GENERIC_IPC ?? "1").trim() === "1";
        }
      `,
    });

    expect(findDesktopGenericIpcRetirementReadinessViolations({ rootDir })).toContain(
      "frontend/src/app/integrations/desktopBridge.ts: do not promote the legacy VITE_DESKTOP_DISABLE_GENERIC_IPC alias to the default; use the policy resolver default instead",
    );
  });

  it("requires the release candidate policy to default to disabled", () => {
    const rootDir = createFixture({});
    writeFixture(
      rootDir,
      "frontend/src/app/integrations/desktopGenericIpcPolicy.ts",
      `
        export function resolveDesktopGenericIpcPolicy(env = import.meta.env) {
          const explicitPolicy = String(env.VITE_DESKTOP_GENERIC_IPC_POLICY ?? "").trim().toLowerCase();
          if (explicitPolicy === "compat") return "compat";
          return "compat";
        }
        export function isDesktopGenericIpcDisabled(env = import.meta.env) {
          resolveDesktopGenericIpcPolicy(env);
          return true;
        }
      `,
    );

    expect(findDesktopGenericIpcRetirementReadinessViolations({ rootDir })).toContain(
      "frontend/src/app/integrations/desktopGenericIpcPolicy.ts: Round 24 release candidate must default to disabled when no explicit compat policy is set",
    );
  });

  it("requires the explicit compat policy value to remain available", () => {
    const rootDir = createFixture({});
    writeFixture(
      rootDir,
      "frontend/src/app/integrations/desktopGenericIpcPolicy.ts",
      `
        export function resolveDesktopGenericIpcPolicy(env = import.meta.env) {
          const explicitPolicy = String(env.VITE_DESKTOP_GENERIC_IPC_POLICY ?? "").trim().toLowerCase();
          return "disabled";
        }
        export function isDesktopGenericIpcDisabled(env = import.meta.env) {
          resolveDesktopGenericIpcPolicy(env);
          return true;
        }
      `,
    );

    expect(findDesktopGenericIpcRetirementReadinessViolations({ rootDir })).toContain(
      "frontend/src/app/integrations/desktopGenericIpcPolicy.ts: explicit VITE_DESKTOP_GENERIC_IPC_POLICY=compat policy value must remain recognizable",
    );
  });

  it("requires tracker to record the explicit compat policy value", () => {
    const tracker = validTracker();
    tracker.domains.genericIpcAdapterDefaultDisabledReleaseCandidate.rollbackPolicy = "missing";
    const rootDir = createFixture({ tracker });

    expect(findDesktopGenericIpcRetirementReadinessViolations({ rootDir })).toContain(
      "docs/desktop-ipc-iteration-status.json: genericIpcAdapterDefaultDisabledReleaseCandidate.rollbackPolicy must preserve the VITE_DESKTOP_GENERIC_IPC_POLICY=compat policy value",
    );
  });

  it("requires compat to remain a documented no-op after adapter removal candidate", () => {
    const rootDir = createFixture({});
    writeFixture(
      rootDir,
      "frontend/src/app/integrations/desktopGenericIpcPolicy.ts",
      `
        export function resolveDesktopGenericIpcPolicy(env = import.meta.env) {
          const explicitPolicy = String(env.VITE_DESKTOP_GENERIC_IPC_POLICY ?? "").trim().toLowerCase();
          if (explicitPolicy === "compat") return "compat";
          return "disabled";
        }
        export function isDesktopGenericIpcDisabled(env = import.meta.env) {
          return resolveDesktopGenericIpcPolicy(env) === "disabled";
        }
      `,
    );

    expect(findDesktopGenericIpcRetirementReadinessViolations({ rootDir })).toContain(
      "frontend/src/app/integrations/desktopGenericIpcPolicy.ts: after adapter removal candidate, compat must remain a documented no-op and generic IPC must stay disabled",
    );
  });

  it("blocks adapter removal before three consecutive green observation rounds", () => {
    const tracker = validTracker();
    tracker.domains.genericIpcAdapterDefaultDisabledReleaseCandidate.adapterRemoved = true;
    const rootDir = createFixture({ tracker });

    expect(findDesktopGenericIpcRetirementReadinessViolations({ rootDir })).toContain(
      "docs/desktop-ipc-iteration-status.json: generic IPC adapter removal is blocked until three consecutive green default-disabled observation rounds",
    );
  });

  it("requires observation evidence for the latest counted default-disabled round", () => {
    const tracker = validTracker();
    tracker.domains.genericIpcAdapterDefaultDisabledReleaseCandidate.observation.rounds[0].browserDevOk = false;
    const rootDir = createFixture({ tracker });

    expect(findDesktopGenericIpcRetirementReadinessViolations({ rootDir })).toContain(
      "docs/desktop-ipc-iteration-status.json: observation round round-25 browserDevOk must be true",
    );
  });

  it("requires evidence for every counted default-disabled observation round", () => {
    const tracker = validTracker();
    tracker.domains.genericIpcAdapterDefaultDisabledReleaseCandidate.observation.currentConsecutiveGreenRounds = 2;
    tracker.domains.genericIpcAdapterDefaultDisabledReleaseCandidate.observation.rounds.push({
      id: "round-26",
      genericIpcPolicy: "disabled",
      compatRollbackPolicy: "compat",
      directBackendApiRequestCount: 1,
      browserDevOk: true,
      adapterRemoved: false,
    });
    const rootDir = createFixture({ tracker });

    expect(findDesktopGenericIpcRetirementReadinessViolations({ rootDir })).toContain(
      "docs/desktop-ipc-iteration-status.json: observation round round-26 directBackendApiRequestCount must remain 0",
    );
  });

  it("requires frontend CI to run the retirement readiness check", () => {
    const rootDir = createFixture({
      packageJson: {
        scripts: {
          "desktop-generic-ipc-retirement:check": "node scripts/check-desktop-generic-ipc-retirement-readiness.mjs",
          ci: "pnpm run desktop-generic-ipc:check",
        },
      },
    });

    expect(findDesktopGenericIpcRetirementReadinessViolations({ rootDir })).toContain(
      "frontend/package.json: ci must run desktop-generic-ipc-retirement:check",
    );
  });
});
