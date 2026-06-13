import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  collectBindingCleanupFacts,
  findDesktopGenericIpcBindingCleanupPreflightViolations,
} from "./check-desktop-generic-ipc-binding-cleanup-preflight.mjs";

function createFixture({
  tracker = validTracker(),
  packageJson = validPackageJson(),
  backend = validBackend(),
  backendTest = validBackendTest(),
} = {}) {
  const rootDir = mkdtempSync(resolve(tmpdir(), "meow-traffic-generic-ipc-binding-cleanup-preflight-"));
  writeFixture(rootDir, "desktop_backend_proxy.go", backend);
  writeFixture(rootDir, "desktop_backend_proxy_test.go", backendTest);
  writeFixture(rootDir, "frontend/wailsjs/go/main/DesktopApp.d.ts", validGeneratedDts());
  writeFixture(rootDir, "frontend/wailsjs/go/main/DesktopApp.js", validGeneratedJs());
  writeFixture(rootDir, "frontend/src/app/integrations/desktopTransportBindingShell.ts", validBindingShell());
  writeFixture(rootDir, "frontend/src/app/integrations/ipcBackendTransport.ts", validIpcBackendTransport());
  writeFixture(
    rootDir,
    "frontend/src/app/integrations/desktopDisabledGenericIpcTransport.ts",
    validDisabledGenericIpcTransport(),
  );
  writeFixture(rootDir, "frontend/src/app/integrations/desktopIpcControls.ts", validDesktopIpcControls());
  writeFixture(rootDir, "frontend/src/app/integrations/desktopBridge.ts", validDesktopBridge());
  writeFixture(rootDir, "frontend/scripts/check-wails-bindings.mjs", validWailsBindingCheck());
  writeFixture(rootDir, "frontend/scripts/check-desktop-old-binding-compat.mjs", validOldBindingCompat());
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

function validBackend() {
  return `
    package main

    func (a *DesktopApp) DownloadObjectsZip(ids []int) (desktopBackendBlob, error) {
      return a.invokeBackendBlob(desktopBackendRequest{})
    }

    func (a *DesktopApp) GetWinRMDecryptResultText(resultID string) (string, error) {
      return a.invokeBackendText(desktopBackendRequest{})
    }
  `;
}

function validBackendTest() {
  return `
    package main

    func TestDesktopTypedJSONProxiesRequest(t *testing.T) {
      _, _ = app.GetIndustrialAnalysis()
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

function validBindingShell() {
  return `
    export interface DesktopShellBinding {
      GetBackendAuthToken?: () => Promise<string>;
    }
  `;
}

function validIpcBackendTransport() {
  return "";
}

function validDisabledGenericIpcTransport() {
  return `
    export function createDisabledGenericIpcBackendTransport() {
      throw new Error("generic_ipc_disabled");
    }
  `;
}

function validDesktopIpcControls() {
  return `
    export class DesktopIpcRequestError extends Error {}
    export interface IpcBackendTransport {}
    export const DESKTOP_IPC_BLOB_MAX_BYTES = 50;
    export function withDesktopIpcControls() {}
  `;
}

function validDesktopBridge() {
  return `
    export function createDesktopBridge() {
      return createDisabledGenericIpcBackendTransport();
    }
  `;
}

function validWailsBindingCheck() {
  return `
    const forbiddenGeneratedBindings = ["InvokeBackendJSON", "InvokeBackendBlob", "InvokeBackendText"];
  `;
}

function validOldBindingCompat() {
  return `
    function extractDesktopBindingUses() {}
    const allowedOldBindingMethodsByFile = {};
  `;
}

function validTracker() {
  return {
    domains: {
      genericIpcBackendGeneratedBindingCleanupPreflight: {
        status: "deletion-completed",
        deletionReady: true,
        backendGeneratedBindingsRemoved: true,
        frontendAdapterConstructionRemoved: true,
        inventory: {
          backendExportedMethods: [],
          typedHelperReuse: [],
          generatedBindings: [],
          frontendBindingSurfaces: [
            "frontend/src/app/integrations/desktopDisabledGenericIpcTransport.ts exports createDisabledGenericIpcBackendTransport",
            "frontend/src/app/integrations/desktopDisabledGenericIpcTransport.ts reports generic_ipc_disabled",
            "frontend/src/app/integrations/desktopIpcControls.ts exports DesktopIpcRequestError, IpcBackendTransport, withDesktopIpcControls, and blob limit checks",
          ],
          guardrailDependencies: [
            "frontend/scripts/check-wails-bindings.mjs forbids removed InvokeBackend* bindings",
            "frontend/scripts/check-desktop-old-binding-compat.mjs rejects unapproved InvokeBackend* inventory",
          ],
        },
        blockers: [],
        nextDeletionPrerequisites: [],
      },
    },
  };
}

function validPackageJson() {
  return {
    scripts: {
      "desktop-generic-ipc-binding-cleanup-preflight:check":
        "node scripts/check-desktop-generic-ipc-binding-cleanup-preflight.mjs",
      "ci:desktop": "pnpm run desktop-generic-ipc-binding-cleanup-preflight:check",
      ci: "pnpm run ci:desktop",
    },
  };
}

function validPlan() {
  return [
    "backend/generated generic IPC binding cleanup",
    "deletionReady = true",
    "typed helper reuse",
    "check-wails-bindings",
    "removed InvokeBackendJSON",
    "removed InvokeBackendBlob",
    "removed InvokeBackendText",
    "desktopDisabledGenericIpcTransport.ts",
  ].join("\n");
}

describe("check-desktop-generic-ipc-binding-cleanup-preflight script", () => {
  it("accepts the completed backend/generated binding cleanup inventory", () => {
    const rootDir = createFixture();

    expect(findDesktopGenericIpcBindingCleanupPreflightViolations({ rootDir })).toEqual([]);
  });

  it("accepts zero typed helper reuse after typed blob/text helper split", () => {
    const rootDir = createFixture();

    expect(collectBindingCleanupFacts({ rootDir }).typedHelperReuse).toEqual([]);
  });

  it("extracts typed helper reuse separately from exported generic helpers", () => {
    const rootDir = createFixture({
      backend: `
        package main

        func (a *DesktopApp) InvokeBackendJSON(req desktopBackendRequest) (any, error) { return nil, nil }
        func (a *DesktopApp) InvokeBackendBlob(req desktopBackendRequest) (desktopBackendBlob, error) { return desktopBackendBlob{}, nil }
        func (a *DesktopApp) InvokeBackendText(req desktopBackendRequest) (string, error) { return "", nil }

        func (a *DesktopApp) DownloadObjectsZip(ids []int) (desktopBackendBlob, error) {
          return a.InvokeBackendBlob(desktopBackendRequest{})
        }

        func (a *DesktopApp) GetWinRMDecryptResultText(resultID string) (string, error) {
          return a.InvokeBackendText(desktopBackendRequest{})
        }
      `,
    });

    expect(collectBindingCleanupFacts({ rootDir }).typedHelperReuse).toEqual([
      { method: "DownloadObjectsZip", helper: "InvokeBackendBlob", line: 9 },
      { method: "GetWinRMDecryptResultText", helper: "InvokeBackendText", line: 13 },
    ]);
  });

  it("rejects keeping preflight status after blockers are cleared", () => {
    const tracker = validTracker();
    tracker.domains.genericIpcBackendGeneratedBindingCleanupPreflight.status = "preflight-completed";
    const rootDir = createFixture({ tracker });

    expect(findDesktopGenericIpcBindingCleanupPreflightViolations({ rootDir })).toContain(
      "docs/desktop-ipc-iteration-status.json: genericIpcBackendGeneratedBindingCleanupPreflight.status must be deletion-completed after blockers are cleared",
    );
  });

  it("rejects stale typed helper reuse inventory", () => {
    const tracker = validTracker();
    tracker.domains.genericIpcBackendGeneratedBindingCleanupPreflight.inventory.typedHelperReuse = [
      "DownloadObjectsZip -> InvokeBackendBlob",
    ];
    const rootDir = createFixture({ tracker });

    expect(findDesktopGenericIpcBindingCleanupPreflightViolations({ rootDir })).toContain(
      "docs/desktop-ipc-iteration-status.json: genericIpcBackendGeneratedBindingCleanupPreflight.inventory.typedHelperReuse has stale entry DownloadObjectsZip -> InvokeBackendBlob",
    );
  });

  it("rejects desktopBridge adapter construction regressions", () => {
    const rootDir = createFixture();
    writeFixture(
      rootDir,
      "frontend/src/app/integrations/desktopBridge.ts",
      `
        export function createDesktopBridge(desktopApp) {
          return createIpcBackendTransport(desktopApp);
        }
      `,
    );

    expect(findDesktopGenericIpcBindingCleanupPreflightViolations({ rootDir })).toContain(
      "frontend/src/app/integrations/desktopBridge.ts: generic IPC adapter construction must remain removed",
    );
  });

  it("requires frontend CI to run the cleanup preflight guardrail", () => {
    const rootDir = createFixture({
      packageJson: {
        scripts: {
          "desktop-generic-ipc-binding-cleanup-preflight:check":
            "node scripts/check-desktop-generic-ipc-binding-cleanup-preflight.mjs",
          ci: "pnpm run test:run",
        },
      },
    });

    expect(findDesktopGenericIpcBindingCleanupPreflightViolations({ rootDir })).toContain(
      "frontend/package.json: ci must run desktop-generic-ipc-binding-cleanup-preflight:check",
    );
  });
});
