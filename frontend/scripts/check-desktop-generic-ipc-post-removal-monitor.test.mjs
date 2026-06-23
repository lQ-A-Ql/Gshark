import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { findDesktopGenericIpcPostRemovalMonitorViolations } from "./check-desktop-generic-ipc-post-removal-monitor.mjs";

function createFixture({
  backendProxy = validBackendProxy(),
  desktopBridge = validDesktopBridge(),
  generatedDts = validGeneratedDts(),
  generatedJs = validGeneratedJs(),
  readme = validReadme(),
  tracker = validTracker(),
  packageJson = validPackageJson(),
  extraSource = "",
} = {}) {
  const rootDir = mkdtempSync(resolve(tmpdir(), "meow-traffic-generic-ipc-post-removal-"));
  writeFixture(rootDir, "desktop_backend_proxy.go", backendProxy);
  writeFixture(rootDir, "frontend/src/app/integrations/desktopBridge.ts", desktopBridge);
  writeFixture(rootDir, "frontend/src/app/integrations/desktopIpcControls.ts", validDesktopIpcControls());
  writeFixture(rootDir, "frontend/src/app/integrations/clients/example.ts", extraSource);
  writeFixture(rootDir, "frontend/wailsjs/go/main/DesktopApp.d.ts", generatedDts);
  writeFixture(rootDir, "frontend/wailsjs/go/main/DesktopApp.js", generatedJs);
  writeFixture(rootDir, "README.md", readme);
  writeFixture(rootDir, "docs/desktop-ipc-iteration-status.json", JSON.stringify(tracker));
  writeFixture(rootDir, "frontend/package.json", JSON.stringify(packageJson));
  return rootDir;
}

function writeFixture(rootDir, relativePath, content) {
  const path = resolve(rootDir, relativePath);
  mkdirSync(resolve(path, ".."), { recursive: true });
  writeFileSync(path, content);
}

function validBackendProxy() {
  return `
    package main
    func (a *DesktopApp) ListObjects() (any, error) { return nil, nil }
  `;
}

function validDesktopBridge() {
  return `
    export function createDesktopBridge() {
      return "typed-only";
    }
  `;
}

function validDesktopIpcControls() {
  return `
    export class DesktopIpcRequestError extends Error {}
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

function validReadme() {
  return [
    "Wails desktop data-plane now uses typed IPC first.",
    "Missing typed routes fail with typed_binding_required.",
    "browser-dev HTTP/SSE remains available.",
    "Wails runtime events remain the desktop event channel.",
  ].join("\n");
}

function validTracker() {
  return {
    domains: {
      genericIpcAdapterRemovalPreflight: {
        status: "deletion-completed",
        adapterRemoved: true,
        frontendAdapterConstructionRemoved: true,
        backendGeneratedBindingsRemoved: true,
      },
      genericIpcBackendGeneratedBindingCleanupPreflight: {
        status: "deletion-completed",
        deletionReady: true,
        backendGeneratedBindingsRemoved: true,
        postRemovalAudit: {
          status: "completed",
          fullGatesRun: true,
          desktopWebviewSmokeRun: true,
          browserDevSmokeRun: true,
          evidence: {
            directBackendApiRequestCount: 0,
            totalInstrumentedNetworkRequests: 0,
            browserDevOk: true,
          },
        },
      },
    },
    openBlockers: [],
  };
}

function validPackageJson() {
  return {
    scripts: {
      "desktop-generic-ipc-post-removal:check": "node scripts/check-desktop-generic-ipc-post-removal-monitor.mjs",
      "ci:desktop": "pnpm run desktop-generic-ipc-post-removal:check",
      ci: "pnpm run ci:desktop",
    },
  };
}

describe("check-desktop-generic-ipc-post-removal-monitor script", () => {
  it("accepts the post-removal source and tracker contract", () => {
    const rootDir = createFixture();

    expect(findDesktopGenericIpcPostRemovalMonitorViolations({ rootDir })).toEqual([]);
  });

  it("rejects reintroduced backend InvokeBackendJSON binding", () => {
    const rootDir = createFixture({
      backendProxy: `
        package main
        func (a *DesktopApp) InvokeBackendJSON(req any) (any, error) { return nil, nil }
      `,
    });

    expect(findDesktopGenericIpcPostRemovalMonitorViolations({ rootDir })).toContain(
      "desktop_backend_proxy.go: removed generic IPC binding token InvokeBackendJSON must not reappear",
    );
  });

  it("rejects reintroduced frontend generic IPC adapter construction", () => {
    const rootDir = createFixture({
      desktopBridge: `
        export function createDesktopBridge() {
          return createIpcBackendTransport();
        }
      `,
    });

    expect(findDesktopGenericIpcPostRemovalMonitorViolations({ rootDir })).toContain(
      "frontend/src/app/integrations/desktopBridge.ts: removed generic IPC adapter token createIpcBackendTransport must not reappear",
    );
  });

  it("rejects a restored legacy adapter file even if it is empty", () => {
    const rootDir = createFixture();
    writeFixture(rootDir, "frontend/src/app/integrations/ipcBackendTransport.ts", "");

    expect(findDesktopGenericIpcPostRemovalMonitorViolations({ rootDir })).toContain(
      "frontend/src/app/integrations/ipcBackendTransport.ts: legacy generic IPC adapter file must remain deleted",
    );
  });

  it("rejects stale README references to removed generated bindings", () => {
    const rootDir = createFixture({
      readme: `${validReadme()}\nInvokeBackendBlob`,
    });

    expect(findDesktopGenericIpcPostRemovalMonitorViolations({ rootDir })).toContain(
      "README.md: stale removed binding reference InvokeBackendBlob",
    );
  });

  it("requires tracker post-removal audit evidence to remain green", () => {
    const tracker = validTracker();
    tracker.domains.genericIpcBackendGeneratedBindingCleanupPreflight.postRemovalAudit.evidence.browserDevOk = false;
    const rootDir = createFixture({ tracker });

    expect(findDesktopGenericIpcPostRemovalMonitorViolations({ rootDir })).toContain(
      "docs/desktop-ipc-iteration-status.json: postRemovalAudit.evidence.browserDevOk must be true",
    );
  });

  it("requires frontend CI to run the monitor", () => {
    const rootDir = createFixture({
      packageJson: {
        scripts: {
          "desktop-generic-ipc-post-removal:check": "node scripts/check-desktop-generic-ipc-post-removal-monitor.mjs",
          ci: "pnpm run desktop-route-classification:check",
        },
      },
    });

    expect(findDesktopGenericIpcPostRemovalMonitorViolations({ rootDir })).toContain(
      "frontend/package.json: ci must run desktop-generic-ipc-post-removal:check",
    );
  });
});
