import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { findDesktopOldBindingCompatViolations } from "./check-desktop-old-binding-compat.mjs";

const exitPlan = [
  "status: frontend adapter construction removed; backend/generated binding cleanup pending",
  "removed InvokeBackendJSON",
  "removed InvokeBackendBlob",
  "removed InvokeBackendText",
  "generic_ipc_disabled",
  "Three consecutive green rounds",
  "desktopWebviewTyped.directBackendApiRequestCount = 0",
  "VITE_DESKTOP_DISABLE_GENERIC_IPC=1",
  "VITE_DESKTOP_GENERIC_IPC_POLICY=compat",
  "DisableGenericIpcAdapterExperiment",
  "genericIpcDisableExperimentBuildFlag = true",
  "Browser-dev HTTP/SSE remains green",
  "Do not remove browser-dev HTTP/SSE debugging",
  "documented no-op",
].join("\n");

function writeFixtureFile(frontendRoot, relativePath, content) {
  const absolutePath = resolve(frontendRoot, relativePath);
  mkdirSync(resolve(absolutePath, ".."), { recursive: true });
  writeFileSync(absolutePath, content);
}

function createFixture(files) {
  const frontendRoot = mkdtempSync(resolve(tmpdir(), "meow-traffic-old-binding-compat-"));
  for (const [relativePath, content] of Object.entries(files)) {
    writeFixtureFile(frontendRoot, relativePath, content);
  }
  return frontendRoot;
}

function writeExitPlan(content = exitPlan) {
  const workspace = mkdtempSync(resolve(tmpdir(), "meow-traffic-old-binding-exit-plan-"));
  const exitPlanPath = resolve(workspace, "docs/desktop-ipc-old-binding-exit-plan.md");
  mkdirSync(resolve(exitPlanPath, ".."), { recursive: true });
  writeFileSync(exitPlanPath, content);
  return exitPlanPath;
}

describe("check-desktop-old-binding-compat script", () => {
  it("accepts approved shell, dialog, and auth-token compatibility bindings", () => {
    const frontendRoot = createFixture({
      "src/app/integrations/backendClients.ts":
        "export function binding() { return (window)?.go?.main?.DesktopApp; }\n",
      "src/app/integrations/httpBridge.ts":
        "const token = await desktopApp.GetBackendAuthToken?.();\ngetDesktopAppBinding()?.GetBackendAuthToken;\n",
      "src/app/integrations/clients/captureClient.ts": "await desktopApp?.OpenCaptureDialog?.();\n",
      "src/app/integrations/clients/desktopClient.ts":
        "await desktopApp.BackendStatus();\nawait desktopApp.CheckAppUpdate();\nawait desktopApp.InstallAppUpdate();\nawait desktopApp.OpenDBCDialog();\n",
    });

    expect(findDesktopOldBindingCompatViolations({ frontendRoot, exitPlanPath: writeExitPlan() })).toEqual([]);
  });

  it("rejects direct old generated data-plane bindings in compatibility clients", () => {
    const frontendRoot = createFixture({
      "src/app/integrations/clients/objectClient.ts": "await desktopApp.ListObjects();\n",
    });

    expect(findDesktopOldBindingCompatViolations({ frontendRoot, exitPlanPath: writeExitPlan() })).toEqual([
      "src/app/integrations/clients/objectClient.ts:1: old generated DesktopApp binding ListObjects is not an approved compatibility use; route desktop data-plane work through desktopBridge or add a typed override",
    ]);
  });

  it("allows typed bridge files to own DesktopApp typed method calls", () => {
    const frontendRoot = createFixture({
      "src/app/integrations/desktopTypedBridgeTooling.ts": "await desktopApp.ListObjects!();\n",
    });

    expect(findDesktopOldBindingCompatViolations({ frontendRoot, exitPlanPath: writeExitPlan() })).toEqual([]);
  });

  it("requires the old generated binding exit plan", () => {
    const frontendRoot = createFixture({});

    expect(
      findDesktopOldBindingCompatViolations({ frontendRoot, exitPlanPath: writeExitPlan("status: guarded") }),
    ).toEqual([
      "docs/desktop-ipc-old-binding-exit-plan.md: missing exit-plan token removed InvokeBackendJSON",
      "docs/desktop-ipc-old-binding-exit-plan.md: missing exit-plan token removed InvokeBackendBlob",
      "docs/desktop-ipc-old-binding-exit-plan.md: missing exit-plan token removed InvokeBackendText",
      "docs/desktop-ipc-old-binding-exit-plan.md: missing exit-plan token generic_ipc_disabled",
      "docs/desktop-ipc-old-binding-exit-plan.md: missing exit-plan token Three consecutive green rounds",
      "docs/desktop-ipc-old-binding-exit-plan.md: missing exit-plan token desktopWebviewTyped.directBackendApiRequestCount = 0",
      "docs/desktop-ipc-old-binding-exit-plan.md: missing exit-plan token VITE_DESKTOP_DISABLE_GENERIC_IPC=1",
      "docs/desktop-ipc-old-binding-exit-plan.md: missing exit-plan token VITE_DESKTOP_GENERIC_IPC_POLICY=compat",
      "docs/desktop-ipc-old-binding-exit-plan.md: missing exit-plan token DisableGenericIpcAdapterExperiment",
      "docs/desktop-ipc-old-binding-exit-plan.md: missing exit-plan token genericIpcDisableExperimentBuildFlag = true",
      "docs/desktop-ipc-old-binding-exit-plan.md: missing exit-plan token Browser-dev HTTP/SSE remains green",
      "docs/desktop-ipc-old-binding-exit-plan.md: missing exit-plan token Do not remove browser-dev HTTP/SSE debugging",
      "docs/desktop-ipc-old-binding-exit-plan.md: missing exit-plan token documented no-op",
    ]);
  });

  it("requires a current exit-plan status", () => {
    const frontendRoot = createFixture({});

    expect(
      findDesktopOldBindingCompatViolations({
        frontendRoot,
        exitPlanPath: writeExitPlan(exitPlan.replace(/^status: .+$/m, "status: unknown")),
      }),
    ).toContain(
      "docs/desktop-ipc-old-binding-exit-plan.md: missing exit-plan status guarded or frontend adapter construction removed",
    );
  });

  it("accepts the post-cleanup shell-only exit-plan status", () => {
    const frontendRoot = createFixture({});

    expect(
      findDesktopOldBindingCompatViolations({
        frontendRoot,
        exitPlanPath: writeExitPlan(
          exitPlan.replace(/^status: .+$/m, "status: shell-compat-only; backend/generated InvokeBackend* removed"),
        ),
      }),
    ).toEqual([]);
  });
});
