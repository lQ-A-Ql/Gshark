import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { findDesktopTransportPolicyViolations } from "./check-desktop-transport-policy.mjs";

function writeFixtureFile(frontendRoot, relativePath, content) {
  const absolutePath = resolve(frontendRoot, relativePath);
  mkdirSync(resolve(absolutePath, ".."), { recursive: true });
  writeFileSync(absolutePath, content);
}

function writePolicyFixture(requirementBody, typedCallBody) {
  const frontendRoot = mkdtempSync(resolve(tmpdir(), "gshark-desktop-policy-check-"));
  writeFixtureFile(frontendRoot, "src/app/integrations/desktopBridge.ts", "export const bridge = {};\n");
  writeFixtureFile(frontendRoot, "src/app/integrations/desktopTypedBridge.ts", "export const typed = {};\n");
  writeFixtureFile(frontendRoot, "src/app/integrations/desktopTypedBridgeCore.ts", "export const core = {};\n");
  writeFixtureFile(frontendRoot, "src/app/integrations/desktopTypedBridgeRequirements.ts", requirementBody);
  writeFixtureFile(frontendRoot, "src/app/integrations/desktopTypedBridgeStream.ts", typedCallBody);
  writeFixtureFile(frontendRoot, "src/app/integrations/desktopTypedBridgeTooling.ts", "export const tooling = {};\n");
  writeFixtureFile(frontendRoot, "src/app/integrations/desktopTypedBridgeAnalysis.ts", "export const analysis = {};\n");
  writeFixtureFile(frontendRoot, "src/app/integrations/desktopTypedBridgeMedia.ts", "export const media = {};\n");
  writeFixtureFile(frontendRoot, "src/app/integrations/desktopTypedBridgeMisc.ts", "export const misc = {};\n");
  writeFixtureFile(frontendRoot, "src/app/integrations/desktopTypedBridgePacket.ts", "export const packet = {};\n");
  writeFixtureFile(frontendRoot, "src/app/integrations/desktopTypedBridgeHunting.ts", "export const hunting = {};\n");
  writeFixtureFile(
    frontendRoot,
    "src/app/integrations/desktopTypedBridgeVehicleDbc.ts",
    "export const vehicleDbc = {};\n",
  );
  writeFixtureFile(frontendRoot, "src/app/integrations/desktopTypedBridgePlugin.ts", "export const plugin = {};\n");
  return frontendRoot;
}

describe("check-desktop-transport-policy script", () => {
  it("accepts typed desktop bridge files that route through DesktopApp methods", () => {
    const frontendRoot = writePolicyFixture(
      'export const typedBindingRequirements = { getHttpStream: "GetHttpStream" };\n',
      "export function createStreamTypedOverrides(desktopApp) { return desktopApp.GetHttpStream!(7); }\n",
    );

    expect(
      findDesktopTransportPolicyViolations({
        frontendRoot,
        requirements: { getHttpStream: "GetHttpStream" },
      }),
    ).toEqual([]);
  });

  it("includes media typed bridge files in the desktop transport policy scan", () => {
    const frontendRoot = writePolicyFixture(
      'export const typedBindingRequirements = { getMediaAnalysis: "GetMediaAnalysis" };\n',
      "export const stream = {};\n",
    );
    writeFixtureFile(
      frontendRoot,
      "src/app/integrations/desktopTypedBridgeMedia.ts",
      "export function createMediaTypedOverrides(desktopApp) { return desktopApp.GetMediaAnalysis!(false); }\n",
    );

    expect(
      findDesktopTransportPolicyViolations({
        frontendRoot,
        requirements: { getMediaAnalysis: "GetMediaAnalysis" },
      }),
    ).toEqual([]);
  });

  it("allows desktopBridge to compose generic IPC fallback outside typed override files", () => {
    const frontendRoot = writePolicyFixture(
      'export const typedBindingRequirements = { getHttpStream: "GetHttpStream" };\n',
      "export function createStreamTypedOverrides(desktopApp) { return desktopApp.GetHttpStream!(7); }\n",
    );
    writeFixtureFile(
      frontendRoot,
      "src/app/integrations/desktopBridge.ts",
      "const ipcTransport = desktopApp.InvokeBackendJSON ? createIpcBackendTransport(desktopApp) : null;\n",
    );

    expect(
      findDesktopTransportPolicyViolations({
        frontendRoot,
        requirements: { getHttpStream: "GetHttpStream" },
      }),
    ).toEqual([]);
  });

  it("rejects direct api path wiring inside typed desktop bridge files", () => {
    const frontendRoot = writePolicyFixture(
      'export const typedBindingRequirements = { getHttpStream: "GetHttpStream" };\n',
      'export const badPath = "/api/streams/http";\ndesktopApp.GetHttpStream!(7);\n',
    );

    expect(
      findDesktopTransportPolicyViolations({
        frontendRoot,
        requirements: { getHttpStream: "GetHttpStream" },
      }),
    ).toEqual([
      "src/app/integrations/desktopTypedBridgeStream.ts:1: typed desktop bridge must not wire direct /api paths; add a DesktopApp typed binding",
    ]);
  });

  it("rejects generic InvokeBackend usage for migrated typed domains", () => {
    const frontendRoot = writePolicyFixture(
      'export const typedBindingRequirements = { getHttpStream: "GetHttpStream" };\n',
      "desktopApp.InvokeBackendJSON({ path: '/api/streams/http' });\ndesktopApp.GetHttpStream!(7);\n",
    );

    expect(
      findDesktopTransportPolicyViolations({
        frontendRoot,
        requirements: { getHttpStream: "GetHttpStream" },
      }),
    ).toEqual([
      "src/app/integrations/desktopTypedBridgeStream.ts:1: typed desktop bridge must not wire direct /api paths; add a DesktopApp typed binding",
      "src/app/integrations/desktopTypedBridgeStream.ts:1: typed desktop bridge must not call generic InvokeBackend* for migrated domains",
    ]);
  });

  it("rejects missing typed binding requirements and missing typed calls", () => {
    const frontendRoot = writePolicyFixture(
      "export const typedBindingRequirements = {};\n",
      "export const noop = 1;\n",
    );

    expect(
      findDesktopTransportPolicyViolations({
        frontendRoot,
        requirements: { getHttpStream: "GetHttpStream" },
      }),
    ).toEqual([
      "src/app/integrations/desktopTypedBridgeRequirements.ts: missing typedBindingRequirements entry getHttpStream -> GetHttpStream",
      "desktop typed bridge does not call DesktopApp.GetHttpStream; generic bridge may still own it",
    ]);
  });
});
