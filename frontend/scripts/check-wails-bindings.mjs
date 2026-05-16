import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const root = resolve(scriptDir, "..");

const requiredMethods = [
  "BackendStatus",
  "GetBackendAuthToken",
  "OpenCaptureDialog",
  "OpenDBCDialog",
  "IsBackendReady",
  "PingBackendDataPlane",
  "InvokeBackendJSON",
  "InvokeBackendBlob",
  "InvokeBackendText",
  "GetToolRuntimeSnapshot",
  "GetToolRuntimeSnapshotFast",
  "GetToolRuntimeSnapshotFull",
  "UpdateToolRuntimeConfig",
  "UpdateToolRuntimeConfigFast",
  "UpdateToolRuntimeConfigFull",
  "SetTSharkPath",
  "StartCapture",
  "StopCapture",
  "PrepareCaptureReplacement",
  "CloseCapture",
  "GetCaptureStatus",
  "ListPacketsPage",
  "GetTLSConfig",
  "UpdateTLSConfig",
  "CheckAppUpdate",
  "InstallAppUpdate",
];

const generatedDts = readFileSync(resolve(root, "wailsjs/go/main/DesktopApp.d.ts"), "utf8");
const generatedJs = readFileSync(resolve(root, "wailsjs/go/main/DesktopApp.js"), "utf8");
const bridgeTypes = readFileSync(resolve(root, "src/app/integrations/desktopTransportBinding.ts"), "utf8");

const failures = [];

for (const method of requiredMethods) {
  if (!new RegExp(`export function ${method}\\b`).test(generatedDts)) {
    failures.push(`missing generated d.ts binding: ${method}`);
  }
  if (!new RegExp(`export function ${method}\\b`).test(generatedJs)) {
    failures.push(`missing generated js binding: ${method}`);
  }
  if (!new RegExp(`${method}\\?\\s*:`).test(bridgeTypes)) {
    failures.push(`missing DesktopTransportBinding declaration: ${method}`);
  }
}

if (failures.length > 0) {
  console.error("Wails binding check failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("Wails binding check: ok");
