import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const root = resolve(scriptDir, "..");

const methodGroups = {
  "desktop-shell": [
    "GetDesktopWebviewSmokeConfig",
    "WriteDesktopWebviewSmokeResult",
    "BackendStatus",
    "GetBackendAuthToken",
    "OpenCaptureDialog",
    "OpenDBCDialog",
    "SelectMiscModulePackage",
    "IsBackendReady",
    "PingBackendDataPlane",
    "CheckAppUpdate",
    "InstallAppUpdate",
  ],
  "typed-control-plane": [
    "GetToolRuntimeSnapshot",
    "GetToolRuntimeSnapshotFast",
    "GetToolRuntimeSnapshotFull",
    "UpdateToolRuntimeConfig",
    "UpdateToolRuntimeConfigFast",
    "UpdateToolRuntimeConfigFull",
    "SetTSharkPath",
    "GetMCPStatus",
    "UpdateMCPConfig",
    "StartCapture",
    "StopCapture",
    "PrepareCaptureReplacement",
    "CloseCapture",
    "GetCaptureStatus",
    "ListPacketsPage",
    "LocatePacketPage",
    "GetPacket",
    "GetTLSConfig",
    "UpdateTLSConfig",
  ],
  "typed-stream": [
    "GetHttpStream",
    "GetRawStream",
    "GetRawStreamPage",
    "DecodeStreamPayload",
    "InspectStreamPayload",
    "ListStreamPayloadSources",
    "ListStreamIDs",
    "UpdateStreamPayloads",
    "GetPacketRawHex",
    "GetPacketLayers",
  ],
  "typed-object-tooling": [
    "ListObjects",
    "DownloadObjectsZip",
    "RunWinRMDecrypt",
    "GetWinRMDecryptResultText",
    "ExportWinRMDecryptResult",
    "ListSMB3SessionCandidates",
    "GenerateSMB3RandomSessionKey",
    "ListNTLMSessionMaterials",
    "GetHTTPLoginAnalysis",
    "GetSMTPAnalysis",
    "GetMySQLAnalysis",
    "GetShiroRememberMeAnalysis",
  ],
  "typed-analysis-evidence": [
    "GetGlobalTrafficStats",
    "GetIndustrialAnalysis",
    "GetVehicleAnalysis",
    "GetUSBAnalysis",
    "GetC2SampleAnalysis",
    "DecryptC2Traffic",
    "GetAPTAnalysis",
    "GetEvidence",
    "GetEvidenceWithFilter",
  ],
  "typed-media": [
    "GetMediaAnalysis",
    "TranscribeMediaArtifact",
    "StartMediaBatchTranscription",
    "GetMediaBatchTranscriptionStatus",
    "CancelMediaBatchTranscription",
    "ExportMediaBatchTranscription",
    "DownloadMediaArtifact",
    "GetMediaPlaybackBlob",
  ],
  "typed-hunting": ["ListThreatHits", "GetHuntingRuntimeConfig", "UpdateHuntingRuntimeConfig"],
  "typed-vehicle-dbc": ["ListVehicleDBCProfiles", "AddVehicleDBC", "RemoveVehicleDBC"],
  "typed-rules": [
    "GetRuleStatus",
    "ToggleRulePack",
    "CheckRuleUpdates",
    "DownloadRulePack",
    "UpdateRuleConfig",
    "GetRuleConflicts",
    "ValidateRules",
  ],
  "typed-misc": [
    "ListMiscModules",
    "ImportMiscModulePackageFromPath",
    "DeleteMiscModulePackage",
    "RunMiscModulePackage",
  ],
};

const generatedDts = readFileSync(resolve(root, "wailsjs/go/main/DesktopApp.d.ts"), "utf8");
const generatedJs = readFileSync(resolve(root, "wailsjs/go/main/DesktopApp.js"), "utf8");
const bridgeTypeFiles = [
  "desktopTransportBinding.ts",
  "desktopTransportBindingShell.ts",
  "desktopTransportBindingControl.ts",
  "desktopTransportBindingStream.ts",
  "desktopTransportBindingTooling.ts",
  "desktopTransportBindingAnalysis.ts",
  "desktopTransportBindingRules.ts",
];
const bridgeTypes = bridgeTypeFiles
  .map((file) => readFileSync(resolve(root, "src/app/integrations", file), "utf8"))
  .join("\n");

const failures = [];
const forbiddenGeneratedBindings = ["InvokeBackendJSON", "InvokeBackendBlob", "InvokeBackendText"];

for (const method of forbiddenGeneratedBindings) {
  if (new RegExp(`export function ${method}\\b`).test(generatedDts)) {
    failures.push(`removed generic IPC binding still exists in generated d.ts: ${method}`);
  }
  if (new RegExp(`export function ${method}\\b`).test(generatedJs)) {
    failures.push(`removed generic IPC binding still exists in generated js: ${method}`);
  }
  if (new RegExp(`${method}\\?\\s*:`).test(bridgeTypes)) {
    failures.push(`removed generic IPC binding still exists in DesktopTransportBinding declaration: ${method}`);
  }
}

for (const [group, methods] of Object.entries(methodGroups)) {
  const missing = [];
  for (const method of methods) {
    if (!new RegExp(`export function ${method}\\b`).test(generatedDts)) {
      failures.push(`missing generated d.ts binding in ${group}: ${method}`);
      missing.push(method);
    }
    if (!new RegExp(`export function ${method}\\b`).test(generatedJs)) {
      failures.push(`missing generated js binding in ${group}: ${method}`);
      missing.push(method);
    }
    if (!new RegExp(`${method}\\?\\s*:`).test(bridgeTypes)) {
      failures.push(`missing DesktopTransportBinding declaration in ${group}: ${method}`);
      missing.push(method);
    }
  }
  if (missing.length > 0) {
    failures.push(`incomplete Wails binding group ${group}: ${[...new Set(missing)].join(", ")}`);
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
