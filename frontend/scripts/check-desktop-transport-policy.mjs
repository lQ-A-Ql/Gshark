import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const typedDesktopBridgeFiles = [
  "src/app/integrations/desktopTypedBridge.ts",
  "src/app/integrations/desktopTypedBridgeCore.ts",
  "src/app/integrations/desktopTypedBridgeRequirements.ts",
  "src/app/integrations/desktopTypedBridgePlaybookRequirements.ts",
  "src/app/integrations/desktopTypedBridgeStream.ts",
  "src/app/integrations/desktopTypedBridgeTooling.ts",
  "src/app/integrations/desktopTypedBridgeAnalysis.ts",
  "src/app/integrations/desktopTypedBridgeMedia.ts",
  "src/app/integrations/desktopTypedBridgeMisc.ts",
  "src/app/integrations/desktopTypedBridgePacket.ts",
  "src/app/integrations/desktopTypedBridgeHunting.ts",
  "src/app/integrations/desktopTypedBridgePlaybook.ts",
  "src/app/integrations/desktopTypedBridgeVehicleDbc.ts",
  "src/app/integrations/desktopTypedBridgeRules.ts",
];

export const typedDesktopRequirementFiles = [
  "src/app/integrations/desktopTypedBridgeRequirements.ts",
  "src/app/integrations/desktopTypedBridgePlaybookRequirements.ts",
];

export const migratedBridgeRequirements = {
  getHttpStream: "GetHttpStream",
  getRawStream: "GetRawStream",
  getRawStreamPage: "GetRawStreamPage",
  decodeStreamPayload: "DecodeStreamPayload",
  inspectStreamPayload: "InspectStreamPayload",
  listStreamPayloadSources: "ListStreamPayloadSources",
  updateStreamPayloads: "UpdateStreamPayloads",
  listStreamIds: "ListStreamIDs",
  getPacketRawHex: "GetPacketRawHex",
  getPacketLayers: "GetPacketLayers",
  listObjects: "ListObjects",
  downloadObjectsZip: "DownloadObjectsZip",
  runWinRMDecrypt: "RunWinRMDecrypt",
  getWinRMDecryptResultText: "GetWinRMDecryptResultText",
  exportWinRMDecryptResult: "ExportWinRMDecryptResult",
  listSMB3SessionCandidates: "ListSMB3SessionCandidates",
  generateSMB3RandomSessionKey: "GenerateSMB3RandomSessionKey",
  listNTLMSessionMaterials: "ListNTLMSessionMaterials",
  getHTTPLoginAnalysis: "GetHTTPLoginAnalysis",
  getSMTPAnalysis: "GetSMTPAnalysis",
  getMySQLAnalysis: "GetMySQLAnalysis",
  getShiroRememberMeAnalysis: "GetShiroRememberMeAnalysis",
  getGlobalTrafficStats: "GetGlobalTrafficStats",
  getIndustrialAnalysis: "GetIndustrialAnalysis",
  getVehicleAnalysis: "GetVehicleAnalysis",
  getMediaAnalysis: "GetMediaAnalysis",
  transcribeMediaArtifact: "TranscribeMediaArtifact",
  startMediaBatchTranscription: "StartMediaBatchTranscription",
  getMediaBatchTranscriptionStatus: "GetMediaBatchTranscriptionStatus",
  cancelMediaBatchTranscription: "CancelMediaBatchTranscription",
  exportMediaBatchTranscription: "ExportMediaBatchTranscription",
  downloadMediaArtifact: "DownloadMediaArtifact",
  getMediaPlaybackBlob: "GetMediaPlaybackBlob",
  getUSBAnalysis: "GetUSBAnalysis",
  getC2SampleAnalysis: "GetC2SampleAnalysis",
  decryptC2Traffic: "DecryptC2Traffic",
  getAPTAnalysis: "GetAPTAnalysis",
  getEvidence: "GetEvidence",
  getEvidenceWithFilter: "GetEvidenceWithFilter",
  locatePacketPage: "LocatePacketPage",
  getPacket: "GetPacket",
  listThreatHits: "ListThreatHits",
  getHuntingRuntimeConfig: "GetHuntingRuntimeConfig",
  updateHuntingRuntimeConfig: "UpdateHuntingRuntimeConfig",
  listPlaybooks: "ListPlaybooks",
  getPlaybook: "GetPlaybook",
  createPlaybook: "CreatePlaybook",
  updatePlaybook: "UpdatePlaybook",
  deletePlaybook: "DeletePlaybook",
  runPlaybook: "RunPlaybook",
  getPlaybookLastRun: "GetPlaybookLastRun",
  listSavedSearches: "ListSavedSearches",
  getSavedSearch: "GetSavedSearch",
  createSavedSearch: "CreateSavedSearch",
  updateSavedSearch: "UpdateSavedSearch",
  deleteSavedSearch: "DeleteSavedSearch",
  executeSavedSearch: "ExecuteSavedSearch",
  listHypotheses: "ListHypotheses",
  getHypothesis: "GetHypothesis",
  createHypothesis: "CreateHypothesis",
  updateHypothesis: "UpdateHypothesis",
  deleteHypothesis: "DeleteHypothesis",
  addHypothesisEvidence: "AddHypothesisEvidence",
  updateHypothesisStatus: "UpdateHypothesisStatus",
  listVehicleDBCProfiles: "ListVehicleDBCProfiles",
  addVehicleDBC: "AddVehicleDBC",
  removeVehicleDBC: "RemoveVehicleDBC",
  listMiscModules: "ListMiscModules",
  selectMiscModulePackage: "SelectMiscModulePackage",
  importMiscModulePackageFromPath: "ImportMiscModulePackageFromPath",
  deleteMiscModule: "DeleteMiscModulePackage",
  runMiscModule: "RunMiscModulePackage",
  getUDPTunnelAnalysis: "GetUDPTunnelAnalysis",
  getBruteforceAnalysis: "GetBruteforceAnalysis",
  getRuleStatus: "GetRuleStatus",
  toggleRulePack: "ToggleRulePack",
  checkRuleUpdates: "CheckRuleUpdates",
  downloadRulePack: "DownloadRulePack",
  updateRuleConfig: "UpdateRuleConfig",
  listRuleConflicts: "GetRuleConflicts",
  validateRuleContent: "ValidateRules",
};

export function findDesktopTransportPolicyViolations({
  frontendRoot = root,
  files = typedDesktopBridgeFiles,
  requirements = migratedBridgeRequirements,
} = {}) {
  const violations = [];

  for (const file of files) {
    const path = resolve(frontendRoot, file);
    if (!existsSync(path)) {
      violations.push(`${file}: missing desktop transport policy file`);
      continue;
    }
    recordForbiddenDesktopBridgeWiring(violations, file, readFileSync(path, "utf8"));
  }

  recordMissingTypedRequirements(violations, frontendRoot, requirements);
  recordMissingTypedCalls(violations, frontendRoot, requirements);

  return violations;
}

function recordForbiddenDesktopBridgeWiring(violations, file, body) {
  body.split(/\r\n|\r|\n/).forEach((line, index) => {
    if (isCommentOnly(line)) {
      return;
    }
    if (containsApiPathLiteral(line)) {
      violations.push(
        `${file}:${index + 1}: typed desktop bridge must not wire direct /api paths; add a DesktopApp typed binding`,
      );
    }
    if (/\bInvokeBackend(?:JSON|Blob|Text)\b/.test(line)) {
      violations.push(
        `${file}:${index + 1}: typed desktop bridge must not call generic InvokeBackend* for migrated domains`,
      );
    }
  });
}

function recordMissingTypedRequirements(violations, frontendRoot, requirements) {
  const fallbackPath = resolve(frontendRoot, "src/app/integrations/desktopTypedBridgeCore.ts");
  const requirementBodies = typedDesktopRequirementFiles
    .map((file) => {
      const path = resolve(frontendRoot, file);
      return existsSync(path) ? readFileSync(path, "utf8") : "";
    })
    .filter(Boolean);
  const fallbackBody = existsSync(fallbackPath) ? readFileSync(fallbackPath, "utf8") : "";
  const body = requirementBodies.length > 0 ? requirementBodies.join("\n") : fallbackBody;

  if (body.length === 0) {
    violations.push(
      "src/app/integrations/desktopTypedBridgeRequirements.ts: missing typed binding requirements source",
    );
    return;
  }
  const displayPath = "src/app/integrations/desktopTypedBridgeRequirements.ts";
  for (const [bridgeMethod, bindingMethod] of Object.entries(requirements)) {
    const requirementPattern = new RegExp(`${escapeRegex(bridgeMethod)}\\s*:\\s*["']${escapeRegex(bindingMethod)}["']`);
    if (!requirementPattern.test(body)) {
      violations.push(`${displayPath}: missing typedBindingRequirements entry ${bridgeMethod} -> ${bindingMethod}`);
    }
  }
}

function recordMissingTypedCalls(violations, frontendRoot, requirements) {
  const typedBridgeBody = typedDesktopBridgeFiles
    .map((file) => {
      const path = resolve(frontendRoot, file);
      return existsSync(path) ? readFileSync(path, "utf8") : "";
    })
    .join("\n");

  for (const bindingMethod of Object.values(requirements)) {
    const callPattern = new RegExp(`desktopApp\\.${escapeRegex(bindingMethod)}!`);
    if (!callPattern.test(typedBridgeBody)) {
      violations.push(
        `desktop typed bridge does not call DesktopApp.${bindingMethod}; generic bridge may still own it`,
      );
    }
  }
}

function containsApiPathLiteral(line) {
  return /(["'`])[^"'`]*(?:127\.0\.0\.1:17891)?\/api\//.test(line);
}

function isCommentOnly(line) {
  return line.trim().startsWith("//");
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function runCli() {
  const violations = findDesktopTransportPolicyViolations();
  if (violations.length === 0) {
    console.log("Desktop transport policy check passed.");
    return;
  }

  console.error("Desktop transport policy violations:");
  for (const violation of violations) {
    console.error(`- ${violation}`);
  }
  process.exit(1);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runCli();
}
