import type { SMB3RandomSessionKeyRequest, WinRMDecryptRequest } from "../core/types";
import { downloadBlob } from "../utils/browserFile";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { LONG_TYPED_IPC_TIMEOUT_MS, typedBlobCall, typedCall } from "./desktopTypedBridgeCore";
import {
  asHTTPLoginAnalysis,
  asMySQLAnalysis,
  asShiroRememberMeAnalysis,
  asSMTPAnalysis,
} from "./mappers/protocolToolMapper";
import { asObjectList } from "./mappers/objectMapper";
import { asBruteforceAnalysis, asUDPTunnelAnalysis } from "./mappers/securityDetectionMapper";
import {
  asNTLMSessionMaterials,
  asSMB3RandomSessionKeyResult,
  asSMB3SessionCandidates,
  asWinRMDecryptResult,
} from "./mappers/toolMapper";

export function createObjectToolingTypedOverrides(desktopApp: DesktopTransportBinding): Partial<BackendBridge> {
  return {
    async listObjects(signal) {
      return asObjectList(await typedCall(() => desktopApp.ListObjects!(), "DesktopApp.ListObjects", signal));
    },
    async downloadObjectsZip(ids) {
      const blob = await typedBlobCall(() => desktopApp.DownloadObjectsZip!(ids), "DesktopApp.DownloadObjectsZip");
      downloadBlob("exported_objects.zip", blob);
    },
    async runWinRMDecrypt(req) {
      return asWinRMDecryptResult(
        await typedCall(
          () => desktopApp.RunWinRMDecrypt!(toWinRMRequest(req)),
          "DesktopApp.RunWinRMDecrypt",
          undefined,
          LONG_TYPED_IPC_TIMEOUT_MS,
        ),
        req.port,
      );
    },
    async getWinRMDecryptResultText(resultId) {
      return String(
        await typedCall(
          () => desktopApp.GetWinRMDecryptResultText!(resultId),
          "DesktopApp.GetWinRMDecryptResultText",
          undefined,
          LONG_TYPED_IPC_TIMEOUT_MS,
        ),
      );
    },
    async exportWinRMDecryptResult(resultId, filename) {
      const blob = await typedBlobCall(
        () => desktopApp.ExportWinRMDecryptResult!(resultId),
        "DesktopApp.ExportWinRMDecryptResult",
      );
      downloadBlob(filename, blob);
    },
    async listSMB3SessionCandidates() {
      return asSMB3SessionCandidates(
        await typedCall(() => desktopApp.ListSMB3SessionCandidates!(), "DesktopApp.ListSMB3SessionCandidates"),
      );
    },
    async generateSMB3RandomSessionKey(req) {
      return asSMB3RandomSessionKeyResult(
        await typedCall(
          () => desktopApp.GenerateSMB3RandomSessionKey!(toSMB3RandomSessionKeyRequest(req)),
          "DesktopApp.GenerateSMB3RandomSessionKey",
          undefined,
          LONG_TYPED_IPC_TIMEOUT_MS,
        ),
      );
    },
    async listNTLMSessionMaterials() {
      return asNTLMSessionMaterials(
        await typedCall(() => desktopApp.ListNTLMSessionMaterials!(), "DesktopApp.ListNTLMSessionMaterials"),
      );
    },
    async getHTTPLoginAnalysis(signal) {
      return asHTTPLoginAnalysis(
        await typedCall(() => desktopApp.GetHTTPLoginAnalysis!(), "DesktopApp.GetHTTPLoginAnalysis", signal),
      );
    },
    async getSMTPAnalysis(signal) {
      return asSMTPAnalysis(await typedCall(() => desktopApp.GetSMTPAnalysis!(), "DesktopApp.GetSMTPAnalysis", signal));
    },
    async getMySQLAnalysis(signal) {
      return asMySQLAnalysis(await typedCall(() => desktopApp.GetMySQLAnalysis!(), "DesktopApp.GetMySQLAnalysis", signal));
    },
    async getShiroRememberMeAnalysis(candidateKeys, signal) {
      return asShiroRememberMeAnalysis(
        await typedCall(
          () => desktopApp.GetShiroRememberMeAnalysis!(Array.isArray(candidateKeys) ? candidateKeys : []),
          "DesktopApp.GetShiroRememberMeAnalysis",
          signal,
          LONG_TYPED_IPC_TIMEOUT_MS,
        ),
      );
    },
    async getUDPTunnelAnalysis(signal) {
      return asUDPTunnelAnalysis(
        await typedCall(() => desktopApp.GetUDPTunnelAnalysis!(), "DesktopApp.GetUDPTunnelAnalysis", signal),
      );
    },
    async getBruteforceAnalysis(signal) {
      return asBruteforceAnalysis(
        await typedCall(() => desktopApp.GetBruteforceAnalysis!(), "DesktopApp.GetBruteforceAnalysis", signal),
      );
    },
  };
}

function toWinRMRequest(req: WinRMDecryptRequest) {
  return {
    port: req.port,
    auth_mode: req.authMode,
    password: req.password ?? "",
    nt_hash: req.ntHash ?? "",
    preview_lines: req.previewLines ?? 0,
    include_error_frames: Boolean(req.includeErrorFrames),
    extract_command_output: Boolean(req.extractCommandOutput),
  };
}

function toSMB3RandomSessionKeyRequest(req: SMB3RandomSessionKeyRequest) {
  return {
    username: req.username,
    domain: req.domain,
    ntlm_hash: req.ntlmHash,
    nt_proof_str: req.ntProofStr,
    encrypted_session_key: req.encryptedSessionKey,
  };
}
