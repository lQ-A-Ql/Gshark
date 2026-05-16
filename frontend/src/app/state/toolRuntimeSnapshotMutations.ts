import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../core/types";
import type { TSharkStatus } from "../integrations/clients/toolRuntimeClient";

export const EMPTY_TSHARK_STATUS: TSharkStatus = {
  available: false,
  path: "",
  message: "",
  customPath: "",
  usingCustomPath: false,
};

export function mergeTSharkStatusIntoSnapshot(
  snapshot: ToolRuntimeSnapshot | null,
  nextPath: string,
  status: TSharkStatus,
): ToolRuntimeSnapshot | null {
  return snapshot
    ? {
        ...snapshot,
        config: { ...snapshot.config, tsharkPath: nextPath },
        tshark: {
          ...snapshot.tshark,
          available: status.available,
          path: status.path,
          message: status.message,
          customPath: status.customPath || undefined,
          usingCustomPath: status.usingCustomPath,
          version: status.version,
          fieldProfile: status.fieldProfile,
          fieldCount: status.fieldCount,
          missingRequiredFields: status.missingRequiredFields,
          missingOptionalFields: status.missingOptionalFields,
          capabilityMessage: status.capabilityMessage,
          capabilityCheckDegraded: status.capabilityCheckDegraded,
        },
      }
    : snapshot;
}

export function buildNextToolRuntimeConfig(
  base: ToolRuntimeConfig,
  patch: Partial<ToolRuntimeConfig>,
): ToolRuntimeConfig {
  return {
    ...base,
    ...patch,
    tsharkPath: String(patch.tsharkPath ?? base.tsharkPath ?? "").trim(),
    ffmpegPath: String(patch.ffmpegPath ?? base.ffmpegPath ?? "").trim(),
    pythonPath: String(patch.pythonPath ?? base.pythonPath ?? "").trim(),
    voskModelPath: String(patch.voskModelPath ?? base.voskModelPath ?? "").trim(),
    yaraEnabled: patch.yaraEnabled ?? base.yaraEnabled,
    yaraBin: String(patch.yaraBin ?? base.yaraBin ?? "").trim(),
    yaraRules: String(patch.yaraRules ?? base.yaraRules ?? "").trim(),
    yaraTimeoutMs: Number(patch.yaraTimeoutMs ?? base.yaraTimeoutMs ?? 25000) || 25000,
  };
}
