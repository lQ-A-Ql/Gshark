import type { ToolRuntimeSnapshot } from "../core/types";
import type { TSharkStatus } from "../integrations/clients/toolRuntimeClient";

export function toTSharkStatus(status: ToolRuntimeSnapshot["tshark"]): TSharkStatus {
  return {
    available: status.available,
    path: status.path,
    message: status.message,
    customPath: status.customPath ?? "",
    usingCustomPath: status.usingCustomPath,
    version: status.version,
    fieldProfile: status.fieldProfile,
    fieldCount: status.fieldCount,
    missingRequiredFields: status.missingRequiredFields ?? [],
    missingOptionalFields: status.missingOptionalFields ?? [],
    capabilityMessage: status.capabilityMessage,
    capabilityCheckDegraded: status.capabilityCheckDegraded,
  };
}

export function describeTSharkReadyStatus(status: TSharkStatus): string {
  if (status.message && status.message !== "ok") return status.message;
  return status.usingCustomPath ? `tshark ready: ${status.path}` : "tshark ready";
}

export function describeTSharkApplyStatus(status: ToolRuntimeSnapshot["tshark"]): string {
  return status.message && status.message !== "ok" ? status.message : "工具路径已更新";
}
