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
