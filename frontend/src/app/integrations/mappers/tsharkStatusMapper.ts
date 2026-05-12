import type { TSharkStatus } from "../clients/toolRuntimeClient";

export function asTSharkStatus(input: any): TSharkStatus {
  return {
    available: Boolean(input?.available),
    path: String(input?.path ?? ""),
    message: String(input?.message ?? ""),
    customPath: String(input?.custom_path ?? ""),
    usingCustomPath: Boolean(input?.using_custom_path),
    version: String(input?.version ?? "") || undefined,
    fieldProfile: String(input?.field_profile ?? "") || undefined,
    fieldCount: Number(input?.field_count ?? 0) || undefined,
    missingRequiredFields: stringList(input?.missing_required_fields),
    missingOptionalFields: stringList(input?.missing_optional_fields),
    capabilityMessage: String(input?.capability_message ?? "") || undefined,
    capabilityCheckDegraded: Boolean(input?.capability_check_degraded),
  };
}

function stringList(input: unknown): string[] {
  return Array.isArray(input) ? input.map((item) => String(item ?? "")) : [];
}
