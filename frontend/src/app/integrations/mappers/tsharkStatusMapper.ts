import type { TSharkStatus } from "../clients/toolRuntimeClient";
import type { TSharkStatusWireDTO } from "../wire/runtimeWireDtos";
import { asPlainObject, asStringList } from "./mapperPrimitives";

export function asTSharkStatus(input: unknown): TSharkStatus {
  const payload: TSharkStatusWireDTO = asPlainObject(input) ?? {};
  return {
    available: Boolean(payload.available),
    path: String(payload.path ?? ""),
    message: String(payload.message ?? ""),
    customPath: String(payload.custom_path ?? ""),
    usingCustomPath: Boolean(payload.using_custom_path),
    version: String(payload.version ?? "") || undefined,
    fieldProfile: String(payload.field_profile ?? "") || undefined,
    fieldCount: Number(payload.field_count ?? 0) || undefined,
    missingRequiredFields: asStringList(payload.missing_required_fields),
    missingOptionalFields: asStringList(payload.missing_optional_fields),
    capabilityMessage: String(payload.capability_message ?? "") || undefined,
    capabilityCheckDegraded: Boolean(payload.capability_check_degraded),
  };
}
