import type { DBCProfile } from "../../core/types";
import { asArray, asPlainObject } from "./mapperPrimitives";

export function asDBCProfile(input: unknown): DBCProfile {
  const payload = asPlainObject(input) ?? {};
  return {
    path: String(payload.path ?? ""),
    name: String(payload.name ?? ""),
    messageCount: Number(payload.message_count ?? 0),
    signalCount: Number(payload.signal_count ?? 0),
  };
}

export function asDBCProfiles(input: unknown): DBCProfile[] {
  return asArray(input).map(asDBCProfile);
}
