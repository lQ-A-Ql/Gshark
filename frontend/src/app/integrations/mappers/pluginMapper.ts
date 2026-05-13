import type { DBCProfile, PluginItem } from "../../core/types";
import { asArray, asPlainObject, asStringList } from "./mapperPrimitives";

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

export function asPluginItem(input: unknown): PluginItem {
  const payload = asPlainObject(input) ?? {};
  return {
    id: typeof payload.id === "number" ? payload.id : String(payload.id ?? ""),
    name: String(payload.name ?? ""),
    version: String(payload.version ?? ""),
    tag: String(payload.tag ?? ""),
    author: String(payload.author ?? ""),
    enabled: Boolean(payload.enabled),
    entry: String(payload.entry ?? ""),
    runtime: String(payload.runtime ?? ""),
    capabilities: asStringList(payload.capabilities),
  };
}

export function asPluginItems(input: unknown): PluginItem[] {
  return asArray(input).map(asPluginItem);
}
