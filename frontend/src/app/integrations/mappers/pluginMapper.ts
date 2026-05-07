import type { DBCProfile, PluginItem } from "../../core/types";
import { asStringList } from "./mapperPrimitives";

export function asDBCProfile(input: any): DBCProfile {
  return {
    path: String(input.path ?? ""),
    name: String(input.name ?? ""),
    messageCount: Number(input.message_count ?? 0),
    signalCount: Number(input.signal_count ?? 0),
  };
}

export function asDBCProfiles(input: any): DBCProfile[] {
  return Array.isArray(input) ? input.map(asDBCProfile) : [];
}

export function asPluginItem(input: any): PluginItem {
  return {
    id: input.id,
    name: input.name,
    version: input.version,
    tag: input.tag,
    author: input.author,
    enabled: input.enabled,
    entry: input.entry || "",
    runtime: input.runtime || "",
    capabilities: asStringList(input.capabilities),
  };
}

export function asPluginItems(input: any): PluginItem[] {
  return Array.isArray(input) ? input.map(asPluginItem) : [];
}
