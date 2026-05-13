export interface PluginSource {
  id: string;
  configPath: string;
  configContent: string;
  logicPath: string;
  logicContent: string;
  entry: string;
}

import { asPlainObject } from "./mapperPrimitives";

export function asPluginSource(input: unknown, fallbackId = ""): PluginSource {
  const payload = asPlainObject(input) ?? {};
  return {
    id: String(payload.id ?? fallbackId),
    configPath: String(payload.config_path ?? ""),
    configContent: String(payload.config_content ?? ""),
    logicPath: String(payload.logic_path ?? ""),
    logicContent: String(payload.logic_content ?? ""),
    entry: String(payload.entry ?? ""),
  };
}

export function toPluginSourceRequest(source: PluginSource) {
  return {
    id: source.id,
    config_path: source.configPath,
    config_content: source.configContent,
    logic_path: source.logicPath,
    logic_content: source.logicContent,
    entry: source.entry,
  };
}
