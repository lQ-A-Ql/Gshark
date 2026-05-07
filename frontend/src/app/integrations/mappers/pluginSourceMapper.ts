export interface PluginSource {
  id: string;
  configPath: string;
  configContent: string;
  logicPath: string;
  logicContent: string;
  entry: string;
}

export function asPluginSource(payload: any, fallbackId = ""): PluginSource {
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
