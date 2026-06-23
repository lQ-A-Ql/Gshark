import type { ToolRuntimeConfig } from "../core/types";

export type ToolRuntimeConfigSource =
  | "missing"
  | "observed-backend-snapshot"
  | "legacy-tshark-only"
  | "stored-runtime-config";
export type ToolRuntimeConfigField = keyof ToolRuntimeConfig;
export type ToolRuntimeConfigExplicitFields = Partial<Record<ToolRuntimeConfigField, boolean>>;

export interface ToolRuntimeConfigState {
  config: ToolRuntimeConfig;
  source: ToolRuntimeConfigSource;
  explicitFields: ToolRuntimeConfigExplicitFields;
}

export interface ToolRuntimeConfigStorageRecord {
  version: 2;
  source: "observed-backend-snapshot" | "stored-runtime-config";
  config: ToolRuntimeConfig;
  explicitFields?: ToolRuntimeConfigExplicitFields;
}

export const EMPTY_TOOL_RUNTIME_CONFIG: ToolRuntimeConfig = {
  tsharkPath: "",
  tsharkAllowedDirs: [],
  ffmpegPath: "",
  ffmpegAllowedDirs: [],
  pythonPath: "",
  pythonAllowedDirs: [],
  voskModelPath: "",
  yaraEnabled: true,
  yaraBin: "",
  yaraAllowedDirs: [],
  yaraRules: "",
  yaraTimeoutMs: 25000,
};

export const TOOL_RUNTIME_CONFIG_FIELDS: readonly ToolRuntimeConfigField[] = [
  "tsharkPath",
  "tsharkAllowedDirs",
  "ffmpegPath",
  "ffmpegAllowedDirs",
  "pythonPath",
  "pythonAllowedDirs",
  "voskModelPath",
  "yaraEnabled",
  "yaraBin",
  "yaraAllowedDirs",
  "yaraRules",
  "yaraTimeoutMs",
];

export function emptyToolRuntimeConfig(): ToolRuntimeConfig {
  return { ...EMPTY_TOOL_RUNTIME_CONFIG };
}

export function missingToolRuntimeConfigState(): ToolRuntimeConfigState {
  return { config: emptyToolRuntimeConfig(), source: "missing", explicitFields: {} };
}

export function legacyTSharkToolRuntimeConfigState(path: string): ToolRuntimeConfigState {
  return {
    config: { ...emptyToolRuntimeConfig(), tsharkPath: path.trim() },
    source: "legacy-tshark-only",
    explicitFields: { tsharkPath: true },
  };
}

export function normalizeStoredToolRuntimeConfig(parsed: unknown, legacyTsharkPath = ""): ToolRuntimeConfig {
  const payload = runtimeConfigPayload(parsed);
  return {
    tsharkPath: String(payload.tsharkPath ?? legacyTsharkPath).trim(),
    tsharkAllowedDirs: asStringList(payload.tsharkAllowedDirs),
    ffmpegPath: String(payload.ffmpegPath ?? "").trim(),
    ffmpegAllowedDirs: asStringList(payload.ffmpegAllowedDirs),
    pythonPath: String(payload.pythonPath ?? "").trim(),
    pythonAllowedDirs: asStringList(payload.pythonAllowedDirs),
    voskModelPath: String(payload.voskModelPath ?? "").trim(),
    yaraEnabled: payload.yaraEnabled !== false,
    yaraBin: String(payload.yaraBin ?? "").trim(),
    yaraAllowedDirs: asStringList(payload.yaraAllowedDirs),
    yaraRules: String(payload.yaraRules ?? "").trim(),
    yaraTimeoutMs: Number(payload.yaraTimeoutMs ?? 25000) || 25000,
  };
}

export function normalizeToolRuntimeConfigState(parsed: unknown, legacyTsharkPath = ""): ToolRuntimeConfigState {
  const record = asRecord(parsed);
  if (record.version === 2 && asRecord(record.config)) {
    const config = normalizeStoredToolRuntimeConfig(record, legacyTsharkPath);
    if (record.source === "stored-runtime-config") {
      const fields = normalizeExplicitFields(record.explicitFields);
      return {
        config,
        source: "stored-runtime-config",
        explicitFields: hasExplicitFields(fields) ? fields : explicitFieldsFromLegacyConfig(config),
      };
    }
    return { config, source: "observed-backend-snapshot", explicitFields: {} };
  }

  const config = normalizeStoredToolRuntimeConfig(parsed, legacyTsharkPath);
  const explicitFields = explicitFieldsFromLegacyConfig(config);
  if (!hasExplicitFields(explicitFields)) {
    return { config, source: "observed-backend-snapshot", explicitFields: {} };
  }
  if (isOnlyExplicitField(explicitFields, "tsharkPath")) {
    return { config, source: "legacy-tshark-only", explicitFields };
  }
  return { config, source: "stored-runtime-config", explicitFields };
}

export function normalizeExplicitFields(input: unknown): ToolRuntimeConfigExplicitFields {
  const payload = asRecord(input);
  const out: ToolRuntimeConfigExplicitFields = {};
  for (const field of TOOL_RUNTIME_CONFIG_FIELDS) {
    if (payload[field] === true) out[field] = true;
  }
  return out;
}

export function explicitFieldsForUserConfig(): ToolRuntimeConfigExplicitFields {
  return Object.fromEntries(
    TOOL_RUNTIME_CONFIG_FIELDS.map((field) => [field, true]),
  ) as ToolRuntimeConfigExplicitFields;
}

export function explicitFieldsFromPatch(patch: Partial<ToolRuntimeConfig>): ToolRuntimeConfigExplicitFields {
  const fields: ToolRuntimeConfigExplicitFields = {};
  for (const field of TOOL_RUNTIME_CONFIG_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(patch, field)) fields[field] = true;
  }
  return fields;
}

export function explicitFieldsFromLegacyConfig(config: ToolRuntimeConfig): ToolRuntimeConfigExplicitFields {
  const fields: ToolRuntimeConfigExplicitFields = {};
  if (config.tsharkPath) fields.tsharkPath = true;
  if (config.tsharkAllowedDirs && config.tsharkAllowedDirs.length > 0) fields.tsharkAllowedDirs = true;
  if (config.ffmpegPath) fields.ffmpegPath = true;
  if (config.ffmpegAllowedDirs && config.ffmpegAllowedDirs.length > 0) fields.ffmpegAllowedDirs = true;
  if (config.pythonPath) fields.pythonPath = true;
  if (config.pythonAllowedDirs && config.pythonAllowedDirs.length > 0) fields.pythonAllowedDirs = true;
  if (config.voskModelPath) fields.voskModelPath = true;
  if (config.yaraEnabled !== EMPTY_TOOL_RUNTIME_CONFIG.yaraEnabled) fields.yaraEnabled = true;
  if (config.yaraBin) fields.yaraBin = true;
  if (config.yaraAllowedDirs && config.yaraAllowedDirs.length > 0) fields.yaraAllowedDirs = true;
  if (config.yaraRules) fields.yaraRules = true;
  if (config.yaraTimeoutMs !== EMPTY_TOOL_RUNTIME_CONFIG.yaraTimeoutMs) fields.yaraTimeoutMs = true;
  return fields;
}

export function hasExplicitFields(fields: ToolRuntimeConfigExplicitFields): boolean {
  return TOOL_RUNTIME_CONFIG_FIELDS.some((field) => fields[field] === true);
}

export function createToolRuntimeStorageRecord(
  config: ToolRuntimeConfig,
  source: ToolRuntimeConfigStorageRecord["source"],
  explicitFields: ToolRuntimeConfigExplicitFields = {},
): ToolRuntimeConfigStorageRecord {
  return {
    version: 2,
    source,
    config: normalizeStoredToolRuntimeConfig(config),
    explicitFields: source === "stored-runtime-config" ? normalizeExplicitFields(explicitFields) : {},
  };
}

function asStringList(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  return input.map((value) => String(value ?? "")).filter((value) => value.length > 0);
}

function runtimeConfigPayload(parsed: unknown): Partial<ToolRuntimeConfig> {
  const record = asRecord(parsed);
  if (record.version === 2) {
    return asRecord(record.config) as Partial<ToolRuntimeConfig>;
  }
  return record as Partial<ToolRuntimeConfig>;
}

function isOnlyExplicitField(fields: ToolRuntimeConfigExplicitFields, expected: ToolRuntimeConfigField): boolean {
  return TOOL_RUNTIME_CONFIG_FIELDS.every((field) => fields[field] === (field === expected ? true : undefined));
}

function asRecord(input: unknown): Record<string, unknown> {
  return typeof input === "object" && input !== null ? (input as Record<string, unknown>) : {};
}
