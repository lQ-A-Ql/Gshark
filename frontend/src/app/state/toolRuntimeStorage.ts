import type { ToolRuntimeConfig } from "../core/types";
import {
  createToolRuntimeStorageRecord,
  explicitFieldsForUserConfig,
  legacyTSharkToolRuntimeConfigState,
  missingToolRuntimeConfigState,
  normalizeExplicitFields,
  normalizeToolRuntimeConfigState,
} from "./toolRuntimeStorageConfig";
import type { ToolRuntimeConfigExplicitFields, ToolRuntimeConfigState } from "./toolRuntimeStorageConfig";

const TSHARK_PATH_STORAGE_KEY = "gshark.tshark-path.v1";
const TOOL_RUNTIME_STORAGE_KEY = "gshark.tool-runtime.v1";

export function readToolRuntimeConfig(): ToolRuntimeConfig {
  return readToolRuntimeConfigState().config;
}

export function readToolRuntimeConfigState(): ToolRuntimeConfigState {
  if (typeof window === "undefined") return missingToolRuntimeConfigState();
  try {
    const raw = window.localStorage.getItem(TOOL_RUNTIME_STORAGE_KEY);
    if (!raw) {
      const legacyTsharkPath = window.localStorage.getItem(TSHARK_PATH_STORAGE_KEY)?.trim() ?? "";
      return legacyTsharkPath ? legacyTSharkToolRuntimeConfigState(legacyTsharkPath) : missingToolRuntimeConfigState();
    }
    const parsed = JSON.parse(raw);
    const legacyTsharkPath = window.localStorage.getItem(TSHARK_PATH_STORAGE_KEY)?.trim() ?? "";
    return normalizeToolRuntimeConfigState(parsed, legacyTsharkPath);
  } catch {
    return missingToolRuntimeConfigState();
  }
}

export function writeObservedToolRuntimeSnapshotConfig(config: ToolRuntimeConfig) {
  writeRuntimeConfigRecord(config, "observed-backend-snapshot", {});
}

export function writeUserToolRuntimeConfig(config: ToolRuntimeConfig, explicitFields = explicitFieldsForUserConfig()) {
  writeRuntimeConfigRecord(config, "stored-runtime-config", normalizeExplicitFields(explicitFields));
}

function writeRuntimeConfigRecord(
  config: ToolRuntimeConfig,
  source: "observed-backend-snapshot" | "stored-runtime-config",
  explicitFields: ToolRuntimeConfigExplicitFields,
) {
  if (typeof window === "undefined") return;
  try {
    const record = createToolRuntimeStorageRecord(config, source, explicitFields);
    window.localStorage.setItem(TOOL_RUNTIME_STORAGE_KEY, JSON.stringify(record));
    if (config.tsharkPath) {
      window.localStorage.setItem(TSHARK_PATH_STORAGE_KEY, config.tsharkPath);
    }
  } catch {
    // localStorage write failed
  }
}
