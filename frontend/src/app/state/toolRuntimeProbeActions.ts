import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../core/types";
import { backendClients } from "../integrations/backendClients";
import { withAbortableTimeout } from "../utils/asyncControl";
import { STARTUP_TOOL_RUNTIME_TIMEOUT_MS } from "./captureConstants";

export const FULL_TOOL_RUNTIME_TIMEOUT_MS = 15000;

export function probeToolRuntimeSnapshot(mode: "fast" | "full" = "full"): Promise<ToolRuntimeSnapshot> {
  const timeoutMs = mode === "fast" ? STARTUP_TOOL_RUNTIME_TIMEOUT_MS : FULL_TOOL_RUNTIME_TIMEOUT_MS;
  return withAbortableTimeout(
    (signal) => backendClients.runtime.getToolRuntimeSnapshot(signal, mode),
    timeoutMs,
    mode === "fast" ? "manual fast tool runtime check timed out" : "manual full tool runtime check timed out",
  );
}

export function syncToolRuntimeConfig(
  config: ToolRuntimeConfig,
  mode: "fast" | "full" = "full",
): Promise<ToolRuntimeSnapshot> {
  const timeoutMs = mode === "fast" ? STARTUP_TOOL_RUNTIME_TIMEOUT_MS : FULL_TOOL_RUNTIME_TIMEOUT_MS;
  return withAbortableTimeout(
    (signal) => backendClients.runtime.updateToolRuntimeConfig(config, signal, mode),
    timeoutMs,
    mode === "fast"
      ? "manual fast tool runtime config sync timed out"
      : "manual full tool runtime config sync timed out",
  );
}
