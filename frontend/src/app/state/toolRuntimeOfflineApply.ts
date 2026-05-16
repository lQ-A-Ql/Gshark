import type { Dispatch, SetStateAction } from "react";
import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../core/types";
import type { TSharkStatus } from "../integrations/clients/toolRuntimeClient";
import { buildOfflineToolRuntimeSnapshot } from "./toolRuntimeOfflineSnapshot";
import type { ToolRuntimeProbeState, ToolRuntimeProbeTransport } from "./toolRuntimeProbeState";

interface OfflineApplyOptions {
  readonly config: ToolRuntimeConfig;
  readonly setToolRuntimeProbeState: Dispatch<SetStateAction<ToolRuntimeProbeState>>;
  readonly setToolRuntimeProbeTransport: Dispatch<SetStateAction<ToolRuntimeProbeTransport>>;
  readonly setLastToolRuntimeProbeError: Dispatch<SetStateAction<string>>;
  readonly setToolRuntimeSnapshot: Dispatch<SetStateAction<ToolRuntimeSnapshot | null>>;
  readonly setTsharkStatus: Dispatch<SetStateAction<TSharkStatus>>;
}

export function applyOfflineToolRuntimeConfig({
  config,
  setToolRuntimeProbeState,
  setToolRuntimeProbeTransport,
  setLastToolRuntimeProbeError,
  setToolRuntimeSnapshot,
  setTsharkStatus,
}: OfflineApplyOptions): ToolRuntimeSnapshot {
  const snapshot = buildOfflineToolRuntimeSnapshot(config);
  setToolRuntimeProbeState("ready");
  setToolRuntimeProbeTransport("unknown");
  setLastToolRuntimeProbeError("");
  setToolRuntimeSnapshot(snapshot);
  setTsharkStatus((prev) => ({
    ...prev,
    customPath: config.tsharkPath,
    usingCustomPath: config.tsharkPath.length > 0,
  }));
  return snapshot;
}
