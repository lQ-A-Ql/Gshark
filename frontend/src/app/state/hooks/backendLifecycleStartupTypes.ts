import type { Dispatch, SetStateAction } from "react";
import type { ToolRuntimeSnapshot } from "../../core/types";
import type { TSharkStatus } from "../../integrations/clients/toolRuntimeClient";
import type { ToolRuntimeProbeState, ToolRuntimeProbeTransport } from "../toolRuntimeProbeState";

export interface StartupToolRuntimeOptions {
  readonly isCancelled: () => boolean;
  readonly setBackendStatus: Dispatch<SetStateAction<string>>;
  readonly setIsTSharkChecking: Dispatch<SetStateAction<boolean>>;
  readonly setIsToolRuntimeLoading: Dispatch<SetStateAction<boolean>>;
  readonly setToolRuntimeCheckDegraded: Dispatch<SetStateAction<boolean>>;
  readonly setToolRuntimeSnapshot: Dispatch<SetStateAction<ToolRuntimeSnapshot | null>>;
  readonly setTsharkStatus: Dispatch<SetStateAction<TSharkStatus>>;
  readonly setToolRuntimeProbeState: Dispatch<SetStateAction<ToolRuntimeProbeState>>;
  readonly setToolRuntimeProbeTransport: Dispatch<SetStateAction<ToolRuntimeProbeTransport>>;
  readonly setLastToolRuntimeProbeError: Dispatch<SetStateAction<string>>;
}
