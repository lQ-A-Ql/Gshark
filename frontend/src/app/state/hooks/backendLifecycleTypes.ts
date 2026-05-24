import type { Dispatch, MutableRefObject, SetStateAction } from "react";

import type { DecryptionConfig, MCPConfig, MCPStatus, ToolRuntimeConfig, ToolRuntimeSnapshot } from "../../core/types";
import type { TSharkStatus } from "../../integrations/clients/toolRuntimeClient";
import type { MediaAnalysisProgress, ThreatAnalysisProgress } from "./useAnalysisProgress";
import type { ToolRuntimeProbeState, ToolRuntimeProbeTransport } from "../toolRuntimeProbeState";
import type { ToolRuntimeConfigExplicitFields } from "../toolRuntimeStorageConfig";

export interface UseBackendLifecycleOptions {
  readonly activeCapturePathRef: MutableRefObject<string>;
  readonly captureWaitersRef: MutableRefObject<Set<() => void>>;
  readonly parseFinishedRef: MutableRefObject<boolean>;
  readonly parseErrorRef: MutableRefObject<string>;
  readonly preloadingRef: MutableRefObject<boolean>;
  readonly scheduleLoadMoreRef: MutableRefObject<() => void>;
  readonly refreshAnalysisResultRef: MutableRefObject<
    (options?: { capturePath?: string; quietSuccess?: boolean }) => Promise<void>
  >;
  readonly updateProgressFromStatusRef: MutableRefObject<(message: string) => boolean>;
  readonly setSelectedPacketId: Dispatch<SetStateAction<number | null>>;
  readonly setMediaAnalysisProgress: Dispatch<SetStateAction<MediaAnalysisProgress>>;
  readonly setThreatAnalysisProgress: Dispatch<SetStateAction<ThreatAnalysisProgress>>;
  readonly setIsThreatAnalysisLoading: Dispatch<SetStateAction<boolean>>;
}

export interface BackendLifecycleState {
  backendConnected: boolean;
  backendStatus: string;
  setBackendStatus: Dispatch<SetStateAction<string>>;
  decryptionConfig: DecryptionConfig;
  updateDecryptionConfig: (patch: Partial<DecryptionConfig>) => void;
  tsharkStatus: TSharkStatus;
  isTSharkChecking: boolean;
  toolRuntimeCheckDegraded: boolean;
  toolRuntimeProbeState: ToolRuntimeProbeState;
  toolRuntimeProbeTransport: ToolRuntimeProbeTransport;
  lastToolRuntimeProbeError: string;
  setTSharkPath: (path: string) => Promise<void>;
  toolRuntimeSnapshot: ToolRuntimeSnapshot | null;
  isToolRuntimeLoading: boolean;
  refreshToolRuntimeSnapshot: () => Promise<ToolRuntimeSnapshot | null>;
  saveToolRuntimeConfig: (
    patch: Partial<ToolRuntimeConfig>,
    explicitFields?: ToolRuntimeConfigExplicitFields,
  ) => Promise<ToolRuntimeSnapshot>;
  backendAuthToken: string;
  isBackendAuthTokenLoading: boolean;
  mcpStatus: MCPStatus | null;
  refreshMCPStatus: () => Promise<MCPStatus | null>;
  saveMCPConfig: (config: MCPConfig) => Promise<MCPStatus>;
}
