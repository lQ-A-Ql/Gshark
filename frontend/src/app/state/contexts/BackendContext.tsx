import { createContext, useContext, type PropsWithChildren } from "react";
import type { DecryptionConfig, MCPConfig, MCPStatus, ToolRuntimeSnapshot } from "../../core/types";
import type { TSharkStatus } from "../../integrations/clients/toolRuntimeClient";
import type { ToolRuntimeProbeState, ToolRuntimeProbeTransport } from "../toolRuntimeProbeState";
import type { ToolRuntimeConfigExplicitFields } from "../toolRuntimeStorageConfig";
import type { ToolRuntimeConfig } from "../../core/types";

export interface BackendContextValue {
  backendConnected: boolean;
  backendStatus: string;
  tsharkStatus: TSharkStatus;
  isTSharkChecking: boolean;
  toolRuntimeCheckDegraded: boolean;
  toolRuntimeProbeState: ToolRuntimeProbeState;
  toolRuntimeProbeTransport: ToolRuntimeProbeTransport;
  lastToolRuntimeProbeError: string;
  setTSharkPath: (path: string) => Promise<void>;
  allowTSharkDir: (dir: string) => Promise<TSharkStatus>;
  removeTSharkAllowedDir: (dir: string) => Promise<TSharkStatus>;
  refreshTSharkAllowedDirs: () => Promise<string[]>;
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
  decryptionConfig: DecryptionConfig;
  updateDecryptionConfig: (patch: Partial<DecryptionConfig>) => void;
}

const BackendContext = createContext<BackendContextValue | null>(null);

export function BackendProvider({ children, value }: PropsWithChildren<{ value: BackendContextValue }>) {
  return <BackendContext.Provider value={value}>{children}</BackendContext.Provider>;
}

export function useBackend() {
  const ctx = useContext(BackendContext);
  if (!ctx) {
    throw new Error("useBackend must be used inside BackendProvider");
  }
  return ctx;
}
