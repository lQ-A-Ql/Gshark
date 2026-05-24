import { useCallback, type Dispatch, type SetStateAction } from "react";
import type { MCPConfig, MCPStatus } from "../../core/types";
import { backendClients } from "../../integrations/backendClients";

interface UseBackendLifecycleMCPControlsOptions {
  readonly backendConnected: boolean;
  readonly setMCPStatus: Dispatch<SetStateAction<MCPStatus | null>>;
}

export function useBackendLifecycleMCPControls({
  backendConnected,
  setMCPStatus,
}: UseBackendLifecycleMCPControlsOptions) {
  const refreshMCPStatus = useCallback(async () => {
    if (!backendConnected) return null;
    const status = await backendClients.runtime.getMCPStatus();
    setMCPStatus(status);
    return status;
  }, [backendConnected, setMCPStatus]);

  const saveMCPConfig = useCallback(
    async (config: MCPConfig) => {
      const status = await backendClients.runtime.updateMCPConfig(config);
      setMCPStatus(status);
      return status;
    },
    [setMCPStatus],
  );

  return { refreshMCPStatus, saveMCPConfig };
}
