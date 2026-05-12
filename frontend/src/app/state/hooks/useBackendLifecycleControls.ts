import { useCallback, type Dispatch, type SetStateAction } from "react";
import type { DecryptionConfig, ToolRuntimeConfig, ToolRuntimeSnapshot } from "../../core/types";
import { backendClients } from "../../integrations/wailsBridge";

interface UseBackendLifecycleControlsOptions {
  readonly backendConnected: boolean;
  readonly setBackendStatus: Dispatch<SetStateAction<string>>;
  readonly setDecryptionConfig: Dispatch<SetStateAction<DecryptionConfig>>;
  readonly setTSharkPathImpl: (
    path: string,
    backendConnected: boolean,
    setBackendStatus: (status: string) => void,
  ) => Promise<void>;
  readonly refreshToolRuntimeSnapshotImpl: (backendConnected: boolean) => Promise<ToolRuntimeSnapshot | null>;
  readonly saveToolRuntimeConfigImpl: (
    patch: Partial<ToolRuntimeConfig>,
    backendConnected: boolean,
    setBackendStatus: (status: string) => void,
  ) => Promise<ToolRuntimeSnapshot>;
}

export function useBackendLifecycleControls({
  backendConnected,
  setBackendStatus,
  setDecryptionConfig,
  setTSharkPathImpl,
  refreshToolRuntimeSnapshotImpl,
  saveToolRuntimeConfigImpl,
}: UseBackendLifecycleControlsOptions) {
  const setBackendStatusText = useCallback((status: string) => setBackendStatus(status), [setBackendStatus]);

  const setTSharkPath = useCallback(
    async (path: string) => {
      await setTSharkPathImpl(path, backendConnected, setBackendStatusText);
    },
    [backendConnected, setBackendStatusText, setTSharkPathImpl],
  );

  const refreshToolRuntimeSnapshot = useCallback(async () => {
    return await refreshToolRuntimeSnapshotImpl(backendConnected);
  }, [backendConnected, refreshToolRuntimeSnapshotImpl]);

  const saveToolRuntimeConfig = useCallback(
    async (patch: Partial<ToolRuntimeConfig>) => {
      return await saveToolRuntimeConfigImpl(patch, backendConnected, setBackendStatusText);
    },
    [backendConnected, saveToolRuntimeConfigImpl, setBackendStatusText],
  );

  const updateDecryptionConfig = useCallback(
    (patch: Partial<DecryptionConfig>) => {
      setDecryptionConfig((prev) => {
        const next = { ...prev, ...patch };
        if (backendConnected) {
          void backendClients.securityMaterial.updateTLSConfig(next).catch(() => setBackendStatus("TLS 配置更新失败"));
        }
        return next;
      });
    },
    [backendConnected, setBackendStatus, setDecryptionConfig],
  );

  return { setTSharkPath, refreshToolRuntimeSnapshot, saveToolRuntimeConfig, updateDecryptionConfig };
}
