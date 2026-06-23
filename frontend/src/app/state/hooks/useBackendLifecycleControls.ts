import { useCallback } from "react";
import { backendClients } from "../../integrations/backendClients";
import type { DecryptionConfig } from "../../core/types";
import type { UseBackendLifecycleControlsOptions } from "./backendLifecycleTypes";
import { useBackendTSharkDirControls } from "./useBackendTSharkDirControls";
import { useBackendToolRuntimeControls } from "./useBackendToolRuntimeControls";

export function useBackendLifecycleControls({
  backendConnected,
  setBackendStatus,
  setDecryptionConfig,
  setTSharkPathImpl,
  allowTSharkDirImpl,
  removeTSharkAllowedDirImpl,
  refreshTSharkAllowedDirsImpl,
  refreshToolRuntimeSnapshotImpl,
  saveToolRuntimeConfigImpl,
}: UseBackendLifecycleControlsOptions) {
  const { allowTSharkDir, removeTSharkAllowedDir, refreshTSharkAllowedDirs } = useBackendTSharkDirControls({
    backendConnected,
    setBackendStatusText: setBackendStatus,
    allowTSharkDirImpl,
    removeTSharkAllowedDirImpl,
    refreshTSharkAllowedDirsImpl,
  });
  const { setTSharkPath, refreshToolRuntimeSnapshot, saveToolRuntimeConfig } = useBackendToolRuntimeControls({
    backendConnected,
    setBackendStatus,
    setTSharkPathImpl,
    refreshToolRuntimeSnapshotImpl,
    saveToolRuntimeConfigImpl,
  });
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
  return {
    setTSharkPath,
    allowTSharkDir,
    removeTSharkAllowedDir,
    refreshTSharkAllowedDirs,
    refreshToolRuntimeSnapshot,
    saveToolRuntimeConfig,
    updateDecryptionConfig,
  };
}
