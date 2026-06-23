import { useCallback } from "react";
import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../../core/types";
import type { ToolRuntimeConfigExplicitFields } from "../toolRuntimeStorageConfig";

interface UseBackendToolRuntimeControlsOptions {
  readonly backendConnected: boolean;
  readonly setBackendStatus: (status: string) => void;
  readonly setTSharkPathImpl: (path: string, backendConnected: boolean, setBackendStatus: (status: string) => void) => Promise<void>;
  readonly refreshToolRuntimeSnapshotImpl: (backendConnected: boolean) => Promise<ToolRuntimeSnapshot | null>;
  readonly saveToolRuntimeConfigImpl: (
    patch: Partial<ToolRuntimeConfig>,
    backendConnected: boolean,
    setBackendStatus: (status: string) => void,
    explicitFields?: ToolRuntimeConfigExplicitFields,
  ) => Promise<ToolRuntimeSnapshot>;
}

export function useBackendToolRuntimeControls({
  backendConnected,
  setBackendStatus,
  setTSharkPathImpl,
  refreshToolRuntimeSnapshotImpl,
  saveToolRuntimeConfigImpl,
}: UseBackendToolRuntimeControlsOptions) {
  const setTSharkPath = useCallback(
    async (path: string) => {
      await setTSharkPathImpl(path, backendConnected, setBackendStatus);
    },
    [backendConnected, setBackendStatus, setTSharkPathImpl],
  );
  const refreshToolRuntimeSnapshot = useCallback(async () => {
    return await refreshToolRuntimeSnapshotImpl(backendConnected);
  }, [backendConnected, refreshToolRuntimeSnapshotImpl]);
  const saveToolRuntimeConfig = useCallback(
    async (patch: Partial<ToolRuntimeConfig>, explicitFields?: ToolRuntimeConfigExplicitFields) => {
      return await saveToolRuntimeConfigImpl(patch, backendConnected, setBackendStatus, explicitFields);
    },
    [backendConnected, saveToolRuntimeConfigImpl, setBackendStatus],
  );
  return { setTSharkPath, refreshToolRuntimeSnapshot, saveToolRuntimeConfig };
}
