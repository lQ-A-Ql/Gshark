import { useCallback } from "react";
import type { TSharkStatus } from "../../integrations/clients/toolRuntimeClient";

export interface UseBackendTSharkDirControlsOptions {
  readonly backendConnected: boolean;
  readonly setBackendStatusText: (status: string) => void;
  readonly allowTSharkDirImpl: (dir: string, backendConnected: boolean, setBackendStatus: (status: string) => void) => Promise<TSharkStatus>;
  readonly removeTSharkAllowedDirImpl: (dir: string, backendConnected: boolean, setBackendStatus: (status: string) => void) => Promise<TSharkStatus>;
  readonly refreshTSharkAllowedDirsImpl: (backendConnected: boolean) => Promise<string[]>;
}

export function useBackendTSharkDirControls({
  backendConnected,
  setBackendStatusText,
  allowTSharkDirImpl,
  removeTSharkAllowedDirImpl,
  refreshTSharkAllowedDirsImpl,
}: UseBackendTSharkDirControlsOptions) {
  const allowTSharkDir = useCallback(
    async (dir: string) => allowTSharkDirImpl(dir, backendConnected, setBackendStatusText),
    [allowTSharkDirImpl, backendConnected, setBackendStatusText],
  );
  const removeTSharkAllowedDir = useCallback(
    async (dir: string) => removeTSharkAllowedDirImpl(dir, backendConnected, setBackendStatusText),
    [backendConnected, removeTSharkAllowedDirImpl, setBackendStatusText],
  );
  const refreshTSharkAllowedDirs = useCallback(
    async () => refreshTSharkAllowedDirsImpl(backendConnected),
    [backendConnected, refreshTSharkAllowedDirsImpl],
  );
  return { allowTSharkDir, removeTSharkAllowedDir, refreshTSharkAllowedDirs };
}
