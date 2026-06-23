import { useCallback } from "react";
import type { ToolRuntimeSnapshot } from "../../core/types";
import type { TSharkStatus } from "../../integrations/clients/toolRuntimeClient";
import {
  allowTSharkDirAction,
  refreshTSharkAllowedDirsAction,
  removeTSharkAllowedDirAction,
  setTSharkPathAction,
} from "../toolRuntimeTSharkActions";

interface UseToolRuntimeTSharkControlsOptions {
  readonly toolRuntimeSnapshot: ToolRuntimeSnapshot | null;
  readonly setTsharkStatus: (value: TSharkStatus | ((prev: TSharkStatus) => TSharkStatus)) => void;
  readonly setToolRuntimeCheckDegraded: (value: boolean | ((prev: boolean) => boolean)) => void;
  readonly setToolRuntimeSnapshot: (value: ToolRuntimeSnapshot | null | ((prev: ToolRuntimeSnapshot | null) => ToolRuntimeSnapshot | null)) => void;
}

export function useToolRuntimeTSharkControls({
  toolRuntimeSnapshot,
  setTsharkStatus,
  setToolRuntimeCheckDegraded,
  setToolRuntimeSnapshot,
}: UseToolRuntimeTSharkControlsOptions) {
  const setTSharkPath = useCallback(
    async (path: string, backendConnected: boolean, setBackendStatus: (status: string) => void) => {
      await setTSharkPathAction(path, backendConnected, {
        setBackendStatus,
        setToolRuntimeCheckDegraded,
        setTsharkStatus,
        setToolRuntimeSnapshot,
        toolRuntimeSnapshot,
      });
    },
    [setToolRuntimeCheckDegraded, setTsharkStatus, setToolRuntimeSnapshot, toolRuntimeSnapshot],
  );

  const allowTSharkDir = useCallback(
    async (dir: string, backendConnected: boolean, setBackendStatus: (status: string) => void) => {
      return allowTSharkDirAction(dir, backendConnected, {
        setBackendStatus,
        setTsharkStatus,
        setToolRuntimeSnapshot,
        toolRuntimeSnapshot,
      });
    },
    [setTsharkStatus, setToolRuntimeSnapshot, toolRuntimeSnapshot],
  );

  const removeTSharkAllowedDir = useCallback(
    async (dir: string, backendConnected: boolean, setBackendStatus: (status: string) => void) => {
      return removeTSharkAllowedDirAction(dir, backendConnected, {
        setBackendStatus,
        setTsharkStatus,
        setToolRuntimeSnapshot,
        toolRuntimeSnapshot,
      });
    },
    [setTsharkStatus, setToolRuntimeSnapshot, toolRuntimeSnapshot],
  );

  const refreshTSharkAllowedDirs = useCallback(
    async (backendConnected: boolean) => {
      return refreshTSharkAllowedDirsAction(backendConnected, {
        setToolRuntimeSnapshot,
        toolRuntimeSnapshot,
      });
    },
    [setToolRuntimeSnapshot, toolRuntimeSnapshot],
  );

  return { setTSharkPath, allowTSharkDir, removeTSharkAllowedDir, refreshTSharkAllowedDirs };
}
