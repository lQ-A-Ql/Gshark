import { useCallback } from "react";

interface UseWorkspaceFilterActionOptions {
  applyFilter: (value: string) => void;
  displayFilter: string;
  rememberFilter: (value: string) => void;
  setDisplayFilter: (value: string) => void;
}

export function useWorkspaceFilterAction({
  applyFilter,
  displayFilter,
  rememberFilter,
  setDisplayFilter,
}: UseWorkspaceFilterActionOptions) {
  return useCallback(
    (value?: string) => {
      const next = (value ?? displayFilter).trim();
      if (next) {
        if (next !== displayFilter) {
          setDisplayFilter(next);
        }
        rememberFilter(next);
        applyFilter(next);
        return;
      }
      applyFilter("");
    },
    [applyFilter, displayFilter, rememberFilter, setDisplayFilter],
  );
}
