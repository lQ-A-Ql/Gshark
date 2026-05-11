import { useCallback, type Dispatch, type SetStateAction } from "react";

interface UseOpenCaptureActionOptions {
  readonly setDisplayFilter: Dispatch<SetStateAction<string>>;
  readonly startCapture: (filePath?: string, filterOverride?: string) => Promise<boolean>;
}

export function useOpenCaptureAction({ setDisplayFilter, startCapture }: UseOpenCaptureActionOptions) {
  return useCallback(
    async (filePath?: string) => {
      setDisplayFilter("");
      return startCapture(filePath, "");
    },
    [setDisplayFilter, startCapture],
  );
}
