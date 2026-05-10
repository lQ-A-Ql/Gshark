import { useCallback, type Dispatch, type MutableRefObject, type SetStateAction } from "react";
import type { CaptureTaskScope } from "../../utils/captureTaskScope";

type RefreshAnalysisResultOptions = { capturePath?: string; quietSuccess?: boolean };

interface UseRefreshAnalysisResultOptions {
  readonly activeCapturePathRef: MutableRefObject<string>;
  readonly backendConnected: boolean;
  readonly captureTaskScopeRef: MutableRefObject<CaptureTaskScope>;
  readonly refreshAnalysisResultImpl: (options: {
    capturePath?: string;
    quietSuccess?: boolean;
    backendConnected: boolean;
    activeCapturePath: string;
    captureTaskScope: CaptureTaskScope;
    setBackendStatus: Dispatch<SetStateAction<string>>;
  }) => Promise<void>;
  readonly setBackendStatus: Dispatch<SetStateAction<string>>;
}

export function useRefreshAnalysisResult(options: UseRefreshAnalysisResultOptions) {
  return useCallback(
    async (refreshOptions?: RefreshAnalysisResultOptions) => {
      await options.refreshAnalysisResultImpl({
        ...refreshOptions,
        backendConnected: options.backendConnected,
        activeCapturePath: options.activeCapturePathRef.current,
        captureTaskScope: options.captureTaskScopeRef.current,
        setBackendStatus: options.setBackendStatus,
      });
    },
    [options],
  );
}
