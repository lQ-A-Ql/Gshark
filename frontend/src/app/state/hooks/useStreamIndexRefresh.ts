import { useCallback, type Dispatch, type MutableRefObject, type SetStateAction } from "react";
import type { CaptureTaskScope } from "../../utils/captureTaskScope";
import { refreshStreamIndexState } from "../streamIndexRefresh";
import type { StreamIds } from "../streamState";

type StreamProtocol = "HTTP" | "TCP" | "UDP";

interface UseStreamIndexRefreshOptions {
  readonly activeCapturePathRef: MutableRefObject<string>;
  readonly backendConnected: boolean;
  readonly captureTaskScopeRef: MutableRefObject<CaptureTaskScope>;
  readonly listStreamIds: (protocol: StreamProtocol, signal: AbortSignal) => Promise<number[]>;
  readonly setBackendStatus: Dispatch<SetStateAction<string>>;
  readonly setStreamIds: Dispatch<SetStateAction<StreamIds>>;
}

export function useStreamIndexRefresh(options: UseStreamIndexRefreshOptions) {
  return useCallback(async () => {
    await refreshStreamIndexState(options);
  }, [options]);
}
