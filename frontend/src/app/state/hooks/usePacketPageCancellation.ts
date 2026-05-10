import { useCallback, type Dispatch, type MutableRefObject, type SetStateAction } from "react";
import type { CaptureTaskScope } from "../../utils/captureTaskScope";

interface UsePacketPageCancellationOptions {
  readonly packetPageSeqRef: MutableRefObject<number>;
  readonly captureTaskScopeRef: MutableRefObject<CaptureTaskScope>;
  readonly setIsPageLoading: Dispatch<SetStateAction<boolean>>;
}

export function usePacketPageCancellation({
  packetPageSeqRef,
  captureTaskScopeRef,
  setIsPageLoading,
}: UsePacketPageCancellationOptions) {
  return useCallback(() => {
    packetPageSeqRef.current += 1;
    captureTaskScopeRef.current.abortTask("packet-page");
    setIsPageLoading(false);
  }, [captureTaskScopeRef, packetPageSeqRef, setIsPageLoading]);
}
