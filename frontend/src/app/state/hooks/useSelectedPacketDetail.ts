import { useEffect, type Dispatch, type MutableRefObject, type SetStateAction } from "react";
import { isAbortLikeError } from "../../utils/asyncControl";
import type { CaptureTaskScope } from "../../utils/captureTaskScope";
import type { Packet } from "../../core/types";

interface UseSelectedPacketDetailOptions {
  readonly selectedPacketId: number | null;
  readonly shouldLoad: boolean;
  readonly captureTaskScopeRef: MutableRefObject<CaptureTaskScope>;
  readonly loadPacket: (packetId: number, signal: AbortSignal) => Promise<Packet>;
  readonly setSelectedPacketDetail: Dispatch<SetStateAction<Packet | null>>;
}

export function useSelectedPacketDetail({
  selectedPacketId,
  shouldLoad,
  captureTaskScopeRef,
  loadPacket,
  setSelectedPacketDetail,
}: UseSelectedPacketDetailOptions) {
  useEffect(() => {
    if (selectedPacketId == null) {
      setSelectedPacketDetail(null);
      return;
    }

    if (!shouldLoad) {
      return;
    }

    const task = captureTaskScopeRef.current.beginTask("packet-detail");
    void loadPacket(selectedPacketId, task.signal)
      .then((packet) => {
        if (task.isCurrent()) {
          setSelectedPacketDetail(packet);
        }
      })
      .catch((error) => {
        if (task.isCurrent() && !isAbortLikeError(error, task.signal)) {
          setSelectedPacketDetail(null);
        }
      })
      .finally(() => {
        task.finish();
      });

    return () => {
      task.abort();
    };
  }, [captureTaskScopeRef, loadPacket, selectedPacketId, setSelectedPacketDetail, shouldLoad]);
}
