import { useEffect, type Dispatch, type MutableRefObject, type SetStateAction } from "react";
import { isAbortLikeError } from "../../utils/asyncControl";
import type { CaptureTaskScope } from "../../utils/captureTaskScope";

type PacketReference = { id: number } | null | undefined;

interface UseSelectedPacketArtifactOptions<T> {
  readonly selectedPacketId: number | null;
  readonly selectedPacket: PacketReference;
  readonly shouldLoad: boolean;
  readonly taskKey: string;
  readonly captureTaskScopeRef: MutableRefObject<CaptureTaskScope>;
  readonly loadArtifact: (packetId: number, signal: AbortSignal) => Promise<T>;
  readonly setValue: Dispatch<SetStateAction<T>>;
  readonly resetValue: T;
}

export function useSelectedPacketArtifact<T>({
  selectedPacketId,
  selectedPacket,
  shouldLoad,
  taskKey,
  captureTaskScopeRef,
  loadArtifact,
  setValue,
  resetValue,
}: UseSelectedPacketArtifactOptions<T>) {
  useEffect(() => {
    if (!shouldLoad || !selectedPacket) {
      setValue(resetValue);
      return;
    }

    const task = captureTaskScopeRef.current.beginTask(taskKey);
    void loadArtifact(selectedPacket.id, task.signal)
      .then((value) => {
        if (task.isCurrent()) {
          setValue(value);
        }
      })
      .catch((error) => {
        if (task.isCurrent() && !isAbortLikeError(error, task.signal)) {
          setValue(resetValue);
        }
      })
      .finally(() => {
        task.finish();
      });

    return () => {
      task.abort();
    };
  }, [
    captureTaskScopeRef,
    loadArtifact,
    resetValue,
    selectedPacket?.id,
    selectedPacketId,
    setValue,
    shouldLoad,
    taskKey,
  ]);
}
