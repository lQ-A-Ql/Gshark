import { useCallback, type Dispatch, type SetStateAction } from "react";
import type { Packet } from "../../core/types";
import { keepSelectedPacketDetailForId } from "../selectedPacketState";

interface UseSelectedPacketActionOptions {
  readonly setSelectedPacketId: Dispatch<SetStateAction<number | null>>;
  readonly setSelectedPacketDetail: Dispatch<SetStateAction<Packet | null>>;
}

export function useSelectedPacketAction({
  setSelectedPacketId,
  setSelectedPacketDetail,
}: UseSelectedPacketActionOptions) {
  return useCallback(
    (id: number) => {
      setSelectedPacketId(id);
      setSelectedPacketDetail((prev) => keepSelectedPacketDetailForId(prev, id));
    },
    [setSelectedPacketDetail, setSelectedPacketId],
  );
}
