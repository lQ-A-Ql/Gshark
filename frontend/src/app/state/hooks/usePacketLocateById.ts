import { useCallback, type Dispatch, type MutableRefObject, type SetStateAction } from "react";
import type { Packet } from "../../core/types";
import type { PacketLocateResult, PacketsPageResult } from "../../integrations/clients/captureClient";
import type { CaptureTaskScope } from "../../utils/captureTaskScope";
import { locatePacketByIdWorkflow } from "../packetLocateWorkflow";

interface UsePacketLocateByIdOptions {
  readonly activeCapturePathRef: MutableRefObject<string>;
  readonly captureTaskScopeRef: MutableRefObject<CaptureTaskScope>;
  readonly displayFilter: string;
  readonly loadPacketPage: (cursor: number, filterOverride?: string) => Promise<PacketsPageResult | null>;
  readonly locatePacketPage: (
    packetId: number,
    limit: number,
    filter: string,
    signal: AbortSignal,
  ) => Promise<PacketLocateResult>;
  readonly pageSize: number;
  readonly setBackendStatus: Dispatch<SetStateAction<string>>;
  readonly setDisplayFilter: Dispatch<SetStateAction<string>>;
  readonly setSelectedPacketId: Dispatch<SetStateAction<number | null>>;
}

export function usePacketLocateById(options: UsePacketLocateByIdOptions) {
  return useCallback(
    async (packetId: number, filterOverride?: string): Promise<Packet | null> => {
      return locatePacketByIdWorkflow({
        packetId,
        pageSize: options.pageSize,
        filterOverride,
        displayFilter: options.displayFilter,
        activeCapturePathRef: options.activeCapturePathRef,
        captureTaskScopeRef: options.captureTaskScopeRef,
        locatePacketPage: options.locatePacketPage,
        loadPacketPage: options.loadPacketPage,
        setDisplayFilter: options.setDisplayFilter,
        setSelectedPacketId: (value) => options.setSelectedPacketId(value),
        setBackendStatus: options.setBackendStatus,
      });
    },
    [options],
  );
}
