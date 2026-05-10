import { useCallback, type Dispatch, type MutableRefObject, type SetStateAction } from "react";
import type { PacketsPageResult } from "../../integrations/clients/captureClient";
import type { CaptureTaskScope } from "../../utils/captureTaskScope";
import { loadPacketPageState } from "../packetPageLoad";

type PacketPageLoadOptions = { finishFilterLoading?: boolean };

interface UsePacketPageLoadOptions {
  readonly activeCapturePathRef: MutableRefObject<string>;
  readonly backendConnected: boolean;
  readonly captureTaskScopeRef: MutableRefObject<CaptureTaskScope>;
  readonly commitPacketPage: (cursor: number, page: PacketsPageResult) => void;
  readonly displayFilter: string;
  readonly listPacketsPage: (
    cursor: number,
    limit: number,
    filter: string,
    signal: AbortSignal,
  ) => Promise<PacketsPageResult>;
  readonly packetPageSeqRef: MutableRefObject<number>;
  readonly pageSize: number;
  readonly setBackendStatus: Dispatch<SetStateAction<string>>;
  readonly setIsFilterLoading: Dispatch<SetStateAction<boolean>>;
  readonly setIsPageLoading: Dispatch<SetStateAction<boolean>>;
  readonly setPacketPageError: Dispatch<SetStateAction<string>>;
}

export function usePacketPageLoad(options: UsePacketPageLoadOptions) {
  return useCallback(
    async (cursor: number, filterOverride?: string, loadOptions?: PacketPageLoadOptions) => {
      return loadPacketPageState({
        cursor,
        pageSize: options.pageSize,
        filter: filterOverride ?? options.displayFilter,
        activeCapturePathRef: options.activeCapturePathRef,
        backendConnected: options.backendConnected,
        packetPageSeqRef: options.packetPageSeqRef,
        captureTaskScopeRef: options.captureTaskScopeRef,
        listPacketsPage: options.listPacketsPage,
        commitPacketPage: options.commitPacketPage,
        setIsPageLoading: options.setIsPageLoading,
        setIsFilterLoading: options.setIsFilterLoading,
        setPacketPageError: options.setPacketPageError,
        setBackendStatus: options.setBackendStatus,
        finishFilterLoading: loadOptions?.finishFilterLoading,
      });
    },
    [options],
  );
}
