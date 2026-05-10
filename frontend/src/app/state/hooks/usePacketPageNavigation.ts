import { useCallback, type Dispatch, type MutableRefObject, type SetStateAction } from "react";
import {
  jumpToPacketPage,
  loadNextPacketPage,
  loadPreviousPacketPage,
  retryPacketPageLoad,
} from "../packetPageNavigation";

interface UsePacketPageNavigationOptions {
  readonly displayFilter: string;
  readonly loadPacketPage: (cursor: number) => Promise<unknown>;
  readonly pageSize: number;
  readonly pageStartRef: MutableRefObject<number>;
  readonly setBackendStatus: Dispatch<SetStateAction<string>>;
  readonly totalPackets: number;
}

export function usePacketPageNavigation({
  displayFilter,
  loadPacketPage,
  pageSize,
  pageStartRef,
  setBackendStatus,
  totalPackets,
}: UsePacketPageNavigationOptions) {
  const loadMorePackets = useCallback(async () => {
    await loadNextPacketPage({ pageStartRef, pageSize, loadPacketPage });
  }, [loadPacketPage, pageSize, pageStartRef]);

  const loadPrevPackets = useCallback(async () => {
    await loadPreviousPacketPage({ pageStartRef, pageSize, loadPacketPage });
  }, [loadPacketPage, pageSize, pageStartRef]);

  const jumpToPage = useCallback(
    async (page: number) => {
      await jumpToPacketPage({ page, totalPackets, pageSize, loadPacketPage });
    },
    [loadPacketPage, pageSize, totalPackets],
  );

  const retryPacketPage = useCallback(async () => {
    await retryPacketPageLoad({ pageStartRef, displayFilter, loadPacketPage, setBackendStatus });
  }, [displayFilter, loadPacketPage, pageStartRef, setBackendStatus]);

  return { jumpToPage, loadMorePackets, loadPrevPackets, retryPacketPage };
}
