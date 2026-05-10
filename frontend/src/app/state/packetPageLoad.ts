import type { PacketsPageResult } from "../integrations/clients/captureClient";
import { isAbortLikeError } from "../utils/asyncControl";
import type { CaptureTaskScope } from "../utils/captureTaskScope";
import { normalizePacketCursor } from "./packetPagination";
import { getPacketPageLoadErrorMessage } from "./packetPageStatus";

type Ref<T> = { current: T };

interface LoadPacketPageOptions {
  readonly cursor: number;
  readonly pageSize: number;
  readonly filter: string;
  readonly activeCapturePathRef: Ref<string>;
  readonly backendConnected: boolean;
  readonly packetPageSeqRef: Ref<number>;
  readonly captureTaskScopeRef: Ref<CaptureTaskScope>;
  readonly listPacketsPage: (
    cursor: number,
    limit: number,
    filter: string,
    signal: AbortSignal,
  ) => Promise<PacketsPageResult>;
  readonly commitPacketPage: (cursor: number, page: PacketsPageResult) => void;
  readonly setIsPageLoading: (value: boolean) => void;
  readonly setIsFilterLoading: (value: boolean) => void;
  readonly setPacketPageError: (value: string) => void;
  readonly setBackendStatus: (value: string) => void;
  readonly finishFilterLoading?: boolean;
}

export async function loadPacketPageState({
  cursor,
  pageSize,
  filter,
  activeCapturePathRef,
  backendConnected,
  packetPageSeqRef,
  captureTaskScopeRef,
  listPacketsPage,
  commitPacketPage,
  setIsPageLoading,
  setIsFilterLoading,
  setPacketPageError,
  setBackendStatus,
  finishFilterLoading = false,
}: LoadPacketPageOptions): Promise<PacketsPageResult | null> {
  if (!backendConnected || !activeCapturePathRef.current) {
    return null;
  }
  const requestSeq = ++packetPageSeqRef.current;
  const task = captureTaskScopeRef.current.beginTask("packet-page");
  setIsPageLoading(true);
  try {
    const safeCursor = normalizePacketCursor(cursor);
    const page = await listPacketsPage(safeCursor, pageSize, filter, task.signal);
    if (!task.isCurrent() || requestSeq !== packetPageSeqRef.current) {
      return null;
    }
    commitPacketPage(safeCursor, page);
    return page;
  } catch (error) {
    if (!task.isCurrent() || isAbortLikeError(error, task.signal)) {
      return null;
    }
    const message = getPacketPageLoadErrorMessage(error);
    setPacketPageError(message);
    setBackendStatus(message);
    return null;
  } finally {
    const isCurrent = task.isCurrent();
    task.finish();
    if (isCurrent && requestSeq === packetPageSeqRef.current) {
      setIsPageLoading(false);
      if (finishFilterLoading) {
        setIsFilterLoading(false);
      }
    }
  }
}
