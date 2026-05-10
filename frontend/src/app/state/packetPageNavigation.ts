import { getNextPacketCursor, getPacketPageCursor, getPrevPacketCursor } from "./packetPagination";
import { getPacketPageRetryStatus } from "./packetPageStatus";

type Ref<T> = { current: T };
type LoadPacketPage = (cursor: number) => Promise<unknown>;

interface PacketPageNavigationOptions {
  readonly pageStartRef: Ref<number>;
  readonly pageSize: number;
  readonly loadPacketPage: LoadPacketPage;
}

export async function loadNextPacketPage({
  pageStartRef,
  pageSize,
  loadPacketPage,
}: PacketPageNavigationOptions): Promise<void> {
  await loadPacketPage(getNextPacketCursor(pageStartRef.current, pageSize));
}

export async function loadPreviousPacketPage({
  pageStartRef,
  pageSize,
  loadPacketPage,
}: PacketPageNavigationOptions): Promise<void> {
  await loadPacketPage(getPrevPacketCursor(pageStartRef.current, pageSize));
}

interface JumpToPacketPageOptions {
  readonly page: number;
  readonly totalPackets: number;
  readonly pageSize: number;
  readonly loadPacketPage: LoadPacketPage;
}

export async function jumpToPacketPage({
  page,
  totalPackets,
  pageSize,
  loadPacketPage,
}: JumpToPacketPageOptions): Promise<void> {
  await loadPacketPage(getPacketPageCursor(page, totalPackets, pageSize));
}

interface RetryPacketPageOptions {
  readonly pageStartRef: Ref<number>;
  readonly displayFilter: string;
  readonly loadPacketPage: LoadPacketPage;
  readonly setBackendStatus: (value: string) => void;
}

export async function retryPacketPageLoad({
  pageStartRef,
  displayFilter,
  loadPacketPage,
  setBackendStatus,
}: RetryPacketPageOptions): Promise<void> {
  setBackendStatus(getPacketPageRetryStatus(displayFilter));
  await loadPacketPage(pageStartRef.current);
}
