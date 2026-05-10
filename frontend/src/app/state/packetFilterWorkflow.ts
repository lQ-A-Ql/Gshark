import type { PacketsPageResult } from "../integrations/clients/captureClient";
import {
  PACKET_FILTER_POLL_INTERVAL_MS,
  PACKET_FILTER_POLL_TIMEOUT_MS,
  getPacketFilterDoneStatus,
  getPacketFilterPollingStatus,
  getPacketFilterWorkingStatus,
} from "./packetFilterStatus";

type Ref<T> = { current: T };

interface PacketFilterWorkflowOptions {
  readonly filter: string;
  readonly shouldRun: boolean;
  readonly pollUntilSettled: boolean;
  readonly filterSeqRef: Ref<number>;
  readonly loadPacketPage: (cursor: number, filterOverride?: string) => Promise<PacketsPageResult | null>;
  readonly resetPacketViewport: () => void;
  readonly setIsFilterLoading: (value: boolean) => void;
  readonly setPacketPageError: (value: string) => void;
  readonly setBackendStatus: (value: string) => void;
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly pollIntervalMs?: number;
  readonly pollTimeoutMs?: number;
}

export async function runPacketFilterWorkflow({
  filter,
  shouldRun,
  pollUntilSettled,
  filterSeqRef,
  loadPacketPage,
  resetPacketViewport,
  setIsFilterLoading,
  setPacketPageError,
  setBackendStatus,
  now = Date.now,
  sleep = (ms) => new Promise((resolve) => window.setTimeout(resolve, ms)),
  pollIntervalMs = PACKET_FILTER_POLL_INTERVAL_MS,
  pollTimeoutMs = PACKET_FILTER_POLL_TIMEOUT_MS,
}: PacketFilterWorkflowOptions): Promise<void> {
  if (!shouldRun) {
    return;
  }

  const filterSeq = ++filterSeqRef.current;
  setIsFilterLoading(true);
  setPacketPageError("");
  resetPacketViewport();
  setBackendStatus(getPacketFilterWorkingStatus(filter));

  let page = await loadPacketPage(0, filter);
  const deadline = now() + pollTimeoutMs;
  while (pollUntilSettled && filterSeq === filterSeqRef.current && page?.filtering && now() < deadline) {
    setBackendStatus(getPacketFilterPollingStatus(filter));
    await sleep(pollIntervalMs);
    page = await loadPacketPage(0, filter);
  }

  if (filterSeq !== filterSeqRef.current) {
    return;
  }

  setIsFilterLoading(false);
  if (page) {
    setBackendStatus(getPacketFilterDoneStatus(filter));
  }
}
