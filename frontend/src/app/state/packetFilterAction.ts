import type { PacketsPageResult } from "../integrations/clients/captureClient";
import { runPacketFilterWorkflow } from "./packetFilterWorkflow";

type Ref<T> = { current: T };

interface PacketFilterActionOptions {
  readonly filter: string;
  readonly syncDisplayFilter: boolean;
  readonly pollUntilSettled: boolean;
  readonly shouldRun: boolean;
  readonly filterSeqRef: Ref<number>;
  readonly loadPacketPage: (cursor: number, filterOverride?: string) => Promise<PacketsPageResult | null>;
  readonly resetPacketViewport: () => void;
  readonly setDisplayFilter: (value: string) => void;
  readonly setIsFilterLoading: (value: boolean) => void;
  readonly setPacketPageError: (value: string) => void;
  readonly setBackendStatus: (value: string) => void;
}

export async function runPacketFilterAction({
  filter,
  syncDisplayFilter,
  pollUntilSettled,
  shouldRun,
  filterSeqRef,
  loadPacketPage,
  resetPacketViewport,
  setDisplayFilter,
  setIsFilterLoading,
  setPacketPageError,
  setBackendStatus,
}: PacketFilterActionOptions): Promise<void> {
  if (syncDisplayFilter) {
    setDisplayFilter(filter);
  }

  await runPacketFilterWorkflow({
    filter,
    shouldRun,
    pollUntilSettled,
    filterSeqRef,
    loadPacketPage,
    resetPacketViewport,
    setIsFilterLoading,
    setPacketPageError,
    setBackendStatus,
  });
}
