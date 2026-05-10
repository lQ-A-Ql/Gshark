import type { Packet } from "../core/types";
import type { PacketLocateResult, PacketsPageResult } from "../integrations/clients/captureClient";
import { isAbortLikeError } from "../utils/asyncControl";
import type { CaptureTaskScope } from "../utils/captureTaskScope";
import { normalizePacketId } from "./packetPagination";

type Ref<T> = { current: T };

interface PacketLocateWorkflowOptions {
  readonly packetId: number;
  readonly pageSize: number;
  readonly filterOverride?: string;
  readonly displayFilter: string;
  readonly activeCapturePathRef: Ref<string>;
  readonly captureTaskScopeRef: Ref<CaptureTaskScope>;
  readonly locatePacketPage: (
    packetId: number,
    limit: number,
    filter: string,
    signal: AbortSignal,
  ) => Promise<PacketLocateResult>;
  readonly loadPacketPage: (cursor: number, filterOverride?: string) => Promise<PacketsPageResult | null>;
  readonly setDisplayFilter: (value: string) => void;
  readonly setSelectedPacketId: (value: number) => void;
  readonly setBackendStatus: (value: string) => void;
}

export async function locatePacketByIdWorkflow({
  packetId,
  pageSize,
  filterOverride,
  displayFilter,
  activeCapturePathRef,
  captureTaskScopeRef,
  locatePacketPage,
  loadPacketPage,
  setDisplayFilter,
  setSelectedPacketId,
  setBackendStatus,
}: PacketLocateWorkflowOptions): Promise<Packet | null> {
  const normalized = normalizePacketId(packetId);
  if (normalized <= 0 || !activeCapturePathRef.current) {
    return null;
  }

  const task = captureTaskScopeRef.current.beginTask("packet-locate");
  try {
    const effectiveFilter = filterOverride ?? displayFilter;
    const located = await locatePacketPage(normalized, pageSize, effectiveFilter, task.signal);
    if (!task.isCurrent()) {
      return null;
    }
    if (!located.found) {
      setBackendStatus(`未找到数据包 #${normalized}`);
      return null;
    }
    if (filterOverride !== undefined) {
      setDisplayFilter(effectiveFilter);
    }
    const page = await loadPacketPage(located.cursor, effectiveFilter);
    if (!page || !task.isCurrent()) {
      return null;
    }
    setSelectedPacketId(normalized);
    return page.items.find((item) => item.id === normalized) ?? null;
  } catch (error) {
    if (!task.isCurrent() || isAbortLikeError(error, task.signal)) {
      return null;
    }
    setBackendStatus(error instanceof Error ? error.message : "定位数据包失败");
    return null;
  } finally {
    task.finish();
  }
}
