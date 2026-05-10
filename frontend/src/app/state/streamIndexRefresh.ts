import { isAbortLikeError } from "../utils/asyncControl";
import type { CaptureTaskScope } from "../utils/captureTaskScope";
import type { StreamIds } from "./streamState";

type Ref<T> = { current: T };
type StreamProtocol = "HTTP" | "TCP" | "UDP";

interface RefreshStreamIndexOptions {
  readonly backendConnected: boolean;
  readonly activeCapturePathRef: Ref<string>;
  readonly captureTaskScopeRef: Ref<CaptureTaskScope>;
  readonly listStreamIds: (protocol: StreamProtocol, signal: AbortSignal) => Promise<number[]>;
  readonly setStreamIds: (value: StreamIds) => void;
  readonly setBackendStatus: (value: string) => void;
}

export async function refreshStreamIndexState({
  backendConnected,
  activeCapturePathRef,
  captureTaskScopeRef,
  listStreamIds,
  setStreamIds,
  setBackendStatus,
}: RefreshStreamIndexOptions): Promise<void> {
  if (!backendConnected) return;
  const capturePath = activeCapturePathRef.current;
  if (!capturePath) return;

  const task = captureTaskScopeRef.current.beginTask("stream-index");
  try {
    const [httpIds, tcpIds, udpIds] = await Promise.all([
      listStreamIds("HTTP", task.signal),
      listStreamIds("TCP", task.signal),
      listStreamIds("UDP", task.signal),
    ]);
    if (!task.isCurrent() || activeCapturePathRef.current !== capturePath) {
      return;
    }
    setStreamIds({ http: httpIds, tcp: tcpIds, udp: udpIds });
  } catch (error) {
    if (!task.isCurrent() || isAbortLikeError(error, task.signal)) {
      return;
    }
    setBackendStatus("流索引刷新失败");
  } finally {
    task.finish();
  }
}
