import { useMemo } from "react";
import { useBackend } from "../contexts/BackendContext";
import { useCapture } from "../contexts/CaptureContext";
import { usePacket } from "../contexts/PacketContext";
import { useStream } from "../contexts/StreamContext";
import { useFilter } from "../contexts/FilterContext";
import { useAnalysis } from "../contexts/AnalysisContext";
import type { SentinelContextValue } from "../sentinelTypes";

export function useSentinelValue(): SentinelContextValue {
  const backend = useBackend();
  const capture = useCapture();
  const packet = usePacket();
  const stream = useStream();
  const filter = useFilter();
  const analysis = useAnalysis();

  return useMemo<SentinelContextValue>(
    () => ({
      ...backend,
      ...capture,
      ...packet,
      ...stream,
      ...filter,
      ...analysis,
    }),
    [backend, capture, packet, stream, filter, analysis],
  );
}
