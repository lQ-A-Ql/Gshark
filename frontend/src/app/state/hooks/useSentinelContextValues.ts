import { useMemo } from "react";
import type { SentinelContextValue } from "../sentinelTypes";
import type { AnalysisContextValue } from "../contexts/AnalysisContext";
import type { BackendContextValue } from "../contexts/BackendContext";
import type { CaptureContextValue } from "../contexts/CaptureContext";
import type { FilterContextValue } from "../contexts/FilterContext";
import type { PacketContextValue } from "../contexts/PacketContext";
import type { StreamContextValue } from "../contexts/StreamContext";

export interface SentinelProviderContextValues {
  readonly value: SentinelContextValue;
  readonly backendValue: BackendContextValue;
  readonly captureValue: CaptureContextValue;
  readonly packetValue: PacketContextValue;
  readonly streamValue: StreamContextValue;
  readonly filterValue: FilterContextValue;
  readonly analysisValue: AnalysisContextValue;
}

export function useSentinelContextValues({
  backendValue,
  captureValue,
  packetValue,
  streamValue,
  filterValue,
  analysisValue,
}: Omit<SentinelProviderContextValues, "value">): SentinelProviderContextValues {
  const value = useMemo<SentinelContextValue>(
    () => ({ ...backendValue, ...captureValue, ...packetValue, ...streamValue, ...filterValue, ...analysisValue }),
    [backendValue, captureValue, packetValue, streamValue, filterValue, analysisValue],
  );

  return { value, backendValue, captureValue, packetValue, streamValue, filterValue, analysisValue };
}
