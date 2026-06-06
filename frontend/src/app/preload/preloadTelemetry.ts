import type { PreloadCost, PreloadKind, PreloadTrigger } from "./preloadBudget";

export type PreloadTelemetryEventName =
  | "preload.started"
  | "preload.skipped"
  | "preload.reused"
  | "preload.aborted"
  | "preload.fulfilled"
  | "preload.failed"
  | "preload.promoted";

export type PreloadTelemetry = {
  event: PreloadTelemetryEventName;
  targetId: string;
  kind: PreloadKind;
  cost: PreloadCost;
  trigger: PreloadTrigger;
  captureRevision?: number;
  durationMs?: number;
  reason?: string;
};

type PreloadTelemetrySink = (event: PreloadTelemetry) => void;

let telemetrySink: PreloadTelemetrySink | undefined;

export function recordPreloadEvent(event: PreloadTelemetry) {
  try {
    telemetrySink?.(event);
  } catch {
    // Telemetry must never affect navigation or analysis flows.
  }
}

export function setPreloadTelemetrySinkForTest(sink: PreloadTelemetrySink | undefined) {
  telemetrySink = sink;
}
