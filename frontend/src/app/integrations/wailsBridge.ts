import { createBridge } from "./bridgeFactory";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";

export { isLikelyVShellLowInfoControlRecord, normalizeC2DecryptResultForDisplay } from "./mappers/c2DecryptDisplayMapper";
export type {
  BackendBridge,
  DesktopTransportBinding,
  EventHandlers,
  EventType,
  FFmpegStatus,
  HuntingRuntimeConfig,
  OpenFileResult,
  PluginSource,
  TSharkStatus,
} from "./bridgeTypes";

function getDesktopAppBinding(): DesktopTransportBinding | undefined {
  if (typeof window === "undefined") {
    return undefined;
  }
  return (window as any)?.go?.main?.DesktopApp as DesktopTransportBinding | undefined;
}

export const bridge: BackendBridge = createBridge({
  getDesktopAppBinding,
});
