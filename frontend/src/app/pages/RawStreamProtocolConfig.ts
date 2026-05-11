import { TCP_RAW_STREAM_TONE, UDP_RAW_STREAM_TONE, type RawStreamTone } from "./RawStreamSections";
import type { RawStreamProtocol } from "./useRawStreamRouteSelection";

export interface RawStreamProtocolConfig {
  enableScrollLoad: boolean;
  loadingText: string;
  selectedPanelClass: string;
  tone: RawStreamTone;
}

export function getRawStreamProtocolConfig(protocol: RawStreamProtocol): RawStreamProtocolConfig {
  if (protocol === "TCP") {
    return {
      enableScrollLoad: true,
      loadingText: "继续下滚可加载更多",
      selectedPanelClass: "min-h-0 min-w-0 space-y-4 overflow-auto pb-4 pr-1",
      tone: TCP_RAW_STREAM_TONE,
    };
  }

  return {
    enableScrollLoad: false,
    loadingText: "",
    selectedPanelClass: "space-y-4 xl:sticky xl:top-0",
    tone: UDP_RAW_STREAM_TONE,
  };
}
