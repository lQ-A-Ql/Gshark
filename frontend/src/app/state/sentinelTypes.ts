import type { buildProtocolTree } from "../core/engine";
import type {
  BinaryStream,
  DecryptionConfig,
  ExtractedObject,
  HttpStream,
  Packet,
  RecentCapture,
  StreamSwitchMetrics,
  ThreatHit,
  ToolRuntimeConfig,
  ToolRuntimeSnapshot,
} from "../core/types";
import type { TSharkStatus } from "../integrations/wailsBridge";
import type { MediaAnalysisProgress, ThreatAnalysisProgress } from "./hooks/useAnalysisProgress";
import type { CaptureFileMeta } from "./captureOpenState";
import type { StreamIds } from "./streamState";

export interface PreparedPacketStream {
  packet: Packet | null;
  protocol: "HTTP" | "TCP" | "UDP" | null;
  streamId: number | null;
}

export interface SentinelContextValue {
  packets: Packet[];
  totalPackets: number;
  currentPage: number;
  totalPages: number;
  isPreloadingCapture: boolean;
  preloadProcessed: number;
  preloadTotal: number;
  filteredPackets: Packet[];
  hasMorePackets: boolean;
  hasPrevPackets: boolean;
  isPageLoading: boolean;
  isFilterLoading: boolean;
  loadMorePackets: () => Promise<void>;
  loadPrevPackets: () => Promise<void>;
  jumpToPage: (page: number) => Promise<void>;
  locatePacketById: (packetId: number, filterOverride?: string) => Promise<Packet | null>;
  selectedPacket: Packet | null;
  selectedPacketRawHex: string;
  selectedPacketId: number | null;
  displayFilter: string;
  setDisplayFilter: (value: string) => void;
  applyFilter: (value?: string) => void;
  clearFilter: () => void;
  selectPacket: (id: number) => void;
  protocolTree: ReturnType<typeof buildProtocolTree>;
  hexDump: string;
  threatHits: ThreatHit[];
  isThreatAnalysisLoading: boolean;
  threatAnalysisProgress: ThreatAnalysisProgress;
  extractedObjects: ExtractedObject[];
  httpStream: HttpStream;
  tcpStream: BinaryStream;
  udpStream: BinaryStream;
  streamIds: StreamIds;
  setActiveStream: (protocol: "HTTP" | "TCP" | "UDP", streamId: number) => Promise<void>;
  persistStreamPayloads: (
    protocol: "HTTP" | "TCP" | "UDP",
    streamId: number,
    patches: Array<{ index: number; body: string }>,
  ) => Promise<void>;
  streamSwitchMetrics: StreamSwitchMetrics;
  decryptionConfig: DecryptionConfig;
  updateDecryptionConfig: (patch: Partial<DecryptionConfig>) => void;
  fileMeta: CaptureFileMeta;
  captureRevision: number;
  recentCaptures: RecentCapture[];
  openCapture: (filePath?: string) => Promise<void>;
  stopCapture: () => Promise<void>;
  preparePacketStream: (
    packetId: number,
    preferredProtocol?: "HTTP" | "TCP" | "UDP",
    filterOverride?: string,
  ) => Promise<PreparedPacketStream>;
  backendConnected: boolean;
  backendStatus: string;
  mediaAnalysisProgress: MediaAnalysisProgress;
  tsharkStatus: TSharkStatus;
  isTSharkChecking: boolean;
  toolRuntimeCheckDegraded: boolean;
  setTSharkPath: (path: string) => Promise<void>;
  toolRuntimeSnapshot: ToolRuntimeSnapshot | null;
  isToolRuntimeLoading: boolean;
  refreshToolRuntimeSnapshot: () => Promise<ToolRuntimeSnapshot | null>;
  saveToolRuntimeConfig: (patch: Partial<ToolRuntimeConfig>) => Promise<ToolRuntimeSnapshot>;
}
