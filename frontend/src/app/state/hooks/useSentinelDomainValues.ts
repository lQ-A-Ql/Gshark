import { useMemo } from "react";
import type { AnalysisContextValue } from "../contexts/AnalysisContext";
import type { BackendContextValue } from "../contexts/BackendContext";
import type { CaptureContextValue } from "../contexts/CaptureContext";
import type { FilterContextValue } from "../contexts/FilterContext";
import type { PacketContextValue } from "../contexts/PacketContext";
import type { StreamContextValue } from "../contexts/StreamContext";
import type { MediaAnalysisProgress, ThreatAnalysisProgress } from "./useAnalysisProgress";
import type { CaptureFileMeta } from "../captureOpenState";
import type { CapturePreloadDiagnostics } from "../capturePreloadDiagnostics";
import type { CaptureTransactionStatus, PreparedPacketStream } from "../sentinelTypes";
import type { StreamIds } from "../streamState";
import type { buildProtocolTree } from "../../core/engine";
import type {
  BinaryStream,
  DecryptionConfig,
  ExtractedObject,
  HttpStream,
  MCPConfig,
  MCPStatus,
  Packet,
  RecentCapture,
  StreamSwitchMetrics,
  ThreatHit,
  ToolRuntimeConfig,
  ToolRuntimeSnapshot,
} from "../../core/types";
import type { TSharkStatus } from "../../integrations/clients/toolRuntimeClient";
import type { ToolRuntimeProbeState, ToolRuntimeProbeTransport } from "../toolRuntimeProbeState";
import type { ToolRuntimeConfigExplicitFields } from "../toolRuntimeStorageConfig";

interface UseSentinelDomainValuesOptions {
  readonly backendConnected: boolean;
  readonly backendStatus: string;
  readonly tsharkStatus: TSharkStatus;
  readonly isTSharkChecking: boolean;
  readonly toolRuntimeCheckDegraded: boolean;
  readonly toolRuntimeProbeState: ToolRuntimeProbeState;
  readonly toolRuntimeProbeTransport: ToolRuntimeProbeTransport;
  readonly lastToolRuntimeProbeError: string;
  readonly setTSharkPath: (path: string) => Promise<void>;
  readonly toolRuntimeSnapshot: ToolRuntimeSnapshot | null;
  readonly isToolRuntimeLoading: boolean;
  readonly refreshToolRuntimeSnapshot: () => Promise<ToolRuntimeSnapshot | null>;
  readonly saveToolRuntimeConfig: (
    patch: Partial<ToolRuntimeConfig>,
    explicitFields?: ToolRuntimeConfigExplicitFields,
  ) => Promise<ToolRuntimeSnapshot>;
  readonly backendAuthToken: string;
  readonly isBackendAuthTokenLoading: boolean;
  readonly mcpStatus: MCPStatus | null;
  readonly refreshMCPStatus: () => Promise<MCPStatus | null>;
  readonly saveMCPConfig: (config: MCPConfig) => Promise<MCPStatus>;
  readonly decryptionConfig: DecryptionConfig;
  readonly updateDecryptionConfig: (patch: Partial<DecryptionConfig>) => void;
  readonly isPreloadingCapture: boolean;
  readonly preloadProcessed: number;
  readonly preloadTotal: number;
  readonly capturePreloadDiagnostics: CapturePreloadDiagnostics | null;
  readonly captureTransaction: CaptureTransactionStatus;
  readonly fileMeta: CaptureFileMeta;
  readonly captureRevision: number;
  readonly recentCaptures: RecentCapture[];
  readonly openCapture: (filePath?: string) => Promise<boolean>;
  readonly stopCapture: () => Promise<void>;
  readonly retryCapturePreloadConfirm: () => Promise<boolean>;
  readonly packets: Packet[];
  readonly totalPackets: number;
  readonly currentPage: number;
  readonly totalPages: number;
  readonly filteredPackets: Packet[];
  readonly hasMorePackets: boolean;
  readonly hasPrevPackets: boolean;
  readonly isPageLoading: boolean;
  readonly isFilterLoading: boolean;
  readonly packetPageError: string;
  readonly loadMorePackets: () => Promise<void>;
  readonly loadPrevPackets: () => Promise<void>;
  readonly jumpToPage: (page: number) => Promise<void>;
  readonly retryPacketPage: () => Promise<void>;
  readonly locatePacketById: (packetId: number, filterOverride?: string) => Promise<Packet | null>;
  readonly selectedPacket: Packet | null;
  readonly selectedPacketRawHex: string;
  readonly selectedPacketId: number | null;
  readonly selectPacket: (id: number) => void;
  readonly protocolTree: ReturnType<typeof buildProtocolTree>;
  readonly hexDump: string;
  readonly httpStream: HttpStream;
  readonly tcpStream: BinaryStream;
  readonly udpStream: BinaryStream;
  readonly streamIds: StreamIds;
  readonly setActiveStream: (protocol: "HTTP" | "TCP" | "UDP", streamId: number) => Promise<void>;
  readonly persistStreamPayloads: (
    protocol: "HTTP" | "TCP" | "UDP",
    streamId: number,
    patches: Array<{ index: number; body: string }>,
  ) => Promise<void>;
  readonly streamSwitchMetrics: StreamSwitchMetrics;
  readonly preparePacketStream: (
    packetId: number,
    preferredProtocol?: "HTTP" | "TCP" | "UDP",
    filterOverride?: string,
  ) => Promise<PreparedPacketStream>;
  readonly displayFilter: string;
  readonly setDisplayFilter: (value: string) => void;
  readonly applyFilter: (value?: string) => void;
  readonly clearFilter: () => void;
  readonly threatHits: ThreatHit[];
  readonly isThreatAnalysisLoading: boolean;
  readonly threatAnalysisProgress: ThreatAnalysisProgress;
  readonly extractedObjects: ExtractedObject[];
  readonly mediaAnalysisProgress: MediaAnalysisProgress;
}

export interface SentinelDomainValues {
  readonly backendValue: BackendContextValue;
  readonly captureValue: CaptureContextValue;
  readonly packetValue: PacketContextValue;
  readonly streamValue: StreamContextValue;
  readonly filterValue: FilterContextValue;
  readonly analysisValue: AnalysisContextValue;
}

export function useSentinelDomainValues({
  backendConnected,
  backendStatus,
  tsharkStatus,
  isTSharkChecking,
  toolRuntimeCheckDegraded,
  toolRuntimeProbeState,
  toolRuntimeProbeTransport,
  lastToolRuntimeProbeError,
  setTSharkPath,
  toolRuntimeSnapshot,
  isToolRuntimeLoading,
  refreshToolRuntimeSnapshot,
  saveToolRuntimeConfig,
  backendAuthToken,
  isBackendAuthTokenLoading,
  mcpStatus,
  refreshMCPStatus,
  saveMCPConfig,
  decryptionConfig,
  updateDecryptionConfig,
  isPreloadingCapture,
  preloadProcessed,
  preloadTotal,
  capturePreloadDiagnostics,
  captureTransaction,
  fileMeta,
  captureRevision,
  recentCaptures,
  openCapture,
  stopCapture,
  retryCapturePreloadConfirm,
  packets,
  totalPackets,
  currentPage,
  totalPages,
  filteredPackets,
  hasMorePackets,
  hasPrevPackets,
  isPageLoading,
  isFilterLoading,
  packetPageError,
  loadMorePackets,
  loadPrevPackets,
  jumpToPage,
  retryPacketPage,
  locatePacketById,
  selectedPacket,
  selectedPacketRawHex,
  selectedPacketId,
  selectPacket,
  protocolTree,
  hexDump,
  httpStream,
  tcpStream,
  udpStream,
  streamIds,
  setActiveStream,
  persistStreamPayloads,
  streamSwitchMetrics,
  preparePacketStream,
  displayFilter,
  setDisplayFilter,
  applyFilter,
  clearFilter,
  threatHits,
  isThreatAnalysisLoading,
  threatAnalysisProgress,
  extractedObjects,
  mediaAnalysisProgress,
}: UseSentinelDomainValuesOptions): SentinelDomainValues {
  const backendValue = useMemo(
    () => ({
      backendConnected,
      backendStatus,
      tsharkStatus,
      isTSharkChecking,
      toolRuntimeCheckDegraded,
      toolRuntimeProbeState,
      toolRuntimeProbeTransport,
      lastToolRuntimeProbeError,
      setTSharkPath,
      toolRuntimeSnapshot,
      isToolRuntimeLoading,
      refreshToolRuntimeSnapshot,
      saveToolRuntimeConfig,
      backendAuthToken,
      isBackendAuthTokenLoading,
      mcpStatus,
      refreshMCPStatus,
      saveMCPConfig,
      decryptionConfig,
      updateDecryptionConfig,
    }),
    [
      backendConnected,
      backendStatus,
      tsharkStatus,
      isTSharkChecking,
      toolRuntimeCheckDegraded,
      toolRuntimeProbeState,
      toolRuntimeProbeTransport,
      lastToolRuntimeProbeError,
      setTSharkPath,
      toolRuntimeSnapshot,
      isToolRuntimeLoading,
      refreshToolRuntimeSnapshot,
      saveToolRuntimeConfig,
      backendAuthToken,
      isBackendAuthTokenLoading,
      mcpStatus,
      refreshMCPStatus,
      saveMCPConfig,
      decryptionConfig,
      updateDecryptionConfig,
    ],
  );

  const captureValue = useMemo(
    () => ({
      isPreloadingCapture,
      preloadProcessed,
      preloadTotal,
      capturePreloadDiagnostics,
      captureTransaction,
      fileMeta,
      captureRevision,
      recentCaptures,
      openCapture,
      stopCapture,
      retryCapturePreloadConfirm,
    }),
    [
      isPreloadingCapture,
      preloadProcessed,
      preloadTotal,
      capturePreloadDiagnostics,
      captureTransaction,
      fileMeta,
      captureRevision,
      recentCaptures,
      openCapture,
      stopCapture,
      retryCapturePreloadConfirm,
    ],
  );

  const packetValue = useMemo(
    () => ({
      packets,
      totalPackets,
      currentPage,
      totalPages,
      filteredPackets,
      hasMorePackets,
      hasPrevPackets,
      isPageLoading,
      isFilterLoading,
      packetPageError,
      loadMorePackets,
      loadPrevPackets,
      jumpToPage,
      retryPacketPage,
      locatePacketById,
      selectedPacket,
      selectedPacketRawHex,
      selectedPacketId,
      selectPacket,
      protocolTree,
      hexDump,
    }),
    [
      packets,
      totalPackets,
      currentPage,
      totalPages,
      filteredPackets,
      hasMorePackets,
      hasPrevPackets,
      isPageLoading,
      isFilterLoading,
      packetPageError,
      loadMorePackets,
      loadPrevPackets,
      jumpToPage,
      retryPacketPage,
      locatePacketById,
      selectedPacket,
      selectedPacketRawHex,
      selectedPacketId,
      selectPacket,
      protocolTree,
      hexDump,
    ],
  );

  const streamValue = useMemo(
    () => ({
      httpStream,
      tcpStream,
      udpStream,
      streamIds,
      setActiveStream,
      persistStreamPayloads,
      streamSwitchMetrics,
      preparePacketStream,
    }),
    [
      httpStream,
      tcpStream,
      udpStream,
      streamIds,
      setActiveStream,
      persistStreamPayloads,
      streamSwitchMetrics,
      preparePacketStream,
    ],
  );

  const filterValue = useMemo(
    () => ({ displayFilter, setDisplayFilter, applyFilter, clearFilter }),
    [displayFilter, setDisplayFilter, applyFilter, clearFilter],
  );

  const analysisValue = useMemo(
    () => ({
      threatHits,
      isThreatAnalysisLoading,
      threatAnalysisProgress,
      extractedObjects,
      mediaAnalysisProgress,
    }),
    [threatHits, isThreatAnalysisLoading, threatAnalysisProgress, extractedObjects, mediaAnalysisProgress],
  );

  return { backendValue, captureValue, packetValue, streamValue, filterValue, analysisValue };
}
