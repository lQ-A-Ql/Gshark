import type {
  AppUpdateStatus,
  BruteforceAnalysis,
  C2DecryptRequest,
  C2DecryptResult,
  APTAnalysis,
  BinaryStream,
  C2SampleAnalysis,
  DBCProfile,
  DecryptionConfig,
  ExtractedObject,
  GlobalTrafficStats,
  HTTPLoginAnalysis,
  HttpStream,
  IndustrialAnalysis,
  MCPConfig,
  MCPStatus,
  MediaAnalysis,
  MediaTranscription,
  MySQLAnalysis,
  Packet,
  ShiroRememberMeAnalysis,
  SMTPAnalysis,
  SpeechBatchTaskStatus,
  SpeechToTextStatus,
  ToolRuntimeConfig,
  ToolRuntimeSnapshot,
  StreamDecodeResult,
  StreamPayloadInspection,
  StreamPayloadSource,
  ThreatHit,
  NTLMSessionMaterial,
  UDPTunnelAnalysis,
  USBAnalysis,
  USBHIDSourceMode,
  VehicleAnalysis,
  WinRMDecryptRequest,
  WinRMDecryptResult,
  SMB3SessionCandidate,
  SMB3RandomSessionKeyRequest,
  SMB3RandomSessionKeyResult,
  UnifiedEvidenceRecord,
} from "../core/types";
import type { CaptureStatus, OpenFileResult, PacketLocateResult, PacketsPageResult } from "./clients/captureClient";
import type { EventHandlers } from "./clients/eventClient";
import type { FFmpegStatus, TSharkStatus } from "./clients/toolRuntimeClient";
import type { HuntingRuntimeConfig } from "./clients/huntingClient";
import type { MiscModuleClient } from "./miscModuleClientTypes";
import type { PlaybookClient } from "./clients/playbookClient";
import type { RuleClient } from "./clients/ruleClient";
export type { DesktopTransportBinding } from "./desktopTransportBinding";
export type { CaptureStatus, OpenFileResult } from "./clients/captureClient";
export type { FFmpegStatus, TSharkStatus } from "./clients/toolRuntimeClient";
export type { HuntingRuntimeConfig } from "./clients/huntingClient";
export type { MiscModuleClient } from "./miscModuleClientTypes";
export type { PlaybookClient } from "./clients/playbookClient";
export type { RuleClient } from "./clients/ruleClient";
export type { EventHandlers, EventType } from "./clients/eventClient";
export interface RuntimeClient {
  isAvailable(): Promise<boolean>;
  getDesktopBackendStatus(): Promise<string>;
  checkAppUpdate(): Promise<AppUpdateStatus>;
  installAppUpdate(): Promise<void>;
  checkTShark(): Promise<TSharkStatus>;
  checkFFmpeg(): Promise<FFmpegStatus>;
  checkSpeechToText(): Promise<SpeechToTextStatus>;
  getToolRuntimeSnapshot(signal?: AbortSignal, mode?: "fast" | "full"): Promise<ToolRuntimeSnapshot>;
  updateToolRuntimeConfig(
    config: ToolRuntimeConfig,
    signal?: AbortSignal,
    mode?: "fast" | "full",
  ): Promise<ToolRuntimeSnapshot>;
  setTSharkPath(path: string): Promise<TSharkStatus>;
  getMCPStatus(signal?: AbortSignal): Promise<MCPStatus>;
  updateMCPConfig(config: MCPConfig, signal?: AbortSignal): Promise<MCPStatus>;
  subscribeEvents(handlers: EventHandlers): () => void;
}

export interface CaptureClient {
  openPcapFile(): Promise<OpenFileResult>;
  startStreamingPackets(filePath: string, filter: string, signal?: AbortSignal): Promise<void>;
  stopStreamingPackets(): Promise<void>;
  prepareCaptureReplacement(): Promise<void>;
  closeCapture(): Promise<void>;
  getCaptureStatus(signal?: AbortSignal): Promise<CaptureStatus>;
}

export interface PacketClient {
  listPackets(): Promise<Packet[]>;
  listPacketsPage(cursor: number, limit: number, filter?: string, signal?: AbortSignal): Promise<PacketsPageResult>;
  locatePacketPage(packetId: number, limit: number, filter?: string, signal?: AbortSignal): Promise<PacketLocateResult>;
  getPacket(packetId: number, signal?: AbortSignal): Promise<Packet>;
  getPacketRawHex(packetId: number, signal?: AbortSignal): Promise<string>;
  getPacketLayers(packetId: number, signal?: AbortSignal): Promise<Record<string, unknown> | null>;
}

export interface HuntingClient {
  listThreatHits(prefixes?: string[], signal?: AbortSignal): Promise<ThreatHit[]>;
  getHuntingRuntimeConfig(signal?: AbortSignal): Promise<HuntingRuntimeConfig>;
  updateHuntingRuntimeConfig(config: HuntingRuntimeConfig): Promise<HuntingRuntimeConfig>;
}

export interface ObjectClient {
  listObjects(signal?: AbortSignal): Promise<ExtractedObject[]>;
  downloadObjectsZip(ids: number[]): Promise<void>;
}

export interface StreamClient {
  getHttpStream(streamId: number, signal?: AbortSignal): Promise<HttpStream>;
  getRawStream(protocol: "TCP" | "UDP", streamId: number, signal?: AbortSignal): Promise<BinaryStream>;
  getRawStreamPage(
    protocol: "TCP" | "UDP",
    streamId: number,
    cursor: number,
    limit: number,
    signal?: AbortSignal,
  ): Promise<BinaryStream>;
  decodeStreamPayload(
    decoder: string,
    payload: string,
    options?: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<StreamDecodeResult>;
  inspectStreamPayload(payload: string, signal?: AbortSignal): Promise<StreamPayloadInspection>;
  listStreamPayloadSources(signal?: AbortSignal, limit?: number): Promise<StreamPayloadSource[]>;
  updateStreamPayloads(
    protocol: "HTTP" | "TCP" | "UDP",
    streamId: number,
    patches: Array<{ index: number; body: string }>,
    signal?: AbortSignal,
  ): Promise<HttpStream | BinaryStream>;
  listStreamIds(protocol: "HTTP" | "TCP" | "UDP", signal?: AbortSignal): Promise<number[]>;
}

export interface AnalysisClient {
  getGlobalTrafficStats(signal?: AbortSignal): Promise<GlobalTrafficStats>;
  getIndustrialAnalysis(signal?: AbortSignal, options?: { source?: "user" | "warmup" }): Promise<IndustrialAnalysis>;
  getVehicleAnalysis(signal?: AbortSignal, options?: { source?: "user" | "warmup" }): Promise<VehicleAnalysis>;
  getUSBAnalysis(
    signal?: AbortSignal,
    hidSource?: USBHIDSourceMode,
    hidEventLimit?: number,
    options?: { source?: "user" | "warmup" },
  ): Promise<USBAnalysis>;
  getC2SampleAnalysis(signal?: AbortSignal, options?: { source?: "user" | "warmup" }): Promise<C2SampleAnalysis>;
  decryptC2Traffic(req: C2DecryptRequest, signal?: AbortSignal): Promise<C2DecryptResult>;
  getAPTAnalysis(signal?: AbortSignal): Promise<APTAnalysis>;
  getHTTPLoginAnalysis(signal?: AbortSignal): Promise<HTTPLoginAnalysis>;
  getSMTPAnalysis(signal?: AbortSignal): Promise<SMTPAnalysis>;
  getMySQLAnalysis(signal?: AbortSignal): Promise<MySQLAnalysis>;
  getShiroRememberMeAnalysis(candidateKeys?: string[], signal?: AbortSignal): Promise<ShiroRememberMeAnalysis>;
  getUDPTunnelAnalysis(signal?: AbortSignal): Promise<UDPTunnelAnalysis>;
  getBruteforceAnalysis(signal?: AbortSignal): Promise<BruteforceAnalysis>;
}

export interface EvidenceClient {
  getEvidence(signal?: AbortSignal): Promise<UnifiedEvidenceRecord[]>;
  getEvidenceWithFilter(modules?: string[], signal?: AbortSignal): Promise<UnifiedEvidenceRecord[]>;
}

export interface MediaClient {
  getMediaAnalysis(forceRefresh?: boolean, signal?: AbortSignal): Promise<MediaAnalysis>;
  transcribeMediaArtifact(token: string, force?: boolean): Promise<MediaTranscription>;
  startMediaBatchTranscription(force?: boolean): Promise<SpeechBatchTaskStatus>;
  getMediaBatchTranscriptionStatus(): Promise<SpeechBatchTaskStatus>;
  cancelMediaBatchTranscription(): Promise<SpeechBatchTaskStatus>;
  exportMediaBatchTranscription(format: "txt" | "json"): Promise<void>;
  downloadMediaArtifact(token: string, filename: string): Promise<void>;
  getMediaPlaybackBlob(token: string): Promise<Blob>;
}

export interface VehicleDBCClient {
  listVehicleDBCProfiles(): Promise<DBCProfile[]>;
  addVehicleDBC(path: string): Promise<DBCProfile[]>;
  removeVehicleDBC(path: string): Promise<DBCProfile[]>;
  openDBCFile(): Promise<OpenFileResult>;
}

export interface SecurityMaterialClient {
  getTLSConfig(): Promise<DecryptionConfig | null>;
  updateTLSConfig(cfg: DecryptionConfig): Promise<void>;
  runWinRMDecrypt(req: WinRMDecryptRequest): Promise<WinRMDecryptResult>;
  getWinRMDecryptResultText(resultId: string): Promise<string>;
  exportWinRMDecryptResult(resultId: string, filename: string): Promise<void>;
  listSMB3SessionCandidates(): Promise<SMB3SessionCandidate[]>;
  generateSMB3RandomSessionKey(req: SMB3RandomSessionKeyRequest): Promise<SMB3RandomSessionKeyResult>;
  listNTLMSessionMaterials(): Promise<NTLMSessionMaterial[]>;
}

export interface BackendBridge
  extends
    RuntimeClient,
    CaptureClient,
    PacketClient,
    HuntingClient,
    ObjectClient,
    StreamClient,
    AnalysisClient,
    EvidenceClient,
    MediaClient,
    VehicleDBCClient,
    SecurityMaterialClient,
    MiscModuleClient,
    PlaybookClient,
    RuleClient {}

export interface BackendClients {
  runtime: RuntimeClient;
  capture: CaptureClient;
  packet: PacketClient;
  hunting: HuntingClient;
  object: ObjectClient;
  stream: StreamClient;
  analysis: AnalysisClient;
  evidence: EvidenceClient;
  media: MediaClient;
  vehicleDBC: VehicleDBCClient;
  securityMaterial: SecurityMaterialClient;
  miscModule: MiscModuleClient;
  playbook: PlaybookClient;
  rules: RuleClient;
}
