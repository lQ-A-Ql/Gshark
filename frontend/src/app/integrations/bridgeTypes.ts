import type {
  AppUpdateStatus,
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
  MediaAnalysis,
  MediaTranscription,
  MiscModuleManifest,
  MiscModuleImportResult,
  MiscModuleRunResult,
  MySQLAnalysis,
  Packet,
  PluginItem,
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
  USBAnalysis,
  VehicleAnalysis,
  WinRMDecryptRequest,
  WinRMDecryptResult,
  SMB3SessionCandidate,
  SMB3RandomSessionKeyRequest,
  SMB3RandomSessionKeyResult,
  UnifiedEvidenceRecord,
} from "../core/types";
import type { PluginSource } from "./mappers/pluginSourceMapper";
import type { EventHandlers } from "./clients/eventClient";
import type { HuntingRuntimeConfig } from "./clients/huntingClient";
import type { CaptureStatus, OpenFileResult, PacketLocateResult, PacketsPageResult } from "./clients/captureClient";
import type { FFmpegStatus, TSharkStatus } from "./clients/toolRuntimeClient";

export type { CaptureStatus, OpenFileResult } from "./clients/captureClient";
export type { PluginSource } from "./mappers/pluginSourceMapper";
export type { FFmpegStatus, TSharkStatus } from "./clients/toolRuntimeClient";
export type { HuntingRuntimeConfig } from "./clients/huntingClient";
export type { EventHandlers, EventType } from "./clients/eventClient";

export interface RuntimeClient {
  isAvailable(): Promise<boolean>;
  getDesktopBackendStatus(): Promise<string>;
  checkAppUpdate(): Promise<AppUpdateStatus>;
  installAppUpdate(): Promise<void>;
  checkTShark(): Promise<TSharkStatus>;
  checkFFmpeg(): Promise<FFmpegStatus>;
  checkSpeechToText(): Promise<SpeechToTextStatus>;
  getToolRuntimeSnapshot(): Promise<ToolRuntimeSnapshot>;
  updateToolRuntimeConfig(config: ToolRuntimeConfig): Promise<ToolRuntimeSnapshot>;
  setTSharkPath(path: string): Promise<TSharkStatus>;
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
  getHuntingRuntimeConfig(): Promise<HuntingRuntimeConfig>;
  updateHuntingRuntimeConfig(config: HuntingRuntimeConfig): Promise<HuntingRuntimeConfig>;
}

export interface ObjectClient {
  listObjects(signal?: AbortSignal): Promise<ExtractedObject[]>;
  downloadObjectsZip(ids: number[]): Promise<void>;
}

export interface StreamClient {
  getHttpStream(streamId: number, signal?: AbortSignal): Promise<HttpStream>;
  getRawStream(protocol: "TCP" | "UDP", streamId: number, signal?: AbortSignal): Promise<BinaryStream>;
  getRawStreamPage(protocol: "TCP" | "UDP", streamId: number, cursor: number, limit: number, signal?: AbortSignal): Promise<BinaryStream>;
  decodeStreamPayload(decoder: string, payload: string, options?: Record<string, unknown>, signal?: AbortSignal): Promise<StreamDecodeResult>;
  inspectStreamPayload(payload: string, signal?: AbortSignal): Promise<StreamPayloadInspection>;
  listStreamPayloadSources(signal?: AbortSignal, limit?: number): Promise<StreamPayloadSource[]>;
  updateStreamPayloads(protocol: "HTTP" | "TCP" | "UDP", streamId: number, patches: Array<{ index: number; body: string }>, signal?: AbortSignal): Promise<HttpStream | BinaryStream>;
  listStreamIds(protocol: "HTTP" | "TCP" | "UDP", signal?: AbortSignal): Promise<number[]>;
}

export interface AnalysisClient {
  getGlobalTrafficStats(signal?: AbortSignal): Promise<GlobalTrafficStats>;
  getIndustrialAnalysis(signal?: AbortSignal): Promise<IndustrialAnalysis>;
  getVehicleAnalysis(signal?: AbortSignal): Promise<VehicleAnalysis>;
  getUSBAnalysis(signal?: AbortSignal): Promise<USBAnalysis>;
  getC2SampleAnalysis(signal?: AbortSignal): Promise<C2SampleAnalysis>;
  decryptC2Traffic(req: C2DecryptRequest, signal?: AbortSignal): Promise<C2DecryptResult>;
  getAPTAnalysis(signal?: AbortSignal): Promise<APTAnalysis>;
  getHTTPLoginAnalysis(signal?: AbortSignal): Promise<HTTPLoginAnalysis>;
  getSMTPAnalysis(signal?: AbortSignal): Promise<SMTPAnalysis>;
  getMySQLAnalysis(signal?: AbortSignal): Promise<MySQLAnalysis>;
  getShiroRememberMeAnalysis(candidateKeys?: string[], signal?: AbortSignal): Promise<ShiroRememberMeAnalysis>;
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

export interface PluginClient {
  listPlugins(): Promise<PluginItem[]>;
  getPluginSource(id: string): Promise<PluginSource>;
  savePluginSource(source: PluginSource): Promise<PluginSource>;
  addPlugin(plugin: PluginItem): Promise<PluginItem>;
  deletePlugin(id: string): Promise<void>;
  togglePlugin(id: string): Promise<PluginItem>;
  setPluginsEnabled(ids: string[], enabled: boolean): Promise<PluginItem[]>;
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

export interface MiscModuleClient {
  listMiscModules(): Promise<MiscModuleManifest[]>;
  importMiscModulePackage(file: File): Promise<MiscModuleImportResult>;
  deleteMiscModule(id: string): Promise<void>;
  runMiscModule(id: string, values: Record<string, string>): Promise<MiscModuleRunResult>;
}

export interface BackendBridge
  extends RuntimeClient,
    CaptureClient,
    PacketClient,
    HuntingClient,
    ObjectClient,
    StreamClient,
    AnalysisClient,
    EvidenceClient,
    MediaClient,
    VehicleDBCClient,
    PluginClient,
    SecurityMaterialClient,
    MiscModuleClient {}

export interface DesktopTransportBinding {
  BackendStatus?: () => Promise<string>;
  GetBackendAuthToken?: () => Promise<string | null | undefined>;
  CheckAppUpdate?: () => Promise<AppUpdateStatus | null | undefined>;
  InstallAppUpdate?: () => Promise<void>;
  OpenDBCDialog?: () => Promise<OpenFileResult | null | undefined>;
  OpenCaptureDialog?: () => Promise<OpenFileResult | null | undefined>;
  IsBackendReady?: () => Promise<boolean>;
  GetToolRuntimeSnapshot?: () => Promise<unknown>;
  UpdateToolRuntimeConfig?: (config: unknown) => Promise<unknown>;
  SetTSharkPath?: (path: string) => Promise<unknown>;
  StartCapture?: (filePath: string, filter: string) => Promise<void>;
  StopCapture?: () => Promise<void>;
  PrepareCaptureReplacement?: () => Promise<void>;
  CloseCapture?: () => Promise<void>;
  GetCaptureStatus?: () => Promise<unknown>;
  GetTLSConfig?: () => Promise<unknown>;
  UpdateTLSConfig?: (cfg: unknown) => Promise<void>;
}
