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
} from "../core/types";
import type { UnifiedEvidenceRecord } from "../features/evidence/evidenceSchema";
import { createAnalysisClient } from "./clients/analysisClient";
import { createC2DecryptClient } from "./clients/c2DecryptClient";
import {
  createCaptureClient,
  type OpenFileResult,
  type PacketLocateResult,
  type PacketsPageResult,
} from "./clients/captureClient";
import { createDesktopClient, type DesktopAppBinding } from "./clients/desktopClient";
import { createEventClient, type EventHandlers } from "./clients/eventClient";
import { createHuntingClient, type HuntingRuntimeConfig } from "./clients/huntingClient";
import { createMediaClient } from "./clients/mediaClient";
import { createObjectClient } from "./clients/objectClient";
import { createPluginClient } from "./clients/pluginClient";
import { createStreamClient } from "./clients/streamClient";
import { createToolClient } from "./clients/toolClient";
import { createToolRuntimeClient, type FFmpegStatus, type TSharkStatus } from "./clients/toolRuntimeClient";
import type { PluginSource } from "./mappers/pluginSourceMapper";

export { isLikelyVShellLowInfoControlRecord, normalizeC2DecryptResultForDisplay } from "./mappers/c2DecryptDisplayMapper";
export type { PluginSource } from "./mappers/pluginSourceMapper";
export type { FFmpegStatus, TSharkStatus } from "./clients/toolRuntimeClient";
export type { HuntingRuntimeConfig } from "./clients/huntingClient";
export type { EventHandlers, EventType } from "./clients/eventClient";

const API_BASE = (import.meta.env.VITE_BACKEND_URL as string | undefined) ?? "http://127.0.0.1:17891";

export type { OpenFileResult } from "./clients/captureClient";

interface AppBridgeBinding extends DesktopAppBinding {
  GetBackendAuthToken?: () => Promise<string | null | undefined>;
  OpenCaptureDialog?: () => Promise<OpenFileResult | null | undefined>;
}

export interface BackendBridge {
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
  openPcapFile(): Promise<OpenFileResult>;
  startStreamingPackets(filePath: string, filter: string, signal?: AbortSignal): Promise<void>;
  stopStreamingPackets(): Promise<void>;
  prepareCaptureReplacement(): Promise<void>;
  closeCapture(): Promise<void>;
  listPackets(): Promise<Packet[]>;
  listPacketsPage(cursor: number, limit: number, filter?: string, signal?: AbortSignal): Promise<PacketsPageResult>;
  locatePacketPage(packetId: number, limit: number, filter?: string, signal?: AbortSignal): Promise<PacketLocateResult>;
  getPacket(packetId: number, signal?: AbortSignal): Promise<Packet>;
  listThreatHits(prefixes?: string[], signal?: AbortSignal): Promise<ThreatHit[]>;
  getHuntingRuntimeConfig(): Promise<HuntingRuntimeConfig>;
  updateHuntingRuntimeConfig(config: HuntingRuntimeConfig): Promise<HuntingRuntimeConfig>;
  listObjects(signal?: AbortSignal): Promise<ExtractedObject[]>;
  downloadObjectsZip(ids: number[]): Promise<void>;
  getHttpStream(streamId: number, signal?: AbortSignal): Promise<HttpStream>;
  getRawStream(protocol: "TCP" | "UDP", streamId: number, signal?: AbortSignal): Promise<BinaryStream>;
  getRawStreamPage(protocol: "TCP" | "UDP", streamId: number, cursor: number, limit: number, signal?: AbortSignal): Promise<BinaryStream>;
  decodeStreamPayload(decoder: string, payload: string, options?: Record<string, unknown>, signal?: AbortSignal): Promise<StreamDecodeResult>;
  inspectStreamPayload(payload: string, signal?: AbortSignal): Promise<StreamPayloadInspection>;
  listStreamPayloadSources(signal?: AbortSignal, limit?: number): Promise<StreamPayloadSource[]>;
  updateStreamPayloads(protocol: "HTTP" | "TCP" | "UDP", streamId: number, patches: Array<{ index: number; body: string }>, signal?: AbortSignal): Promise<HttpStream | BinaryStream>;
  listStreamIds(protocol: "HTTP" | "TCP" | "UDP", signal?: AbortSignal): Promise<number[]>;
  getPacketRawHex(packetId: number, signal?: AbortSignal): Promise<string>;
  getPacketLayers(packetId: number, signal?: AbortSignal): Promise<Record<string, unknown> | null>;
  getGlobalTrafficStats(signal?: AbortSignal): Promise<GlobalTrafficStats>;
  getIndustrialAnalysis(signal?: AbortSignal): Promise<IndustrialAnalysis>;
  getVehicleAnalysis(signal?: AbortSignal): Promise<VehicleAnalysis>;
  getMediaAnalysis(forceRefresh?: boolean, signal?: AbortSignal): Promise<MediaAnalysis>;
  transcribeMediaArtifact(token: string, force?: boolean): Promise<MediaTranscription>;
  startMediaBatchTranscription(force?: boolean): Promise<SpeechBatchTaskStatus>;
  getMediaBatchTranscriptionStatus(): Promise<SpeechBatchTaskStatus>;
  cancelMediaBatchTranscription(): Promise<SpeechBatchTaskStatus>;
  exportMediaBatchTranscription(format: "txt" | "json"): Promise<void>;
  getUSBAnalysis(signal?: AbortSignal): Promise<USBAnalysis>;
  getC2SampleAnalysis(signal?: AbortSignal): Promise<C2SampleAnalysis>;
  decryptC2Traffic(req: C2DecryptRequest, signal?: AbortSignal): Promise<C2DecryptResult>;
  getAPTAnalysis(signal?: AbortSignal): Promise<APTAnalysis>;
  getEvidence(signal?: AbortSignal): Promise<UnifiedEvidenceRecord[]>;
  getEvidenceWithFilter(modules?: string[], signal?: AbortSignal): Promise<UnifiedEvidenceRecord[]>;
  downloadMediaArtifact(token: string, filename: string): Promise<void>;
  getMediaPlaybackBlob(token: string): Promise<Blob>;
  listVehicleDBCProfiles(): Promise<DBCProfile[]>;
  addVehicleDBC(path: string): Promise<DBCProfile[]>;
  removeVehicleDBC(path: string): Promise<DBCProfile[]>;
  openDBCFile(): Promise<OpenFileResult>;
  listPlugins(): Promise<PluginItem[]>;
  getPluginSource(id: string): Promise<PluginSource>;
  savePluginSource(source: PluginSource): Promise<PluginSource>;
  addPlugin(plugin: PluginItem): Promise<PluginItem>;
  deletePlugin(id: string): Promise<void>;
  togglePlugin(id: string): Promise<PluginItem>;
  setPluginsEnabled(ids: string[], enabled: boolean): Promise<PluginItem[]>;
  getTLSConfig(): Promise<DecryptionConfig | null>;
  updateTLSConfig(cfg: DecryptionConfig): Promise<void>;
  runWinRMDecrypt(req: WinRMDecryptRequest): Promise<WinRMDecryptResult>;
  getWinRMDecryptResultText(resultId: string): Promise<string>;
  exportWinRMDecryptResult(resultId: string, filename: string): Promise<void>;
  listMiscModules(): Promise<MiscModuleManifest[]>;
  importMiscModulePackage(file: File): Promise<MiscModuleImportResult>;
  deleteMiscModule(id: string): Promise<void>;
  runMiscModule(id: string, values: Record<string, string>): Promise<MiscModuleRunResult>;
  listSMB3SessionCandidates(): Promise<SMB3SessionCandidate[]>;
  generateSMB3RandomSessionKey(req: SMB3RandomSessionKeyRequest): Promise<SMB3RandomSessionKeyResult>;
  listNTLMSessionMaterials(): Promise<NTLMSessionMaterial[]>;
  getHTTPLoginAnalysis(signal?: AbortSignal): Promise<HTTPLoginAnalysis>;
  getSMTPAnalysis(signal?: AbortSignal): Promise<SMTPAnalysis>;
  getMySQLAnalysis(signal?: AbortSignal): Promise<MySQLAnalysis>;
  getShiroRememberMeAnalysis(candidateKeys?: string[], signal?: AbortSignal): Promise<ShiroRememberMeAnalysis>;
  subscribeEvents(handlers: EventHandlers): () => void;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = await buildAuthorizedHeaders(path, init?.headers, init?.body);

  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
  });
  if (!res.ok) {
    let detail = "";
    try {
      const payload = await res.json();
      if (payload && typeof payload.error === "string") {
        detail = payload.error;
      }
    } catch {
      // ignore invalid json error payload
    }
    throw new Error(detail || `backend request failed: ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

async function requestBlob(path: string, init?: RequestInit): Promise<Blob> {
  const headers = await buildAuthorizedHeaders(path, init?.headers, init?.body);
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
  });
  if (!res.ok) {
    let detail = "";
    try {
      const payload = await res.json();
      if (payload && typeof payload.error === "string") {
        detail = payload.error;
      }
    } catch {
      // ignore invalid json error payload
    }
    throw new Error(detail || `backend request failed: ${res.status} ${res.statusText}`);
  }
  return await res.blob();
}

function getDesktopAppBinding(): AppBridgeBinding | undefined {
  if (typeof window === "undefined") {
    return undefined;
  }
  return (window as any)?.go?.main?.DesktopApp as AppBridgeBinding | undefined;
}

let backendAuthTokenPromise: Promise<string> | null = null;

async function getBackendAuthToken(): Promise<string> {
  if (backendAuthTokenPromise) {
    return backendAuthTokenPromise;
  }

  backendAuthTokenPromise = (async () => {
    const envToken = String(import.meta.env.VITE_BACKEND_TOKEN ?? "").trim();
    if (envToken) {
      return envToken;
    }

    const desktopApp = getDesktopAppBinding();
    if (desktopApp?.GetBackendAuthToken) {
      const token = await desktopApp.GetBackendAuthToken();
      return String(token ?? "").trim();
    }

    return "";
  })();

  return backendAuthTokenPromise;
}

async function buildAuthorizedHeaders(path: string, headersInit?: HeadersInit, body?: BodyInit | null): Promise<Headers> {
  const headers = new Headers(headersInit ?? {});
  if (!(body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  if (path !== "/health" && !headers.has("Authorization")) {
    const token = await getBackendAuthToken();
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
    }
  }

  return headers;
}

export async function getBackendAuthHeaders(path: string, headersInit?: HeadersInit, body?: BodyInit | null): Promise<Headers> {
  return buildAuthorizedHeaders(path, headersInit, body);
}

const mediaClient = createMediaClient(request, requestBlob);
const analysisClient = createAnalysisClient(request);
const pluginClient = createPluginClient(request);
const streamClient = createStreamClient(request);
const toolClient = createToolClient(request, API_BASE, buildAuthorizedHeaders);
const captureClient = createCaptureClient(request, getDesktopAppBinding);
const toolRuntimeClient = createToolRuntimeClient(request);
const objectClient = createObjectClient(request, requestBlob);
const huntingClient = createHuntingClient(request);
const c2DecryptClient = createC2DecryptClient(request);
const eventClient = createEventClient(API_BASE, getBackendAuthToken);
const desktopClient = createDesktopClient(request, getDesktopAppBinding);

export const bridge: BackendBridge = {
  isAvailable: desktopClient.isAvailable,
  getDesktopBackendStatus: desktopClient.getDesktopBackendStatus,
  checkAppUpdate: desktopClient.checkAppUpdate,
  installAppUpdate: desktopClient.installAppUpdate,

  checkTShark: toolRuntimeClient.checkTShark,
  checkFFmpeg: toolRuntimeClient.checkFFmpeg,
  checkSpeechToText: toolRuntimeClient.checkSpeechToText,
  getToolRuntimeSnapshot: toolRuntimeClient.getToolRuntimeSnapshot,
  updateToolRuntimeConfig: toolRuntimeClient.updateToolRuntimeConfig,
  setTSharkPath: toolRuntimeClient.setTSharkPath,

  openPcapFile: captureClient.openPcapFile,
  startStreamingPackets: captureClient.startStreamingPackets,
  stopStreamingPackets: captureClient.stopStreamingPackets,
  prepareCaptureReplacement: captureClient.prepareCaptureReplacement,
  closeCapture: captureClient.closeCapture,
  listPackets: captureClient.listPackets,
  listPacketsPage: captureClient.listPacketsPage,

  openDBCFile: desktopClient.openDBCFile,

  locatePacketPage: captureClient.locatePacketPage,
  getPacket: captureClient.getPacket,

  listThreatHits: huntingClient.listThreatHits,
  getHuntingRuntimeConfig: huntingClient.getHuntingRuntimeConfig,
  updateHuntingRuntimeConfig: huntingClient.updateHuntingRuntimeConfig,

  listObjects: objectClient.listObjects,
  downloadObjectsZip: objectClient.downloadObjectsZip,

  getHttpStream: streamClient.getHttpStream,
  getRawStream: streamClient.getRawStream,
  getRawStreamPage: streamClient.getRawStreamPage,
  decodeStreamPayload: streamClient.decodeStreamPayload,
  inspectStreamPayload: streamClient.inspectStreamPayload,
  listStreamPayloadSources: streamClient.listStreamPayloadSources,
  updateStreamPayloads: streamClient.updateStreamPayloads,
  listStreamIds: streamClient.listStreamIds,
  getPacketRawHex: streamClient.getPacketRawHex,
  getPacketLayers: streamClient.getPacketLayers,

  getGlobalTrafficStats: analysisClient.getGlobalTrafficStats,
  getIndustrialAnalysis: analysisClient.getIndustrialAnalysis,
  getVehicleAnalysis: analysisClient.getVehicleAnalysis,

  getMediaAnalysis: mediaClient.getMediaAnalysis,
  transcribeMediaArtifact: mediaClient.transcribeMediaArtifact,
  startMediaBatchTranscription: mediaClient.startMediaBatchTranscription,
  getMediaBatchTranscriptionStatus: mediaClient.getMediaBatchTranscriptionStatus,
  cancelMediaBatchTranscription: mediaClient.cancelMediaBatchTranscription,
  exportMediaBatchTranscription: mediaClient.exportMediaBatchTranscription,

  getUSBAnalysis: analysisClient.getUSBAnalysis,
  getC2SampleAnalysis: analysisClient.getC2SampleAnalysis,

  decryptC2Traffic: c2DecryptClient.decryptC2Traffic,

  getAPTAnalysis: analysisClient.getAPTAnalysis,
  getEvidence: analysisClient.getEvidence,
  getEvidenceWithFilter: analysisClient.getEvidenceWithFilter,

  downloadMediaArtifact: mediaClient.downloadMediaArtifact,
  getMediaPlaybackBlob: mediaClient.getMediaPlaybackBlob,

  listVehicleDBCProfiles: pluginClient.listVehicleDBCProfiles,
  addVehicleDBC: pluginClient.addVehicleDBC,
  removeVehicleDBC: pluginClient.removeVehicleDBC,
  listPlugins: pluginClient.listPlugins,
  getPluginSource: pluginClient.getPluginSource,
  savePluginSource: pluginClient.savePluginSource,
  addPlugin: pluginClient.addPlugin,
  deletePlugin: pluginClient.deletePlugin,
  togglePlugin: pluginClient.togglePlugin,
  setPluginsEnabled: pluginClient.setPluginsEnabled,
  getTLSConfig: pluginClient.getTLSConfig,
  updateTLSConfig: pluginClient.updateTLSConfig,

  runWinRMDecrypt: toolClient.runWinRMDecrypt,
  getWinRMDecryptResultText: toolClient.getWinRMDecryptResultText,
  exportWinRMDecryptResult: toolClient.exportWinRMDecryptResult,
  listMiscModules: toolClient.listMiscModules,
  importMiscModulePackage: toolClient.importMiscModulePackage,
  deleteMiscModule: toolClient.deleteMiscModule,
  runMiscModule: toolClient.runMiscModule,
  listSMB3SessionCandidates: toolClient.listSMB3SessionCandidates,
  generateSMB3RandomSessionKey: toolClient.generateSMB3RandomSessionKey,
  listNTLMSessionMaterials: toolClient.listNTLMSessionMaterials,
  getHTTPLoginAnalysis: toolClient.getHTTPLoginAnalysis,
  getSMTPAnalysis: toolClient.getSMTPAnalysis,
  getMySQLAnalysis: toolClient.getMySQLAnalysis,
  getShiroRememberMeAnalysis: toolClient.getShiroRememberMeAnalysis,

  subscribeEvents: eventClient.subscribeEvents,
};
