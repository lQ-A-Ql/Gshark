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
import { downloadBlob } from "../utils/browserFile";
import { createAnalysisClient } from "./clients/analysisClient";
import {
  createCaptureClient,
  type OpenFileResult,
  type PacketLocateResult,
  type PacketsPageResult,
} from "./clients/captureClient";
import { createMediaClient } from "./clients/mediaClient";
import { createPluginClient } from "./clients/pluginClient";
import { createStreamClient } from "./clients/streamClient";
import { createToolClient } from "./clients/toolClient";
import { asC2DecryptedRecord } from "./mappers/c2DecryptMapper";
import { normalizeC2DecryptResultForDisplay } from "./mappers/c2DecryptDisplayMapper";
import { asPacket, asThreatHit } from "./mappers/packetStreamMapper";
import type { PluginSource } from "./mappers/pluginSourceMapper";
import { asObjectList } from "./mappers/objectMapper";
import { asToolRuntimeSnapshot } from "./mappers/runtimeMapper";

export { isLikelyVShellLowInfoControlRecord, normalizeC2DecryptResultForDisplay } from "./mappers/c2DecryptDisplayMapper";
export type { PluginSource } from "./mappers/pluginSourceMapper";

const API_BASE = (import.meta.env.VITE_BACKEND_URL as string | undefined) ?? "http://127.0.0.1:17891";

export type { OpenFileResult } from "./clients/captureClient";

interface DesktopAppBinding {
  BackendStatus?: () => Promise<string>;
  GetBackendAuthToken?: () => Promise<string | null | undefined>;
  OpenCaptureDialog?: () => Promise<OpenFileResult | null | undefined>;
  OpenDBCDialog?: () => Promise<OpenFileResult | null | undefined>;
  CheckAppUpdate?: () => Promise<AppUpdateStatus | null | undefined>;
  InstallAppUpdate?: () => Promise<void>;
}

export type EventType = "packet" | "status" | "error";

interface EventHandlers {
  packet?: (packet: Packet) => void;
  status?: (message: string) => void;
  error?: (message: string) => void;
}

export interface TSharkStatus {
  available: boolean;
  path: string;
  message: string;
  customPath: string;
  usingCustomPath: boolean;
}

export interface FFmpegStatus {
  available: boolean;
  path: string;
  message: string;
}

export interface HuntingRuntimeConfig {
  prefixes: string[];
  yaraEnabled: boolean;
  yaraBin: string;
  yaraRules: string;
  yaraTimeoutMs: number;
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

function getDesktopAppBinding(): DesktopAppBinding | undefined {
  if (typeof window === "undefined") {
    return undefined;
  }
  return (window as any)?.go?.main?.DesktopApp as DesktopAppBinding | undefined;
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

export const bridge: BackendBridge = {
  async isAvailable() {
    const desktopApp = getDesktopAppBinding();
    if (desktopApp?.BackendStatus) {
      try {
        const status = String(await desktopApp.BackendStatus()).trim().toLowerCase();
        if (status && status !== "running" && status !== "running (reused-existing)" && status !== "starting") {
          return false;
        }
      } catch {
        // Ignore desktop status errors and fall through to HTTP health check.
      }
    }
    try {
      await request<{ status: string }>("/health");
      return true;
    } catch {
      return false;
    }
  },

  async getDesktopBackendStatus() {
    const desktopApp = getDesktopAppBinding();
    if (!desktopApp?.BackendStatus) {
      return "";
    }
    try {
      return String(await desktopApp.BackendStatus()).trim();
    } catch {
      return "";
    }
  },

  async checkAppUpdate() {
    const desktopApp = getDesktopAppBinding();
    if (!desktopApp?.CheckAppUpdate) {
      throw new Error("当前环境不支持桌面端更新");
    }
    const result = await desktopApp.CheckAppUpdate();
    if (!result) {
      throw new Error("更新状态为空");
    }
    return {
      currentVersion: String(result.currentVersion ?? ""),
      currentVersionDisplay: String(result.currentVersionDisplay ?? ""),
      currentVersionSource: String(result.currentVersionSource ?? ""),
      currentExecutable: String(result.currentExecutable ?? ""),
      localHash: String(result.localHash ?? ""),
      repo: String(result.repo ?? ""),
      authMode: String(result.authMode ?? ""),
      checkedAt: String(result.checkedAt ?? ""),
      apiUrl: String(result.apiUrl ?? ""),
      hasUpdate: Boolean(result.hasUpdate),
      upToDate: Boolean(result.upToDate),
      hashMismatch: Boolean(result.hashMismatch),
      latestTag: String(result.latestTag ?? ""),
      latestName: String(result.latestName ?? ""),
      latestPublishedAt: String(result.latestPublishedAt ?? ""),
      releaseUrl: String(result.releaseUrl ?? ""),
      releaseNotes: String(result.releaseNotes ?? ""),
      selectedAsset: result.selectedAsset
        ? {
            name: String(result.selectedAsset.name ?? ""),
            downloadUrl: String(result.selectedAsset.downloadUrl ?? ""),
            sizeBytes: Number(result.selectedAsset.sizeBytes ?? 0),
            contentType: String(result.selectedAsset.contentType ?? "") || undefined,
          }
        : undefined,
      canInstall: Boolean(result.canInstall),
      message: String(result.message ?? ""),
    };
  },

  async installAppUpdate() {
    const desktopApp = getDesktopAppBinding();
    if (!desktopApp?.InstallAppUpdate) {
      throw new Error("当前环境不支持桌面端更新");
    }
    await desktopApp.InstallAppUpdate();
  },

  async checkTShark() {
    const payload = await request<any>("/api/tools/tshark");
    return {
      available: Boolean(payload.available),
      path: String(payload.path ?? ""),
      message: String(payload.message ?? ""),
      customPath: String(payload.custom_path ?? ""),
      usingCustomPath: Boolean(payload.using_custom_path),
    };
  },

  async checkFFmpeg() {
    const payload = await request<any>("/api/tools/ffmpeg");
    return {
      available: Boolean(payload.available),
      path: String(payload.path ?? ""),
      message: String(payload.message ?? ""),
    };
  },

  async checkSpeechToText() {
    const payload = await request<any>("/api/tools/speech-to-text");
    return {
      available: Boolean(payload.available),
      engine: String(payload.engine ?? ""),
      language: String(payload.language ?? ""),
      pythonAvailable: Boolean(payload.python_available),
      pythonCommand: String(payload.python_command ?? "") || undefined,
      ffmpegAvailable: Boolean(payload.ffmpeg_available),
      voskAvailable: Boolean(payload.vosk_available),
      modelAvailable: Boolean(payload.model_available),
      modelPath: String(payload.model_path ?? "") || undefined,
      message: String(payload.message ?? ""),
    };
  },

  async getToolRuntimeSnapshot() {
    const payload = await request<any>("/api/tools/runtime-config");
    return asToolRuntimeSnapshot(payload);
  },

  async updateToolRuntimeConfig(config: ToolRuntimeConfig) {
    const payload = await request<any>("/api/tools/runtime-config", {
      method: "POST",
      body: JSON.stringify({
        tshark_path: config.tsharkPath,
        ffmpeg_path: config.ffmpegPath,
        python_path: config.pythonPath,
        vosk_model_path: config.voskModelPath,
        yara_enabled: config.yaraEnabled,
        yara_bin: config.yaraBin,
        yara_rules: config.yaraRules,
        yara_timeout_ms: config.yaraTimeoutMs,
      }),
    });
    return asToolRuntimeSnapshot(payload);
  },

  async setTSharkPath(path: string) {
    const payload = await request<any>("/api/tools/tshark", {
      method: "POST",
      body: JSON.stringify({ path }),
    });
    return {
      available: Boolean(payload.available),
      path: String(payload.path ?? ""),
      message: String(payload.message ?? ""),
      customPath: String(payload.custom_path ?? ""),
      usingCustomPath: Boolean(payload.using_custom_path),
    };
  },

  openPcapFile: captureClient.openPcapFile,
  startStreamingPackets: captureClient.startStreamingPackets,
  stopStreamingPackets: captureClient.stopStreamingPackets,
  prepareCaptureReplacement: captureClient.prepareCaptureReplacement,
  closeCapture: captureClient.closeCapture,
  listPackets: captureClient.listPackets,
  listPacketsPage: captureClient.listPacketsPage,

  async openDBCFile() {
    const desktopApp = getDesktopAppBinding();
    if (!desktopApp?.OpenDBCDialog) {
      throw new Error("当前环境不支持原生 DBC 文件选择");
    }
    const result = await desktopApp.OpenDBCDialog();
    if (!result?.filePath) {
      throw new Error("未选择 DBC 文件");
    }
    return {
      filePath: String(result.filePath),
      fileSize: Number(result.fileSize ?? 0),
      fileName: String(result.fileName ?? String(result.filePath).split(/[\\/]/).pop() ?? "database.dbc"),
    };
  },

  locatePacketPage: captureClient.locatePacketPage,
  getPacket: captureClient.getPacket,

  async listThreatHits(prefixes = ["flag{", "ctf{"], signal?: AbortSignal) {
    const query = prefixes.map((p) => `prefix=${encodeURIComponent(p)}`).join("&");
    const rows = await request<any[]>(`/api/hunting?${query}`, { signal });
    return rows.map(asThreatHit);
  },

  async getHuntingRuntimeConfig() {
    const payload = await request<any>("/api/hunting/config");
    const prefixes = Array.isArray(payload.prefixes)
      ? payload.prefixes.map((p: unknown) => String(p ?? "").trim()).filter(Boolean)
      : [];
    return {
      prefixes,
      yaraEnabled: Boolean(payload.yara_enabled ?? true),
      yaraBin: String(payload.yara_bin ?? ""),
      yaraRules: String(payload.yara_rules ?? ""),
      yaraTimeoutMs: Number(payload.yara_timeout_ms ?? 25000),
    };
  },

  async updateHuntingRuntimeConfig(config: HuntingRuntimeConfig) {
    const payload = await request<any>("/api/hunting/config", {
      method: "POST",
      body: JSON.stringify({
        prefixes: config.prefixes,
        yara_enabled: config.yaraEnabled,
        yara_bin: config.yaraBin,
        yara_rules: config.yaraRules,
        yara_timeout_ms: config.yaraTimeoutMs,
      }),
    });
    const prefixes = Array.isArray(payload.prefixes)
      ? payload.prefixes.map((p: unknown) => String(p ?? "").trim()).filter(Boolean)
      : [];
    return {
      prefixes,
      yaraEnabled: Boolean(payload.yara_enabled ?? true),
      yaraBin: String(payload.yara_bin ?? ""),
      yaraRules: String(payload.yara_rules ?? ""),
      yaraTimeoutMs: Number(payload.yara_timeout_ms ?? 25000),
    };
  },

  async listObjects(signal?: AbortSignal) {
    const rows = await request<any[]>("/api/objects", { signal });
    return asObjectList(rows);
  },

  async downloadObjectsZip(ids: number[]) {
    const body = JSON.stringify({ ids });
    const blob = await requestBlob("/api/objects/download", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
    downloadBlob("exported_objects.zip", blob);
  },

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

  async decryptC2Traffic(req: C2DecryptRequest, signal?: AbortSignal) {
    const payload = await request<any>("/api/c2-analysis/decrypt", {
      method: "POST",
      signal,
      body: JSON.stringify({
        family: req.family,
        scope: req.scope
          ? {
              packet_ids: req.scope.packetIds ?? [],
              stream_ids: req.scope.streamIds ?? [],
              use_candidates: Boolean(req.scope.useCandidates),
              use_aggregates: Boolean(req.scope.useAggregates),
            }
          : undefined,
        vshell: req.vshell
          ? {
              vkey: req.vshell.vkey,
              salt: req.vshell.salt,
              mode: req.vshell.mode,
            }
          : undefined,
        cs: req.cs
          ? {
              key_mode: req.cs.keyMode,
              aes_key: req.cs.aesKey,
              hmac_key: req.cs.hmacKey,
              aes_rand: req.cs.aesRand,
              rsa_private_key: req.cs.rsaPrivateKey,
              transform_mode: req.cs.transformMode,
            }
          : undefined,
      }),
    });
    const result: C2DecryptResult = {
      family: String(payload.family ?? req.family) === "vshell" ? "vshell" : "cs",
      status: String(payload.status ?? "failed"),
      totalCandidates: Number(payload.total_candidates ?? 0),
      decryptedCount: Number(payload.decrypted_count ?? 0),
      failedCount: Number(payload.failed_count ?? 0),
      records: Array.isArray(payload.records) ? payload.records.map(asC2DecryptedRecord) : [],
      notes: Array.isArray(payload.notes) ? payload.notes.map((value: unknown) => String(value ?? "")) : [],
    };
    return normalizeC2DecryptResultForDisplay(result);
  },

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

  subscribeEvents(handlers: EventHandlers) {
    let disposed = false;
    let retryMs = 1000;
    let source: EventSource | null = null;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;

    function connect() {
      if (disposed) return;

      void getBackendAuthToken().then((token) => {
        if (disposed) return;
        const url = token
          ? `${API_BASE}/api/events?access_token=${encodeURIComponent(token)}`
          : `${API_BASE}/api/events`;
        source = new EventSource(url);

        source.addEventListener("ready", () => {
          retryMs = 1000; // reset backoff on successful connection
        });

        source.addEventListener("packet", (event) => {
          try {
            handlers.packet?.(asPacket(JSON.parse((event as MessageEvent).data)));
          } catch {
            return;
          }
        });
        source.addEventListener("status", (event) => {
          try {
            const payload = JSON.parse((event as MessageEvent).data);
            handlers.status?.(String(payload.message ?? ""));
          } catch {
            return;
          }
        });
        source.addEventListener("error", (event) => {
          try {
            const payload = JSON.parse((event as MessageEvent).data);
            handlers.error?.(String(payload.message ?? ""));
          } catch {
            // connection lost – attempt reconnect with exponential backoff
            if (source) {
              source.close();
              source = null;
            }
            if (!disposed) {
              handlers.error?.(`后端连接断开，${(retryMs / 1000).toFixed(0)}s 后重连...`);
              retryTimer = setTimeout(() => {
                retryMs = Math.min(retryMs * 2, 30000);
                connect();
              }, retryMs);
            }
          }
        });
      }).catch(() => {
        if (!disposed) {
          handlers.error?.("后端鉴权初始化失败");
        }
      });
    }

    connect();

    return () => {
      disposed = true;
      if (retryTimer) clearTimeout(retryTimer);
      if (source) source.close();
    };
  },
};
