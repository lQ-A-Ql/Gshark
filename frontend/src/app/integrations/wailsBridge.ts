import type {
  AppUpdateStatus,
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

const API_BASE = (import.meta.env.VITE_BACKEND_URL as string | undefined) ?? "http://127.0.0.1:17891";

export interface OpenFileResult {
  filePath: string;
  fileSize: number;
  fileName: string;
}

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

interface PacketsPageResult {
  items: Packet[];
  nextCursor: number;
  total: number;
  hasMore: boolean;
  filtering?: boolean;
}

interface PacketLocateResult {
  packetId: number;
  cursor: number;
  total: number;
  found: boolean;
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

export interface PluginSource {
  id: string;
  configPath: string;
  configContent: string;
  logicPath: string;
  logicContent: string;
  entry: string;
}

export interface HuntingRuntimeConfig {
  prefixes: string[];
  yaraEnabled: boolean;
  yaraBin: string;
  yaraRules: string;
  yaraTimeoutMs: number;
}

function normalizePacketTime(value: unknown): string {
  const raw = String(value ?? "").trim();
  if (!raw) return "";

  if (/^\d{13,}$/.test(raw)) {
    const ms = Number(raw.slice(0, 13));
    if (!Number.isNaN(ms)) {
      const d = new Date(ms);
      return `${d.toTimeString().slice(0, 8)}.${String(d.getMilliseconds()).padStart(3, "0")}`;
    }
  }

  const parsed = new Date(raw);
  if (!Number.isNaN(parsed.getTime())) {
    const iso = parsed.toISOString();
    return iso.slice(11, 23);
  }

  if (raw.length > 16) {
    return `${raw.slice(0, 13)}...`;
  }
  return raw;
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
  startStreamingPackets(filePath: string, filter: string): Promise<void>;
  stopStreamingPackets(): Promise<void>;
  closeCapture(): Promise<void>;
  listPackets(): Promise<Packet[]>;
  listPacketsPage(cursor: number, limit: number, filter?: string, signal?: AbortSignal): Promise<PacketsPageResult>;
  locatePacketPage(packetId: number, limit: number, filter?: string): Promise<PacketLocateResult>;
  getPacket(packetId: number): Promise<Packet>;
  listThreatHits(prefixes?: string[], signal?: AbortSignal): Promise<ThreatHit[]>;
  getHuntingRuntimeConfig(): Promise<HuntingRuntimeConfig>;
  updateHuntingRuntimeConfig(config: HuntingRuntimeConfig): Promise<HuntingRuntimeConfig>;
  listObjects(signal?: AbortSignal): Promise<ExtractedObject[]>;
  getHttpStream(streamId: number, signal?: AbortSignal): Promise<HttpStream>;
  getRawStream(protocol: "TCP" | "UDP", streamId: number, signal?: AbortSignal): Promise<BinaryStream>;
  getRawStreamPage(protocol: "TCP" | "UDP", streamId: number, cursor: number, limit: number, signal?: AbortSignal): Promise<BinaryStream>;
  decodeStreamPayload(decoder: string, payload: string, options?: Record<string, unknown>, signal?: AbortSignal): Promise<StreamDecodeResult>;
  inspectStreamPayload(payload: string, signal?: AbortSignal): Promise<StreamPayloadInspection>;
  updateStreamPayloads(protocol: "HTTP" | "TCP" | "UDP", streamId: number, patches: Array<{ index: number; body: string }>, signal?: AbortSignal): Promise<HttpStream | BinaryStream>;
  listStreamIds(protocol: "HTTP" | "TCP" | "UDP"): Promise<number[]>;
  getPacketRawHex(packetId: number): Promise<string>;
  getPacketLayers(packetId: number): Promise<Record<string, unknown> | null>;
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
  getAPTAnalysis(signal?: AbortSignal): Promise<APTAnalysis>;
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

function asPacket(input: any): Packet {
  const color = input.color_features ?? {};
  return {
    id: Number(input.id ?? 0),
    time: normalizePacketTime(input.timestamp),
    src: String(input.source_ip ?? ""),
    srcPort: Number(input.source_port ?? 0),
    dst: String(input.dest_ip ?? ""),
    dstPort: Number(input.dest_port ?? 0),
    proto: String(input.protocol ?? "OTHER") as Packet["proto"],
    displayProtocol: String(input.display_protocol ?? "").trim() || undefined,
    length: Number(input.length ?? 0),
    info: String(input.info ?? ""),
    payload: String(input.payload ?? ""),
    rawHex: String(input.raw_hex ?? "") || undefined,
    streamId: Number(input.stream_id ?? 0),
    ipHeaderLen: Number(input.ip_header_len ?? 0) || undefined,
    l4HeaderLen: Number(input.l4_header_len ?? 0) || undefined,
    colorFeatures: {
      tcpAnalysisFlags: Boolean(color.tcp_analysis_flags),
      tcpWindowUpdate: Boolean(color.tcp_window_update),
      tcpKeepAlive: Boolean(color.tcp_keep_alive),
      tcpKeepAliveAck: Boolean(color.tcp_keep_alive_ack),
      tcpRst: Boolean(color.tcp_rst),
      tcpSyn: Boolean(color.tcp_syn),
      tcpFin: Boolean(color.tcp_fin),
      hsrpState: Number(color.hsrp_state ?? 0) || undefined,
      ospfMsg: Number(color.ospf_msg ?? 0) || undefined,
      icmpType: Number(color.icmp_type ?? 0) || undefined,
      icmpv6Type: Number(color.icmpv6_type ?? 0) || undefined,
      ipv4Ttl: Number(color.ipv4_ttl ?? 0) || undefined,
      ipv6HopLimit: Number(color.ipv6_hop_limit ?? 0) || undefined,
      stpTopologyChange: Boolean(color.stp_topology_change),
      checksumBad: Boolean(color.checksum_bad),
      broadcast: Boolean(color.broadcast),
      hasSmb: Boolean(color.has_smb),
      hasNbss: Boolean(color.has_nbss),
      hasNbns: Boolean(color.has_nbns),
      hasNetbios: Boolean(color.has_netbios),
      hasDcerpc: Boolean(color.has_dcerpc),
      hasSystemdJournal: Boolean(color.has_systemd_journal),
      hasSysdig: Boolean(color.has_sysdig),
      hasHsrp: Boolean(color.has_hsrp),
      hasEigrp: Boolean(color.has_eigrp),
      hasOspf: Boolean(color.has_ospf),
      hasBgp: Boolean(color.has_bgp),
      hasCdp: Boolean(color.has_cdp),
      hasVrrp: Boolean(color.has_vrrp),
      hasCarp: Boolean(color.has_carp),
      hasGvrp: Boolean(color.has_gvrp),
      hasIgmp: Boolean(color.has_igmp),
      hasIsmp: Boolean(color.has_ismp),
      hasRip: Boolean(color.has_rip),
      hasGlbp: Boolean(color.has_glbp),
      hasPim: Boolean(color.has_pim),
    },
  };
}

function threatLevel(value: string): ThreatHit["level"] {
  if (value === "critical" || value === "high" || value === "medium" || value === "low") {
    return value;
  }
  return "low";
}

function asThreatHit(input: any): ThreatHit {
  return {
    id: Number(input.id ?? 0),
    packetId: Number(input.packet_id ?? 0),
    category: String(input.category ?? "Anomaly") as ThreatHit["category"],
    rule: String(input.rule ?? ""),
    level: threatLevel(String(input.level ?? "low")),
    preview: String(input.preview ?? ""),
    match: String(input.match ?? ""),
  };
}

function asObject(input: any): ExtractedObject {
  const source = String(input.source ?? "HTTP");
  return {
    id: Number(input.id ?? 0),
    packetId: Number(input.packet_id ?? 0),
    name: String(input.name ?? "object.bin"),
    sizeBytes: Number(input.size_bytes ?? 0),
    mime: String(input.mime ?? "application/octet-stream"),
    source: source === "FTP" ? "FTP" : "HTTP",
  };
}

function asHttpStream(input: any): HttpStream {
  const chunks = Array.isArray(input.chunks)
    ? input.chunks.map((chunk: any) => ({
        packetId: Number(chunk.packet_id ?? 0),
        direction: chunk.direction === "server" ? "server" : "client",
        body: String(chunk.body ?? ""),
      }))
    : [];

  const fallbackChunks = chunks.length
    ? chunks
    : [
        ...(String(input.request ?? "")
          ? [{ packetId: 0, direction: "client" as const, body: String(input.request ?? "") }]
          : []),
        ...(String(input.response ?? "")
          ? [{ packetId: 0, direction: "server" as const, body: String(input.response ?? "") }]
          : []),
      ];

  return {
    id: Number(input.stream_id ?? 1),
    client: String(input.from ?? ""),
    server: String(input.to ?? ""),
    request: String(input.request ?? ""),
    response: String(input.response ?? ""),
    chunks: fallbackChunks,
    loadMeta: asStreamLoadMeta(input.load_meta),
  };
}

function asBinaryStream(input: any, protocol: "TCP" | "UDP"): BinaryStream {
  const chunks = Array.isArray(input.chunks)
    ? input.chunks.map((chunk: any) => ({
        packetId: Number(chunk.packet_id ?? 0),
        direction: chunk.direction === "server" ? "server" : "client",
        body: String(chunk.body ?? ""),
      }))
    : [];

  return {
    id: Number(input.stream_id ?? 1),
    protocol,
    from: String(input.from ?? ""),
    to: String(input.to ?? ""),
    chunks,
    nextCursor: Number(input.next_cursor ?? chunks.length),
    totalChunks: Number(input.total ?? chunks.length),
    hasMore: Boolean(input.has_more),
    loadMeta: asStreamLoadMeta(input.load_meta),
  };
}

function asStreamLoadMeta(input: any): HttpStream["loadMeta"] {
  if (!input || typeof input !== "object") {
    return undefined;
  }
  return {
    source: String(input.source ?? "").trim() || undefined,
    loading: Boolean(input.loading),
    cacheHit: Boolean(input.cache_hit),
    indexHit: Boolean(input.index_hit),
    fileFallback: Boolean(input.file_fallback),
    tsharkMs: Number(input.tshark_ms ?? 0) || 0,
    overrideCount: Number(input.override_count ?? 0) || undefined,
  };
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

function downloadBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
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

  async openPcapFile() {
    const desktopApp = getDesktopAppBinding();
    if (desktopApp?.OpenCaptureDialog) {
      const result = await desktopApp.OpenCaptureDialog();
      if (!result?.filePath) {
        throw new Error("未选择文件");
      }
      return {
        filePath: String(result.filePath),
        fileSize: Number(result.fileSize ?? 0),
        fileName: String(result.fileName ?? String(result.filePath).split(/[\\/]/).pop() ?? "capture.pcapng"),
      };
    }

    const file = await selectLocalFile();
    const form = new FormData();
    form.append("file", file, file.name);

    const result = await request<OpenFileResult>("/api/capture/upload", {
      method: "POST",
      body: form,
    });

    return {
      filePath: result.filePath,
      fileSize: Number(result.fileSize ?? file.size),
      fileName: result.fileName ?? file.name,
    };
  },

  async startStreamingPackets(filePath: string, filter: string) {
    await request("/api/capture/start", {
      method: "POST",
      body: JSON.stringify({ file_path: filePath, display_filter: filter, max_packets: 0, emit_packets: false, fast_list: true }),
    });
  },

  async stopStreamingPackets() {
    await request("/api/capture/stop", { method: "POST" });
  },

  async closeCapture() {
    await request("/api/capture/close", { method: "POST" });
  },

  async listPackets() {
    const rows = await request<any[]>("/api/packets");
    return rows.map(asPacket);
  },

  async listPacketsPage(cursor: number, limit: number, filter = "", signal?: AbortSignal) {
    const query = new URLSearchParams({
      cursor: String(cursor),
      limit: String(limit),
    });
    if (filter.trim()) {
      query.set("filter", filter);
    }
    const payload = await request<any>(`/api/packets/page?${query.toString()}`, { signal });
    const rows = Array.isArray(payload.items) ? payload.items : [];
    return {
      items: rows.map(asPacket),
      nextCursor: Number(payload.next_cursor ?? rows.length),
      total: Number(payload.total ?? rows.length),
      hasMore: Boolean(payload.has_more),
      filtering: Boolean(payload.filtering),
    };
  },

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

  async locatePacketPage(packetId: number, limit: number, filter = "") {
    const query = new URLSearchParams({
      id: String(packetId),
      limit: String(limit),
    });
    if (filter.trim()) {
      query.set("filter", filter);
    }
    const payload = await request<any>(`/api/packets/locate?${query.toString()}`);
    return {
      packetId: Number(payload.packet_id ?? packetId),
      cursor: Number(payload.cursor ?? 0),
      total: Number(payload.total ?? 0),
      found: Boolean(payload.found),
    };
  },

  async getPacket(packetId: number) {
    const payload = await request<any>(`/api/packet?id=${encodeURIComponent(String(packetId))}`);
    return asPacket(payload);
  },

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
    return rows.map(asObject);
  },

  async getHttpStream(streamId: number, signal?: AbortSignal) {
    const stream = await request<any>(`/api/streams/http?streamId=${encodeURIComponent(String(streamId))}`, { signal });
    return asHttpStream(stream);
  },

  async getRawStream(protocol: "TCP" | "UDP", streamId: number, signal?: AbortSignal) {
    const stream = await request<any>(`/api/streams/raw?protocol=${protocol}&streamId=${encodeURIComponent(String(streamId))}`, { signal });
    return asBinaryStream(stream, protocol);
  },

  async getRawStreamPage(protocol: "TCP" | "UDP", streamId: number, cursor: number, limit: number, signal?: AbortSignal) {
    const stream = await request<any>(
      `/api/streams/raw/page?protocol=${protocol}&streamId=${encodeURIComponent(String(streamId))}&cursor=${encodeURIComponent(String(cursor))}&limit=${encodeURIComponent(String(limit))}`,
      { signal },
    );
    return asBinaryStream(stream, protocol);
  },

  async decodeStreamPayload(decoder: string, payload: string, options: Record<string, unknown> = {}, signal?: AbortSignal) {
    const result = await request<any>("/api/streams/decode", {
      method: "POST",
      signal,
      body: JSON.stringify({
        decoder,
        payload,
        options,
      }),
    });
    return {
      decoder: String(result.decoder ?? decoder) as StreamDecodeResult["decoder"],
      summary: String(result.summary ?? ""),
      text: String(result.text ?? ""),
      bytesHex: String(result.bytes_hex ?? ""),
      encoding: String(result.encoding ?? ""),
      confidence: Number(result.confidence ?? 0) || undefined,
      warnings: Array.isArray(result.warnings) ? result.warnings.map((item: unknown) => String(item ?? "")) : [],
      signals: Array.isArray(result.signals) ? result.signals.map((item: unknown) => String(item ?? "")) : [],
      attemptErrors: Array.isArray(result.attempt_errors) ? result.attempt_errors.map((item: unknown) => String(item ?? "")) : [],
    };
  },

  async inspectStreamPayload(payload: string, signal?: AbortSignal) {
    const result = await request<any>("/api/streams/inspect", {
      method: "POST",
      signal,
      body: JSON.stringify({ payload }),
    });
    return {
      normalizedPayload: String(result.normalized_payload ?? ""),
      candidates: Array.isArray(result.candidates)
        ? result.candidates.map((item: any) => ({
            id: String(item.id ?? ""),
            label: String(item.label ?? ""),
            kind: String(item.kind ?? ""),
            paramName: String(item.param_name ?? "") || undefined,
            value: String(item.value ?? ""),
            preview: String(item.preview ?? "") || undefined,
            confidence: Number(item.confidence ?? 0) || undefined,
            decoderHints: Array.isArray(item.decoder_hints) ? item.decoder_hints.map((x: unknown) => String(x ?? "")) : [],
            fingerprints: Array.isArray(item.fingerprints) ? item.fingerprints.map((x: unknown) => String(x ?? "")) : [],
          }))
        : [],
      suggestedCandidateId: String(result.suggested_candidate_id ?? "") || undefined,
      suggestedDecoder: String(result.suggested_decoder ?? "") || undefined,
      suggestedFamily: String(result.suggested_family ?? "") || undefined,
      confidence: Number(result.confidence ?? 0) || undefined,
      reasons: Array.isArray(result.reasons) ? result.reasons.map((item: unknown) => String(item ?? "")) : [],
    } as StreamPayloadInspection;
  },

  async updateStreamPayloads(protocol: "HTTP" | "TCP" | "UDP", streamId: number, patches: Array<{ index: number; body: string }>, signal?: AbortSignal) {
    const payload = await request<any>("/api/streams/payloads", {
      method: "POST",
      signal,
      body: JSON.stringify({
        protocol,
        stream_id: streamId,
        patches,
      }),
    });
    return protocol === "HTTP" ? asHttpStream(payload) : asBinaryStream(payload, protocol);
  },

  async listStreamIds(protocol: "HTTP" | "TCP" | "UDP") {
    const payload = await request<any>(`/api/streams/index?protocol=${encodeURIComponent(protocol)}`);
    const ids = Array.isArray(payload.ids) ? payload.ids : [];
    return ids
      .map((id: unknown) => Number(id))
      .filter((id: number) => Number.isFinite(id) && id >= 0)
      .sort((a: number, b: number) => a - b);
  },

  async getPacketRawHex(packetId: number) {
    const payload = await request<any>(`/api/packet/raw?id=${encodeURIComponent(String(packetId))}`);
    return String(payload.raw_hex ?? "");
  },

  async getPacketLayers(packetId: number) {
    const payload = await request<any>(`/api/packet/layers?id=${encodeURIComponent(String(packetId))}`);
    const layers = payload.layers;
    if (layers && typeof layers === "object" && !Array.isArray(layers)) {
      return layers as Record<string, unknown>;
    }
    return null;
  },

  async getGlobalTrafficStats(signal?: AbortSignal) {
    const payload = await request<any>("/api/stats/traffic/global", { signal });
    return {
      totalPackets: Number(payload.total_packets ?? 0),
      protocolKinds: Number(payload.protocol_kinds ?? 0),
      timeline: Array.isArray(payload.timeline)
        ? payload.timeline.map((x: any) => ({ label: String(x.label ?? ""), count: Number(x.count ?? 0) }))
        : [],
      protocolDist: Array.isArray(payload.protocol_dist)
        ? payload.protocol_dist.map((x: any) => ({ label: String(x.label ?? ""), count: Number(x.count ?? 0) }))
        : [],
      topTalkers: Array.isArray(payload.top_talkers)
        ? payload.top_talkers.map((x: any) => ({ label: String(x.label ?? ""), count: Number(x.count ?? 0) }))
        : [],
      topHostnames: Array.isArray(payload.top_hostnames)
        ? payload.top_hostnames.map((x: any) => ({ label: String(x.label ?? ""), count: Number(x.count ?? 0) }))
        : [],
      topDomains: Array.isArray(payload.top_domains)
        ? payload.top_domains.map((x: any) => ({ label: String(x.label ?? ""), count: Number(x.count ?? 0) }))
        : [],
      topSrcIPs: Array.isArray(payload.top_src_ips)
        ? payload.top_src_ips.map((x: any) => ({ label: String(x.label ?? ""), count: Number(x.count ?? 0) }))
        : [],
      topDstIPs: Array.isArray(payload.top_dst_ips)
        ? payload.top_dst_ips.map((x: any) => ({ label: String(x.label ?? ""), count: Number(x.count ?? 0) }))
        : [],
      topComputerNames: Array.isArray(payload.top_computer_names)
        ? payload.top_computer_names.map((x: any) => ({ label: String(x.label ?? ""), count: Number(x.count ?? 0) }))
        : [],
      topDestPorts: Array.isArray(payload.top_dest_ports)
        ? payload.top_dest_ports.map((x: any) => ({ label: String(x.label ?? ""), count: Number(x.count ?? 0) }))
        : [],
      topSrcPorts: Array.isArray(payload.top_src_ports)
        ? payload.top_src_ports.map((x: any) => ({ label: String(x.label ?? ""), count: Number(x.count ?? 0) }))
        : [],
    };
  },

  async getIndustrialAnalysis(signal?: AbortSignal) {
    const payload = await request<any>("/api/analysis/industrial", { signal });
    return {
      totalIndustrialPackets: Number(payload.total_industrial_packets ?? 0),
      protocols: Array.isArray(payload.protocols) ? payload.protocols.map(asBucket) : [],
      conversations: Array.isArray(payload.conversations) ? payload.conversations.map(asConversation) : [],
      modbus: {
        totalFrames: Number(payload.modbus?.total_frames ?? 0),
        requests: Number(payload.modbus?.requests ?? 0),
        responses: Number(payload.modbus?.responses ?? 0),
        exceptions: Number(payload.modbus?.exceptions ?? 0),
        functionCodes: Array.isArray(payload.modbus?.function_codes) ? payload.modbus.function_codes.map(asBucket) : [],
        unitIds: Array.isArray(payload.modbus?.unit_ids) ? payload.modbus.unit_ids.map(asBucket) : [],
        referenceHits: Array.isArray(payload.modbus?.reference_hits) ? payload.modbus.reference_hits.map(asBucket) : [],
        exceptionCodes: Array.isArray(payload.modbus?.exception_codes) ? payload.modbus.exception_codes.map(asBucket) : [],
        transactions: Array.isArray(payload.modbus?.transactions)
          ? payload.modbus.transactions.map((item: any) => ({
              packetId: Number(item.packet_id ?? 0),
              time: String(item.time ?? ""),
              source: String(item.source ?? ""),
              destination: String(item.destination ?? ""),
              transactionId: Number(item.transaction_id ?? 0),
              unitId: Number(item.unit_id ?? 0),
              functionCode: Number(item.function_code ?? 0),
              functionName: String(item.function_name ?? ""),
              kind: String(item.kind ?? ""),
              reference: String(item.reference ?? ""),
              quantity: String(item.quantity ?? ""),
              exceptionCode: Number(item.exception_code ?? 0),
              responseTime: String(item.response_time ?? ""),
              registerValues: String(item.register_values ?? "") || undefined,
              bitRange: item.bit_range && typeof item.bit_range === "object"
                ? {
                    type: String(item.bit_range.type ?? "") || undefined,
                    start: Number(item.bit_range.start ?? 0) || undefined,
                    count: Number(item.bit_range.count ?? 0) || undefined,
                    values: Array.isArray(item.bit_range.values) ? item.bit_range.values.map((value: unknown) => Boolean(value)) : undefined,
                    preview: String(item.bit_range.preview ?? "") || undefined,
                  }
                : undefined,
              summary: String(item.summary ?? ""),
            }))
          : [],
      },
      suspiciousWrites: Array.isArray(payload.suspicious_writes)
        ? payload.suspicious_writes.map((item: any) => ({
            target: String(item.target ?? ""),
            unitId: Number(item.unit_id ?? 0),
            functionCode: Number(item.function_code ?? 0),
            functionName: String(item.function_name ?? ""),
            writeCount: Number(item.write_count ?? 0),
            sources: Array.isArray(item.sources) ? item.sources.map((value: unknown) => String(value ?? "")) : [],
            firstTime: String(item.first_time ?? ""),
            lastTime: String(item.last_time ?? ""),
            sampleValues: Array.isArray(item.sample_values) ? item.sample_values.map((value: unknown) => String(value ?? "")) : [],
            samplePacketId: Number(item.sample_packet_id ?? 0),
          }))
        : [],
      controlCommands: Array.isArray(payload.control_commands)
        ? payload.control_commands.map((item: any) => ({
            packetId: Number(item.packet_id ?? 0),
            time: String(item.time ?? ""),
            protocol: String(item.protocol ?? ""),
            source: String(item.source ?? ""),
            destination: String(item.destination ?? ""),
            operation: String(item.operation ?? ""),
            target: String(item.target ?? ""),
            value: String(item.value ?? ""),
            result: String(item.result ?? ""),
            summary: String(item.summary ?? ""),
          }))
        : [],
      ruleHits: Array.isArray(payload.rule_hits)
        ? payload.rule_hits.map((item: any) => ({
            rule: String(item.rule ?? ""),
            level: threatLevel(String(item.level ?? "low")),
            packetId: Number(item.packet_id ?? 0) || undefined,
            time: String(item.time ?? "") || undefined,
            source: String(item.source ?? "") || undefined,
            destination: String(item.destination ?? "") || undefined,
            functionCode: Number(item.function_code ?? 0) || undefined,
            functionName: String(item.function_name ?? "") || undefined,
            target: String(item.target ?? "") || undefined,
            evidence: String(item.evidence ?? "") || undefined,
            summary: String(item.summary ?? ""),
          }))
        : [],
      details: Array.isArray(payload.details)
        ? payload.details.map((detail: any) => ({
            name: String(detail.name ?? ""),
            totalFrames: Number(detail.total_frames ?? 0),
            operations: Array.isArray(detail.operations) ? detail.operations.map(asBucket) : [],
            targets: Array.isArray(detail.targets) ? detail.targets.map(asBucket) : [],
            results: Array.isArray(detail.results) ? detail.results.map(asBucket) : [],
            records: Array.isArray(detail.records)
              ? detail.records.map((item: any) => ({
                  packetId: Number(item.packet_id ?? 0),
                  time: String(item.time ?? ""),
                  source: String(item.source ?? ""),
                  destination: String(item.destination ?? ""),
                  operation: String(item.operation ?? ""),
                  target: String(item.target ?? "") || undefined,
                  result: String(item.result ?? "") || undefined,
                  value: String(item.value ?? "") || undefined,
                  summary: String(item.summary ?? ""),
                }))
              : [],
          }))
        : [],
      notes: Array.isArray(payload.notes) ? payload.notes.map((item: unknown) => String(item ?? "")) : [],
    };
  },

  async getVehicleAnalysis(signal?: AbortSignal) {
    const payload = await request<any>("/api/analysis/vehicle", { signal });
    return {
      totalVehiclePackets: Number(payload.total_vehicle_packets ?? 0),
      protocols: Array.isArray(payload.protocols) ? payload.protocols.map(asBucket) : [],
      conversations: Array.isArray(payload.conversations) ? payload.conversations.map(asConversation) : [],
      can: {
        totalFrames: Number(payload.can?.total_frames ?? 0),
        extendedFrames: Number(payload.can?.extended_frames ?? 0),
        rtrFrames: Number(payload.can?.rtr_frames ?? 0),
        errorFrames: Number(payload.can?.error_frames ?? 0),
        busIds: Array.isArray(payload.can?.bus_ids) ? payload.can.bus_ids.map(asBucket) : [],
        messageIds: Array.isArray(payload.can?.message_ids) ? payload.can.message_ids.map(asBucket) : [],
        payloadProtocols: Array.isArray(payload.can?.payload_protocols) ? payload.can.payload_protocols.map(asBucket) : [],
        payloadRecords: Array.isArray(payload.can?.payload_records)
          ? payload.can.payload_records.map((item: any) => ({
              packetId: Number(item.packet_id ?? 0),
              time: String(item.time ?? ""),
              busId: String(item.bus_id ?? ""),
              identifier: String(item.identifier ?? ""),
              protocol: String(item.protocol ?? ""),
              frameType: String(item.frame_type ?? "") || undefined,
              sourceAddress: String(item.source_address ?? "") || undefined,
              targetAddress: String(item.target_address ?? "") || undefined,
              service: String(item.service ?? "") || undefined,
              detail: String(item.detail ?? "") || undefined,
              length: Number(item.length ?? 0),
              rawData: String(item.raw_data ?? "") || undefined,
              summary: String(item.summary ?? ""),
            }))
          : [],
        dbcProfiles: Array.isArray(payload.can?.dbc_profiles)
          ? payload.can.dbc_profiles.map((item: any) => ({
              path: String(item.path ?? ""),
              name: String(item.name ?? ""),
              messageCount: Number(item.message_count ?? 0),
              signalCount: Number(item.signal_count ?? 0),
            }))
          : [],
        decodedMessageDist: Array.isArray(payload.can?.decoded_message_dist) ? payload.can.decoded_message_dist.map(asBucket) : [],
        decodedSignals: Array.isArray(payload.can?.decoded_signals) ? payload.can.decoded_signals.map(asBucket) : [],
        decodedMessages: Array.isArray(payload.can?.decoded_messages)
          ? payload.can.decoded_messages.map((item: any) => ({
              packetId: Number(item.packet_id ?? 0),
              time: String(item.time ?? ""),
              busId: String(item.bus_id ?? ""),
              identifier: String(item.identifier ?? ""),
              database: String(item.database ?? ""),
              messageName: String(item.message_name ?? ""),
              sender: String(item.sender ?? "") || undefined,
              signals: Array.isArray(item.signals)
                ? item.signals.map((signal: any) => ({
                    name: String(signal.name ?? ""),
                    value: String(signal.value ?? ""),
                    unit: String(signal.unit ?? "") || undefined,
                  }))
                : [],
              summary: String(item.summary ?? ""),
            }))
          : [],
        signalTimelines: Array.isArray(payload.can?.signal_timelines)
          ? payload.can.signal_timelines.map((item: any) => ({
              name: String(item.name ?? ""),
              samples: Array.isArray(item.samples)
                ? item.samples.map((sample: any) => ({
                    packetId: Number(sample.packet_id ?? 0),
                    time: String(sample.time ?? ""),
                    value: Number(sample.value ?? 0),
                    unit: String(sample.unit ?? "") || undefined,
                    messageName: String(sample.message_name ?? "") || undefined,
                  }))
                : [],
            }))
          : [],
          frames: Array.isArray(payload.can?.frames)
            ? payload.can.frames.map((item: any) => ({
                packetId: Number(item.packet_id ?? 0),
                time: String(item.time ?? ""),
                identifier: String(item.identifier ?? ""),
                busId: String(item.bus_id ?? ""),
                length: Number(item.length ?? 0),
                rawData: String(item.raw_data ?? "") || undefined,
                isExtended: Boolean(item.is_extended),
                isRTR: Boolean(item.is_rtr),
                isError: Boolean(item.is_error),
                errorFlags: String(item.error_flags ?? "") || undefined,
                summary: String(item.summary ?? ""),
            }))
          : [],
      },
      j1939: {
        totalMessages: Number(payload.j1939?.total_messages ?? 0),
        pgns: Array.isArray(payload.j1939?.pgns) ? payload.j1939.pgns.map(asBucket) : [],
        sourceAddrs: Array.isArray(payload.j1939?.source_addrs) ? payload.j1939.source_addrs.map(asBucket) : [],
        targetAddrs: Array.isArray(payload.j1939?.target_addrs) ? payload.j1939.target_addrs.map(asBucket) : [],
        messages: Array.isArray(payload.j1939?.messages)
          ? payload.j1939.messages.map((item: any) => ({
              packetId: Number(item.packet_id ?? 0),
              time: String(item.time ?? ""),
              canId: String(item.can_id ?? ""),
              pgn: String(item.pgn ?? ""),
              priority: Number(item.priority ?? 0),
              sourceAddr: String(item.source_addr ?? ""),
              targetAddr: String(item.target_addr ?? ""),
              dataPreview: String(item.data_preview ?? "") || undefined,
              summary: String(item.summary ?? ""),
            }))
          : [],
      },
      doip: {
        totalMessages: Number(payload.doip?.total_messages ?? 0),
        messageTypes: Array.isArray(payload.doip?.message_types) ? payload.doip.message_types.map(asBucket) : [],
        vins: Array.isArray(payload.doip?.vins) ? payload.doip.vins.map(asBucket) : [],
        endpoints: Array.isArray(payload.doip?.endpoints) ? payload.doip.endpoints.map(asBucket) : [],
        messages: Array.isArray(payload.doip?.messages)
          ? payload.doip.messages.map((item: any) => ({
              packetId: Number(item.packet_id ?? 0),
              time: String(item.time ?? ""),
              source: String(item.source ?? ""),
              destination: String(item.destination ?? ""),
              type: String(item.type ?? ""),
              vin: String(item.vin ?? "") || undefined,
              logicalAddress: String(item.logical_address ?? "") || undefined,
              sourceAddress: String(item.source_address ?? "") || undefined,
              targetAddress: String(item.target_address ?? "") || undefined,
              testerAddress: String(item.tester_address ?? "") || undefined,
              responseCode: String(item.response_code ?? "") || undefined,
              diagnosticState: String(item.diagnostic_state ?? "") || undefined,
              summary: String(item.summary ?? ""),
            }))
          : [],
      },
      uds: {
        totalMessages: Number(payload.uds?.total_messages ?? 0),
        serviceIDs: Array.isArray(payload.uds?.service_ids) ? payload.uds.service_ids.map(asBucket) : [],
        negativeCodes: Array.isArray(payload.uds?.negative_codes) ? payload.uds.negative_codes.map(asBucket) : [],
        dtcs: Array.isArray(payload.uds?.dtcs) ? payload.uds.dtcs.map(asBucket) : [],
        vins: Array.isArray(payload.uds?.vins) ? payload.uds.vins.map(asBucket) : [],
        messages: Array.isArray(payload.uds?.messages)
          ? payload.uds.messages.map((item: any) => ({
              packetId: Number(item.packet_id ?? 0),
              time: String(item.time ?? ""),
              serviceId: String(item.service_id ?? ""),
              serviceName: String(item.service_name ?? ""),
              isReply: Boolean(item.is_reply),
              subFunction: String(item.sub_function ?? "") || undefined,
              sourceAddress: String(item.source_address ?? "") || undefined,
              targetAddress: String(item.target_address ?? "") || undefined,
              dataIdentifier: String(item.data_identifier ?? "") || undefined,
              diagnosticVIN: String(item.diagnostic_vin ?? "") || undefined,
              dtc: String(item.dtc ?? "") || undefined,
              negativeCode: String(item.negative_code ?? "") || undefined,
              summary: String(item.summary ?? ""),
            }))
          : [],
        transactions: Array.isArray(payload.uds?.transactions)
          ? payload.uds.transactions.map((item: any) => ({
              requestPacketId: Number(item.request_packet_id ?? 0),
              responsePacketId: Number(item.response_packet_id ?? 0) || undefined,
              requestTime: String(item.request_time ?? ""),
              responseTime: String(item.response_time ?? "") || undefined,
              sourceAddress: String(item.source_address ?? "") || undefined,
              targetAddress: String(item.target_address ?? "") || undefined,
              serviceId: String(item.service_id ?? ""),
              serviceName: String(item.service_name ?? ""),
              subFunction: String(item.sub_function ?? "") || undefined,
              dataIdentifier: String(item.data_identifier ?? "") || undefined,
              dtc: String(item.dtc ?? "") || undefined,
              status: String(item.status ?? ""),
              negativeCode: String(item.negative_code ?? "") || undefined,
              latencyMs: Number(item.latency_ms ?? 0) || undefined,
              requestSummary: String(item.request_summary ?? "") || undefined,
              responseSummary: String(item.response_summary ?? "") || undefined,
            }))
          : [],
      },
      recommendations: Array.isArray(payload.recommendations)
        ? payload.recommendations.map((item: unknown) => String(item ?? ""))
        : [],
    };
  },

  async getMediaAnalysis(forceRefresh = false, signal?: AbortSignal) {
    const payload = await request<any>(forceRefresh ? "/api/analysis/media?refresh=1" : "/api/analysis/media", { signal });
    return {
      totalMediaPackets: Number(payload.total_media_packets ?? 0),
      protocols: Array.isArray(payload.protocols) ? payload.protocols.map(asBucket) : [],
      applications: Array.isArray(payload.applications) ? payload.applications.map(asBucket) : [],
      sessions: Array.isArray(payload.sessions)
        ? payload.sessions.map((item: any) => ({
            id: String(item.id ?? ""),
            mediaType: String(item.media_type ?? ""),
            family: String(item.family ?? ""),
            application: String(item.application ?? ""),
            source: String(item.source ?? ""),
            sourcePort: Number(item.source_port ?? 0),
            destination: String(item.destination ?? ""),
            destinationPort: Number(item.destination_port ?? 0),
            transport: String(item.transport ?? ""),
            ssrc: String(item.ssrc ?? "") || undefined,
            payloadType: String(item.payload_type ?? "") || undefined,
            codec: String(item.codec ?? "") || undefined,
            clockRate: Number(item.clock_rate ?? 0) || undefined,
            startTime: String(item.start_time ?? "") || undefined,
            endTime: String(item.end_time ?? "") || undefined,
            packetCount: Number(item.packet_count ?? 0),
            gapCount: Number(item.gap_count ?? 0),
            controlSummary: String(item.control_summary ?? "") || undefined,
            tags: Array.isArray(item.tags) ? item.tags.map((tag: unknown) => String(tag ?? "")) : [],
            notes: Array.isArray(item.notes) ? item.notes.map((note: unknown) => String(note ?? "")) : [],
            artifact: item.artifact
              ? {
                  token: String(item.artifact.token ?? ""),
                  name: String(item.artifact.name ?? ""),
                  codec: String(item.artifact.codec ?? "") || undefined,
                  format: String(item.artifact.format ?? "") || undefined,
                  sizeBytes: Number(item.artifact.size_bytes ?? 0),
                }
              : undefined,
          }))
        : [],
      notes: Array.isArray(payload.notes) ? payload.notes.map((item: unknown) => String(item ?? "")) : [],
    };
  },

  async transcribeMediaArtifact(token: string, force = false) {
    const payload = await request<any>("/api/analysis/media/transcribe", {
      method: "POST",
      body: JSON.stringify({ token, force }),
    });
    return {
      token: String(payload.token ?? ""),
      sessionId: String(payload.session_id ?? ""),
      title: String(payload.title ?? ""),
      text: String(payload.text ?? ""),
      language: String(payload.language ?? ""),
      engine: String(payload.engine ?? ""),
      status: String(payload.status ?? ""),
      error: String(payload.error ?? "") || undefined,
      cached: Boolean(payload.cached),
      durationSeconds: Number(payload.duration_seconds ?? 0),
      segments: Array.isArray(payload.segments)
        ? payload.segments.map((item: any) => ({
            startSeconds: Number(item.start_seconds ?? 0),
            endSeconds: Number(item.end_seconds ?? 0),
            text: String(item.text ?? ""),
          }))
        : [],
    };
  },

  async startMediaBatchTranscription(force = false) {
    const payload = await request<any>("/api/analysis/media/transcribe/batch", {
      method: "POST",
      body: JSON.stringify({ force }),
    });
    return asSpeechBatchTaskStatus(payload);
  },

  async getMediaBatchTranscriptionStatus() {
    const payload = await request<any>("/api/analysis/media/transcribe/batch");
    return asSpeechBatchTaskStatus(payload);
  },

  async cancelMediaBatchTranscription() {
    const payload = await request<any>("/api/analysis/media/transcribe/batch/cancel", {
      method: "POST",
      body: JSON.stringify({}),
    });
    return asSpeechBatchTaskStatus(payload);
  },

  async exportMediaBatchTranscription(format: "txt" | "json") {
    const blob = await requestBlob(`/api/analysis/media/transcribe/batch/export?format=${encodeURIComponent(format)}`);
    downloadBlob(`media-transcription.${format}`, blob);
  },

  async getUSBAnalysis(signal?: AbortSignal) {
    const payload = await request<any>("/api/analysis/usb", { signal });
    const asUSBPacketRecord = (item: any) => ({
      packetId: Number(item.packet_id ?? 0),
      time: String(item.time ?? ""),
      protocol: String(item.protocol ?? ""),
      busId: String(item.bus_id ?? ""),
      deviceAddress: String(item.device_address ?? ""),
      endpoint: String(item.endpoint ?? ""),
      direction: String(item.direction ?? ""),
      transferType: String(item.transfer_type ?? ""),
      urbType: String(item.urb_type ?? ""),
      status: String(item.status ?? ""),
      dataLength: Number(item.data_length ?? 0),
      setupRequest: String(item.setup_request ?? "") || undefined,
      payloadPreview: String(item.payload_preview ?? "") || undefined,
      summary: String(item.summary ?? ""),
    });
    const asUSBKeyboardEvent = (item: any) => ({
      packetId: Number(item.packet_id ?? 0),
      time: String(item.time ?? ""),
      device: String(item.device ?? ""),
      endpoint: String(item.endpoint ?? ""),
      modifiers: Array.isArray(item.modifiers) ? item.modifiers.map((value: unknown) => String(value ?? "")) : [],
      keys: Array.isArray(item.keys) ? item.keys.map((value: unknown) => String(value ?? "")) : [],
      pressedModifiers: Array.isArray(item.pressed_modifiers) ? item.pressed_modifiers.map((value: unknown) => String(value ?? "")) : [],
      releasedModifiers: Array.isArray(item.released_modifiers) ? item.released_modifiers.map((value: unknown) => String(value ?? "")) : [],
      pressedKeys: Array.isArray(item.pressed_keys) ? item.pressed_keys.map((value: unknown) => String(value ?? "")) : [],
      releasedKeys: Array.isArray(item.released_keys) ? item.released_keys.map((value: unknown) => String(value ?? "")) : [],
      text: String(item.text ?? "") || undefined,
      summary: String(item.summary ?? ""),
    });
    const asUSBMouseEvent = (item: any) => ({
      packetId: Number(item.packet_id ?? 0),
      time: String(item.time ?? ""),
      device: String(item.device ?? ""),
      endpoint: String(item.endpoint ?? ""),
      buttons: Array.isArray(item.buttons) ? item.buttons.map((value: unknown) => String(value ?? "")) : [],
      pressedButtons: Array.isArray(item.pressed_buttons) ? item.pressed_buttons.map((value: unknown) => String(value ?? "")) : [],
      releasedButtons: Array.isArray(item.released_buttons) ? item.released_buttons.map((value: unknown) => String(value ?? "")) : [],
      xDelta: Number(item.x_delta ?? 0),
      yDelta: Number(item.y_delta ?? 0),
      wheelVertical: Number(item.wheel_vertical ?? 0),
      wheelHorizontal: Number(item.wheel_horizontal ?? 0),
      positionX: Number(item.position_x ?? 0),
      positionY: Number(item.position_y ?? 0),
      summary: String(item.summary ?? ""),
    });
    const asUSBMassStorageOperation = (item: any) => ({
      packetId: Number(item.packet_id ?? 0),
      time: String(item.time ?? ""),
      device: String(item.device ?? ""),
      endpoint: String(item.endpoint ?? ""),
      lun: String(item.lun ?? ""),
      command: String(item.command ?? ""),
      operation: String(item.operation ?? "other"),
      transferLength: Number(item.transfer_length ?? 0),
      direction: String(item.direction ?? ""),
      status: String(item.status ?? ""),
      requestFrame: item.request_frame == null ? undefined : Number(item.request_frame),
      responseFrame: item.response_frame == null ? undefined : Number(item.response_frame),
      latencyMs: item.latency_ms == null ? undefined : Number(item.latency_ms),
      dataResidue: item.data_residue == null ? undefined : Number(item.data_residue),
      summary: String(item.summary ?? ""),
    });
    return {
      totalUSBPackets: Number(payload.total_usb_packets ?? 0),
      keyboardPackets: Number(payload.keyboard_packets ?? 0),
      mousePackets: Number(payload.mouse_packets ?? 0),
      otherUSBPackets: Number(payload.other_usb_packets ?? 0),
      hidPackets: Number(payload.hid_packets ?? 0),
      massStoragePackets: Number(payload.mass_storage_packets ?? 0),
      protocols: Array.isArray(payload.protocols) ? payload.protocols.map(asBucket) : [],
      transferTypes: Array.isArray(payload.transfer_types) ? payload.transfer_types.map(asBucket) : [],
      directions: Array.isArray(payload.directions) ? payload.directions.map(asBucket) : [],
      devices: Array.isArray(payload.devices) ? payload.devices.map(asBucket) : [],
      endpoints: Array.isArray(payload.endpoints) ? payload.endpoints.map(asBucket) : [],
      setupRequests: Array.isArray(payload.setup_requests) ? payload.setup_requests.map(asBucket) : [],
      records: Array.isArray(payload.records) ? payload.records.map(asUSBPacketRecord) : [],
      keyboardEvents: Array.isArray(payload.keyboard_events) ? payload.keyboard_events.map(asUSBKeyboardEvent) : [],
      mouseEvents: Array.isArray(payload.mouse_events) ? payload.mouse_events.map(asUSBMouseEvent) : [],
      otherRecords: Array.isArray(payload.other_records) ? payload.other_records.map(asUSBPacketRecord) : [],
      hid: {
        keyboardEvents: Array.isArray(payload.hid?.keyboard_events) ? payload.hid.keyboard_events.map(asUSBKeyboardEvent) : [],
        mouseEvents: Array.isArray(payload.hid?.mouse_events) ? payload.hid.mouse_events.map(asUSBMouseEvent) : [],
        devices: Array.isArray(payload.hid?.devices) ? payload.hid.devices.map(asBucket) : [],
        notes: Array.isArray(payload.hid?.notes) ? payload.hid.notes.map((item: unknown) => String(item ?? "")) : [],
      },
      massStorage: {
        totalPackets: Number(payload.mass_storage?.total_packets ?? 0),
        readPackets: Number(payload.mass_storage?.read_packets ?? 0),
        writePackets: Number(payload.mass_storage?.write_packets ?? 0),
        controlPackets: Number(payload.mass_storage?.control_packets ?? 0),
        devices: Array.isArray(payload.mass_storage?.devices) ? payload.mass_storage.devices.map(asBucket) : [],
        luns: Array.isArray(payload.mass_storage?.luns) ? payload.mass_storage.luns.map(asBucket) : [],
        commands: Array.isArray(payload.mass_storage?.commands) ? payload.mass_storage.commands.map(asBucket) : [],
        readOperations: Array.isArray(payload.mass_storage?.read_operations) ? payload.mass_storage.read_operations.map(asUSBMassStorageOperation) : [],
        writeOperations: Array.isArray(payload.mass_storage?.write_operations) ? payload.mass_storage.write_operations.map(asUSBMassStorageOperation) : [],
        notes: Array.isArray(payload.mass_storage?.notes) ? payload.mass_storage.notes.map((item: unknown) => String(item ?? "")) : [],
      },
      other: {
        totalPackets: Number(payload.other?.total_packets ?? 0),
        controlPackets: Number(payload.other?.control_packets ?? 0),
        devices: Array.isArray(payload.other?.devices) ? payload.other.devices.map(asBucket) : [],
        endpoints: Array.isArray(payload.other?.endpoints) ? payload.other.endpoints.map(asBucket) : [],
        setupRequests: Array.isArray(payload.other?.setup_requests) ? payload.other.setup_requests.map(asBucket) : [],
        controlRecords: Array.isArray(payload.other?.control_records) ? payload.other.control_records.map(asUSBPacketRecord) : [],
        records: Array.isArray(payload.other?.records) ? payload.other.records.map(asUSBPacketRecord) : [],
        notes: Array.isArray(payload.other?.notes) ? payload.other.notes.map((item: unknown) => String(item ?? "")) : [],
      },
      notes: Array.isArray(payload.notes) ? payload.notes.map((item: unknown) => String(item ?? "")) : [],
    };
  },

  async getC2SampleAnalysis(signal?: AbortSignal) {
    const payload = await request<any>("/api/c2-analysis", { signal });
    const asC2Record = (item: any) => ({
      packetId: Number(item.packet_id ?? 0),
      streamId: Number(item.stream_id ?? 0) || undefined,
      time: String(item.time ?? "") || undefined,
      family: String(item.family ?? "cs") === "vshell" ? "vshell" : "cs",
      channel: String(item.channel ?? "") || undefined,
      source: String(item.source ?? "") || undefined,
      destination: String(item.destination ?? "") || undefined,
      host: String(item.host ?? "") || undefined,
      uri: String(item.uri ?? "") || undefined,
      method: String(item.method ?? "") || undefined,
      indicatorType: String(item.indicator_type ?? "") || undefined,
      indicatorValue: String(item.indicator_value ?? "") || undefined,
      confidence: Number(item.confidence ?? 0) || undefined,
      summary: String(item.summary ?? ""),
      evidence: String(item.evidence ?? "") || undefined,
      tags: Array.isArray(item.tags) ? item.tags.map((value: unknown) => String(value ?? "")) : [],
      actorHints: Array.isArray(item.actor_hints) ? item.actor_hints.map((value: unknown) => String(value ?? "")) : [],
      sampleFamily: String(item.sample_family ?? "") || undefined,
      campaignStage: String(item.campaign_stage ?? "") || undefined,
      transportTraits: Array.isArray(item.transport_traits) ? item.transport_traits.map((value: unknown) => String(value ?? "")) : [],
      infrastructureHints: Array.isArray(item.infrastructure_hints) ? item.infrastructure_hints.map((value: unknown) => String(value ?? "")) : [],
      ttpTags: Array.isArray(item.ttp_tags) ? item.ttp_tags.map((value: unknown) => String(value ?? "")) : [],
      attributionConfidence: Number(item.attribution_confidence ?? 0) || undefined,
    });
    const asC2BeaconPattern = (item: any) => ({
      name: String(item.name ?? ""),
      value: String(item.value ?? ""),
      confidence: Number(item.confidence ?? 0) || undefined,
      summary: String(item.summary ?? ""),
    });
    const asC2ScoreFactor = (item: any) => ({
      name: String(item.name ?? ""),
      weight: Number(item.weight ?? 0),
      direction: String(item.direction ?? ""),
      summary: String(item.summary ?? "") || undefined,
    });
    const asC2HTTPEndpointAggregate = (item: any) => ({
      host: String(item.host ?? ""),
      uri: String(item.uri ?? ""),
      channel: String(item.channel ?? "") || undefined,
      total: Number(item.total ?? 0),
      getCount: Number(item.get_count ?? 0),
      postCount: Number(item.post_count ?? 0),
      methods: Array.isArray(item.methods) ? item.methods.map(asBucket) : [],
      firstTime: String(item.first_time ?? "") || undefined,
      lastTime: String(item.last_time ?? "") || undefined,
      avgInterval: String(item.avg_interval ?? "") || undefined,
      jitter: String(item.jitter ?? "") || undefined,
      streams: Array.isArray(item.streams) ? item.streams.map((value: unknown) => Number(value ?? 0)).filter(Boolean) : [],
      packets: Array.isArray(item.packets) ? item.packets.map((value: unknown) => Number(value ?? 0)).filter(Boolean) : [],
      representativePacket: Number(item.representative_packet ?? 0) || undefined,
      confidence: Number(item.confidence ?? 0) || undefined,
      signalTags: Array.isArray(item.signal_tags) ? item.signal_tags.map((value: unknown) => String(value ?? "")) : [],
      scoreFactors: Array.isArray(item.score_factors) ? item.score_factors.map(asC2ScoreFactor) : [],
      summary: String(item.summary ?? ""),
    });
    const asC2DNSAggregate = (item: any) => ({
      qname: String(item.qname ?? ""),
      total: Number(item.total ?? 0),
      maxLabelLength: Number(item.max_label_length ?? 0),
      queryTypes: Array.isArray(item.query_types) ? item.query_types.map(asBucket) : [],
      txtCount: Number(item.txt_count ?? 0),
      nullCount: Number(item.null_count ?? 0),
      cnameCount: Number(item.cname_count ?? 0),
      requestCount: Number(item.request_count ?? 0),
      responseCount: Number(item.response_count ?? 0),
      firstTime: String(item.first_time ?? "") || undefined,
      lastTime: String(item.last_time ?? "") || undefined,
      avgInterval: String(item.avg_interval ?? "") || undefined,
      jitter: String(item.jitter ?? "") || undefined,
      packets: Array.isArray(item.packets) ? item.packets.map((value: unknown) => Number(value ?? 0)).filter(Boolean) : [],
      confidence: Number(item.confidence ?? 0) || undefined,
      summary: String(item.summary ?? ""),
    });
    const asC2StreamAggregate = (item: any) => ({
      streamId: Number(item.stream_id ?? 0),
      protocol: String(item.protocol ?? "") || undefined,
      totalPackets: Number(item.total_packets ?? 0),
      archMarkers: Array.isArray(item.arch_markers) ? item.arch_markers.map(asBucket) : [],
      lengthPrefixCount: Number(item.length_prefix_count ?? 0),
      shortPackets: Number(item.short_packets ?? 0),
      longPackets: Number(item.long_packets ?? 0),
      transitions: Number(item.transitions ?? 0),
      heartbeatAvg: String(item.heartbeat_avg ?? "") || undefined,
      heartbeatJitter: String(item.heartbeat_jitter ?? "") || undefined,
      hasWebSocket: Boolean(item.has_websocket),
      wsParams: String(item.ws_params ?? "") || undefined,
      listenerHints: Array.isArray(item.listener_hints) ? item.listener_hints.map(asBucket) : [],
      firstTime: String(item.first_time ?? "") || undefined,
      lastTime: String(item.last_time ?? "") || undefined,
      packets: Array.isArray(item.packets) ? item.packets.map((value: unknown) => Number(value ?? 0)).filter(Boolean) : [],
      confidence: Number(item.confidence ?? 0) || undefined,
      summary: String(item.summary ?? ""),
    });
    const asC2Family = (item: any) => ({
      candidateCount: Number(item.candidate_count ?? 0),
      matchedRuleCount: Number(item.matched_rule_count ?? 0),
      channels: Array.isArray(item.channels) ? item.channels.map(asBucket) : [],
      indicators: Array.isArray(item.indicators) ? item.indicators.map(asBucket) : [],
      conversations: Array.isArray(item.conversations) ? item.conversations.map(asConversation) : [],
      beaconPatterns: Array.isArray(item.beacon_patterns) ? item.beacon_patterns.map(asC2BeaconPattern) : [],
      hostUriAggregates: Array.isArray(item.host_uri_aggregates) ? item.host_uri_aggregates.map(asC2HTTPEndpointAggregate) : [],
      dnsAggregates: Array.isArray(item.dns_aggregates) ? item.dns_aggregates.map(asC2DNSAggregate) : [],
      streamAggregates: Array.isArray(item.stream_aggregates) ? item.stream_aggregates.map(asC2StreamAggregate) : [],
      candidates: Array.isArray(item.candidates) ? item.candidates.map(asC2Record) : [],
      notes: Array.isArray(item.notes) ? item.notes.map((value: unknown) => String(value ?? "")) : [],
      relatedActors: Array.isArray(item.related_actors) ? item.related_actors.map(asBucket) : [],
      deliveryChains: Array.isArray(item.delivery_chains) ? item.delivery_chains.map(asBucket) : [],
    });
    return {
      totalMatchedPackets: Number(payload.total_matched_packets ?? 0),
      families: Array.isArray(payload.families) ? payload.families.map(asBucket) : [],
      conversations: Array.isArray(payload.conversations) ? payload.conversations.map(asConversation) : [],
      cs: asC2Family(payload.cs ?? {}),
      vshell: asC2Family(payload.vshell ?? {}),
      notes: Array.isArray(payload.notes) ? payload.notes.map((value: unknown) => String(value ?? "")) : [],
    } as C2SampleAnalysis;
  },

  async getAPTAnalysis(signal?: AbortSignal) {
    const payload = await request<any>("/api/apt-analysis", { signal });
    const asAPTRecord = (item: any) => ({
      packetId: Number(item.packet_id ?? 0),
      streamId: Number(item.stream_id ?? 0) || undefined,
      time: String(item.time ?? "") || undefined,
      actorId: String(item.actor_id ?? "") || undefined,
      actorName: String(item.actor_name ?? "") || undefined,
      sourceModule: String(item.source_module ?? "") || undefined,
      family: String(item.family ?? "") || undefined,
      evidenceType: String(item.evidence_type ?? "") || undefined,
      evidenceValue: String(item.evidence_value ?? "") || undefined,
      confidence: Number(item.confidence ?? 0) || undefined,
      source: String(item.source ?? "") || undefined,
      destination: String(item.destination ?? "") || undefined,
      host: String(item.host ?? "") || undefined,
      uri: String(item.uri ?? "") || undefined,
      sampleFamily: String(item.sample_family ?? "") || undefined,
      campaignStage: String(item.campaign_stage ?? "") || undefined,
      transportTraits: Array.isArray(item.transport_traits) ? item.transport_traits.map((value: unknown) => String(value ?? "")) : [],
      infrastructureHints: Array.isArray(item.infrastructure_hints) ? item.infrastructure_hints.map((value: unknown) => String(value ?? "")) : [],
      ttpTags: Array.isArray(item.ttp_tags) ? item.ttp_tags.map((value: unknown) => String(value ?? "")) : [],
      tags: Array.isArray(item.tags) ? item.tags.map((value: unknown) => String(value ?? "")) : [],
      summary: String(item.summary ?? ""),
      evidence: String(item.evidence ?? "") || undefined,
    });
    const asAPTProfile = (item: any) => ({
      id: String(item.id ?? ""),
      name: String(item.name ?? ""),
      aliases: Array.isArray(item.aliases) ? item.aliases.map((value: unknown) => String(value ?? "")) : [],
      summary: String(item.summary ?? ""),
      confidence: Number(item.confidence ?? 0) || undefined,
      evidenceCount: Number(item.evidence_count ?? 0),
      sampleFamilies: Array.isArray(item.sample_families) ? item.sample_families.map(asBucket) : [],
      campaignStages: Array.isArray(item.campaign_stages) ? item.campaign_stages.map(asBucket) : [],
      transportTraits: Array.isArray(item.transport_traits) ? item.transport_traits.map(asBucket) : [],
      infrastructureHints: Array.isArray(item.infrastructure_hints) ? item.infrastructure_hints.map(asBucket) : [],
      relatedC2Families: Array.isArray(item.related_c2_families) ? item.related_c2_families.map(asBucket) : [],
      ttpTags: Array.isArray(item.ttp_tags) ? item.ttp_tags.map(asBucket) : [],
      notes: Array.isArray(item.notes) ? item.notes.map((value: unknown) => String(value ?? "")) : [],
    });
    return {
      totalEvidence: Number(payload.total_evidence ?? 0),
      actors: Array.isArray(payload.actors) ? payload.actors.map(asBucket) : [],
      sampleFamilies: Array.isArray(payload.sample_families) ? payload.sample_families.map(asBucket) : [],
      campaignStages: Array.isArray(payload.campaign_stages) ? payload.campaign_stages.map(asBucket) : [],
      transportTraits: Array.isArray(payload.transport_traits) ? payload.transport_traits.map(asBucket) : [],
      infrastructureHints: Array.isArray(payload.infrastructure_hints) ? payload.infrastructure_hints.map(asBucket) : [],
      relatedC2Families: Array.isArray(payload.related_c2_families) ? payload.related_c2_families.map(asBucket) : [],
      profiles: Array.isArray(payload.profiles) ? payload.profiles.map(asAPTProfile) : [],
      evidence: Array.isArray(payload.evidence) ? payload.evidence.map(asAPTRecord) : [],
      notes: Array.isArray(payload.notes) ? payload.notes.map((value: unknown) => String(value ?? "")) : [],
    } as APTAnalysis;
  },

  async downloadMediaArtifact(token: string, filename: string) {
    const blob = await requestBlob(`/api/analysis/media/export?token=${encodeURIComponent(token)}`);
    downloadBlob(filename, blob);
  },

  async getMediaPlaybackBlob(token: string) {
    return await requestBlob(`/api/analysis/media/play?token=${encodeURIComponent(token)}`);
  },

  async listVehicleDBCProfiles() {
    const rows = await request<any[]>("/api/analysis/vehicle/dbc");
    return rows.map((item) => ({
      path: String(item.path ?? ""),
      name: String(item.name ?? ""),
      messageCount: Number(item.message_count ?? 0),
      signalCount: Number(item.signal_count ?? 0),
    }));
  },

  async addVehicleDBC(path: string) {
    const rows = await request<any[]>("/api/analysis/vehicle/dbc", {
      method: "POST",
      body: JSON.stringify({ path }),
    });
    return rows.map((item) => ({
      path: String(item.path ?? ""),
      name: String(item.name ?? ""),
      messageCount: Number(item.message_count ?? 0),
      signalCount: Number(item.signal_count ?? 0),
    }));
  },

  async removeVehicleDBC(path: string) {
    const rows = await request<any[]>(`/api/analysis/vehicle/dbc?path=${encodeURIComponent(path)}`, {
      method: "DELETE",
    });
    return rows.map((item) => ({
      path: String(item.path ?? ""),
      name: String(item.name ?? ""),
      messageCount: Number(item.message_count ?? 0),
      signalCount: Number(item.signal_count ?? 0),
    }));
  },

  async listPlugins() {
    const rows = await request<any[]>("/api/plugins");
    return rows.map((item) => ({
      id: item.id,
      name: item.name,
      version: item.version,
      tag: item.tag,
      author: item.author,
      enabled: item.enabled,
      entry: item.entry || "",
      runtime: item.runtime || "",
      capabilities: Array.isArray(item.capabilities) ? item.capabilities.map((value: unknown) => String(value ?? "")) : [],
    }));
  },

  async getPluginSource(id: string) {
    const payload = await request<any>(`/api/plugins/source?id=${encodeURIComponent(id)}`);
    return {
      id: String(payload.id ?? id),
      configPath: String(payload.config_path ?? ""),
      configContent: String(payload.config_content ?? ""),
      logicPath: String(payload.logic_path ?? ""),
      logicContent: String(payload.logic_content ?? ""),
      entry: String(payload.entry ?? ""),
    };
  },

  async savePluginSource(source: PluginSource) {
    const payload = await request<any>(`/api/plugins/source`, {
      method: "POST",
      body: JSON.stringify({
        id: source.id,
        config_path: source.configPath,
        config_content: source.configContent,
        logic_path: source.logicPath,
        logic_content: source.logicContent,
        entry: source.entry,
      }),
    });
    return {
      id: String(payload.id ?? source.id),
      configPath: String(payload.config_path ?? ""),
      configContent: String(payload.config_content ?? ""),
      logicPath: String(payload.logic_path ?? ""),
      logicContent: String(payload.logic_content ?? ""),
      entry: String(payload.entry ?? ""),
    };
  },

  async addPlugin(plugin: PluginItem) {
    const item = await request<any>(`/api/plugins/add`, {
      method: "POST",
      body: JSON.stringify({
        id: String(plugin.id),
        name: plugin.name,
        version: plugin.version,
        tag: plugin.tag,
        author: plugin.author,
        enabled: plugin.enabled,
        entry: plugin.entry || "",
        capabilities: Array.isArray(plugin.capabilities) ? plugin.capabilities : [],
      }),
    });
    return {
      id: item.id,
      name: item.name,
      version: item.version,
      tag: item.tag,
      author: item.author,
      enabled: item.enabled,
      entry: item.entry || "",
      runtime: item.runtime || "",
      capabilities: Array.isArray(item.capabilities) ? item.capabilities.map((value: unknown) => String(value ?? "")) : [],
    };
  },

  async deletePlugin(id: string) {
    await request(`/api/plugins/delete?id=${encodeURIComponent(id)}`, { method: "POST" });
  },

  async togglePlugin(id: string) {
    const item = await request<any>(`/api/plugins/toggle?id=${encodeURIComponent(id)}`, { method: "POST" });
    return {
      id: item.id,
      name: item.name,
      version: item.version,
      tag: item.tag,
      author: item.author,
      enabled: item.enabled,
      entry: item.entry || "",
      runtime: item.runtime || "",
      capabilities: Array.isArray(item.capabilities) ? item.capabilities.map((value: unknown) => String(value ?? "")) : [],
    };
  },

  async setPluginsEnabled(ids: string[], enabled: boolean) {
    const rows = await request<any[]>(`/api/plugins/bulk`, {
      method: "POST",
      body: JSON.stringify({ ids, enabled }),
    });
    return rows.map((item) => ({
      id: item.id,
      name: item.name,
      version: item.version,
      tag: item.tag,
      author: item.author,
      enabled: item.enabled,
      entry: item.entry || "",
      runtime: item.runtime || "",
      capabilities: Array.isArray(item.capabilities) ? item.capabilities.map((value: unknown) => String(value ?? "")) : [],
    }));
  },

  async getTLSConfig() {
    try {
      const cfg = await request<any>("/api/tls");
      return {
        sslKeyLogPath: cfg.ssl_key_log_file ?? "",
        privateKeyPath: cfg.rsa_private_key ?? "",
        privateKeyIpPort: cfg.target_ip_port ?? "",
      };
    } catch {
      return null;
    }
  },

  async updateTLSConfig(cfg: DecryptionConfig) {
    await request("/api/tls", {
      method: "POST",
      body: JSON.stringify({
        ssl_key_log_file: cfg.sslKeyLogPath,
        rsa_private_key: cfg.privateKeyPath,
        target_ip_port: cfg.privateKeyIpPort,
      }),
    });
  },

  async runWinRMDecrypt(req: WinRMDecryptRequest) {
    const payload = await request<any>("/api/tools/winrm-decrypt", {
      method: "POST",
      body: JSON.stringify({
        port: req.port,
        auth_mode: req.authMode,
        password: req.password ?? "",
        nt_hash: req.ntHash ?? "",
        preview_lines: req.previewLines ?? 0,
        include_error_frames: Boolean(req.includeErrorFrames),
        extract_command_output: Boolean(req.extractCommandOutput),
      }),
    });
    return {
      resultId: String(payload.result_id ?? ""),
      captureName: String(payload.capture_name ?? ""),
      port: Number(payload.port ?? req.port ?? 0),
      authMode: String(payload.auth_mode ?? ""),
      previewText: String(payload.preview_text ?? ""),
      previewTruncated: Boolean(payload.preview_truncated),
      lineCount: Number(payload.line_count ?? 0),
      frameCount: Number(payload.frame_count ?? 0),
      errorFrameCount: Number(payload.error_frame_count ?? 0),
      extractedFrameCount: Number(payload.extracted_frame_count ?? 0),
      exportFilename: String(payload.export_filename ?? "winrm-decrypt.txt"),
      message: String(payload.message ?? ""),
    };
  },

  async getWinRMDecryptResultText(resultId: string) {
    const response = await fetch(`${API_BASE}/api/tools/winrm-decrypt/export?result_id=${encodeURIComponent(resultId)}`, {
      headers: await buildAuthorizedHeaders(`/api/tools/winrm-decrypt/export?result_id=${encodeURIComponent(resultId)}`),
    });
    if (!response.ok) {
      let message = "获取 WinRM 结果失败";
      try {
        const payload = await response.json();
        message = String(payload.error ?? message);
      } catch {
        // ignore non-json error payload
      }
      throw new Error(message);
    }
    return await response.text();
  },

  async exportWinRMDecryptResult(resultId: string, filename: string) {
    const response = await fetch(`${API_BASE}/api/tools/winrm-decrypt/export?result_id=${encodeURIComponent(resultId)}`, {
      headers: await buildAuthorizedHeaders(`/api/tools/winrm-decrypt/export?result_id=${encodeURIComponent(resultId)}`),
    });
    if (!response.ok) {
      let message = "导出 WinRM 结果失败";
      try {
        const payload = await response.json();
        message = String(payload.error ?? message);
      } catch {
        // ignore non-json error payload
      }
      throw new Error(message);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  },

  async listMiscModules() {
    const rows = await request<any[]>("/api/tools/misc/modules");
    return rows.map((item) => ({
      id: String(item.id ?? ""),
      kind: String(item.kind ?? ""),
      title: String(item.title ?? ""),
      summary: String(item.summary ?? ""),
      tags: Array.isArray(item.tags) ? item.tags.map((tag: any) => String(tag ?? "")) : [],
      apiPrefix: String(item.api_prefix ?? ""),
      docsPath: String(item.docs_path ?? "") || undefined,
      requiresCapture: Boolean(item.requires_capture),
      protocolDomain: String(item.protocol_domain ?? "") || undefined,
      supportsExport: Boolean(item.supports_export),
      cancellable: Boolean(item.cancellable),
      dependsOn: Array.isArray(item.depends_on) ? item.depends_on.map((value: any) => String(value ?? "")) : undefined,
      formSchema: item.form_schema && typeof item.form_schema === "object"
        ? {
            description: String(item.form_schema.description ?? "") || undefined,
            submitLabel: String(item.form_schema.submit_label ?? "") || undefined,
            resultTitle: String(item.form_schema.result_title ?? "") || undefined,
            fields: Array.isArray(item.form_schema.fields)
              ? item.form_schema.fields.map((field: any) => ({
                  name: String(field.name ?? ""),
                  label: String(field.label ?? ""),
                  type: String(field.type ?? "text"),
                  placeholder: String(field.placeholder ?? "") || undefined,
                  defaultValue: String(field.default_value ?? "") || undefined,
                  helpText: String(field.help_text ?? "") || undefined,
                  required: Boolean(field.required),
                  secret: Boolean(field.secret),
                  rows: Number(field.rows ?? 0) || undefined,
                  options: Array.isArray(field.options)
                    ? field.options.map((option: any) => ({
                        value: String(option.value ?? ""),
                        label: String(option.label ?? ""),
                      }))
                    : undefined,
                }))
              : [],
          }
        : undefined,
      interfaceSchema: item.interface_schema && typeof item.interface_schema === "object"
        ? {
            method: String(item.interface_schema.method ?? "") || undefined,
            invokePath: String(item.interface_schema.invoke_path ?? "") || undefined,
            runtime: String(item.interface_schema.runtime ?? "") || undefined,
            entry: String(item.interface_schema.entry ?? "") || undefined,
            hostBridge: Boolean(item.interface_schema.host_bridge),
          }
        : undefined,
    }));
  },

  async importMiscModulePackage(file: File) {
    const form = new FormData();
    form.append("file", file);
    const payload = await request<any>("/api/tools/misc/import", {
      method: "POST",
      body: form,
    });
    return {
      module: {
        id: String(payload.module?.id ?? ""),
        kind: String(payload.module?.kind ?? ""),
        title: String(payload.module?.title ?? ""),
        summary: String(payload.module?.summary ?? ""),
        tags: Array.isArray(payload.module?.tags) ? payload.module.tags.map((tag: unknown) => String(tag ?? "")) : [],
        apiPrefix: String(payload.module?.api_prefix ?? ""),
        docsPath: String(payload.module?.docs_path ?? "") || undefined,
        requiresCapture: Boolean(payload.module?.requires_capture),
        formSchema: payload.module?.form_schema,
        interfaceSchema: payload.module?.interface_schema,
      },
      installedPath: String(payload.installed_path ?? ""),
      message: String(payload.message ?? ""),
    };
  },

  async deleteMiscModule(id: string) {
    await request<any>(`/api/tools/misc/packages/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
  },

  async runMiscModule(id: string, values: Record<string, string>) {
    const payload = await request<any>(`/api/tools/misc/packages/${encodeURIComponent(id)}/invoke`, {
      method: "POST",
      body: JSON.stringify({ values }),
    });
    return {
      message: String(payload.message ?? ""),
      text: String(payload.text ?? "") || undefined,
      output: payload.output,
      table: payload.table && typeof payload.table === "object"
        ? {
            columns: Array.isArray(payload.table.columns)
              ? payload.table.columns.map((column: any) => ({
                  key: String(column.key ?? ""),
                  label: String(column.label ?? ""),
                }))
              : [],
            rows: Array.isArray(payload.table.rows)
              ? payload.table.rows.map((row: any) => {
                  const next: Record<string, string> = {};
                  for (const [key, value] of Object.entries(row ?? {})) {
                    next[String(key)] = String(value ?? "");
                  }
                  return next;
                })
              : [],
          }
        : undefined,
    };
  },

  async listSMB3SessionCandidates() {
    const rows = await request<any[]>("/api/tools/smb3-session-candidates");
    return rows.map((item) => ({
      sessionId: String(item.session_id ?? ""),
      username: String(item.username ?? ""),
      domain: String(item.domain ?? ""),
      ntProofStr: String(item.nt_proof_str ?? ""),
      encryptedSessionKey: String(item.encrypted_session_key ?? ""),
      src: String(item.src ?? ""),
      dst: String(item.dst ?? ""),
      frameNumber: String(item.frame_number ?? ""),
      timestamp: String(item.timestamp ?? ""),
      complete: Boolean(item.complete),
      displayLabel: String(item.display_label ?? ""),
    }));
  },

  async generateSMB3RandomSessionKey(req: SMB3RandomSessionKeyRequest) {
    const payload = await request<any>("/api/tools/smb3-random-session-key", {
      method: "POST",
      body: JSON.stringify({
        username: req.username,
        domain: req.domain,
        ntlm_hash: req.ntlmHash,
        nt_proof_str: req.ntProofStr,
        encrypted_session_key: req.encryptedSessionKey,
      }),
    });
    return {
      randomSessionKey: String(payload.random_session_key ?? ""),
      message: String(payload.message ?? ""),
    };
  },

  async listNTLMSessionMaterials() {
    const payload = await request<any[]>("/api/tools/ntlm-sessions");
    return payload.map((item: any) => ({
      protocol: String(item.protocol ?? ""),
      transport: String(item.transport ?? "") || undefined,
      frameNumber: String(item.frame_number ?? ""),
      timestamp: String(item.timestamp ?? "") || undefined,
      src: String(item.src ?? "") || undefined,
      dst: String(item.dst ?? "") || undefined,
      srcPort: String(item.src_port ?? "") || undefined,
      dstPort: String(item.dst_port ?? "") || undefined,
      direction: String(item.direction ?? "") || undefined,
      username: String(item.username ?? "") || undefined,
      domain: String(item.domain ?? "") || undefined,
      userDisplay: String(item.user_display ?? "") || undefined,
      challenge: String(item.challenge ?? "") || undefined,
      ntProofStr: String(item.nt_proof_str ?? "") || undefined,
      encryptedSessionKey: String(item.encrypted_session_key ?? "") || undefined,
      sessionId: String(item.session_id ?? "") || undefined,
      authHeader: String(item.auth_header ?? "") || undefined,
      wwwAuthenticate: String(item.www_authenticate ?? "") || undefined,
      info: String(item.info ?? "") || undefined,
      complete: Boolean(item.complete),
      displayLabel: String(item.display_label ?? ""),
    })) as NTLMSessionMaterial[];
  },

  async getHTTPLoginAnalysis(signal?: AbortSignal) {
    const payload = await request<any>("/api/tools/http-login-analysis", { signal });
    return {
      totalAttempts: Number(payload.total_attempts ?? 0),
      candidateEndpoints: Number(payload.candidate_endpoints ?? 0),
      successCount: Number(payload.success_count ?? 0),
      failureCount: Number(payload.failure_count ?? 0),
      uncertainCount: Number(payload.uncertain_count ?? 0),
      bruteforceCount: Number(payload.bruteforce_count ?? 0),
      endpoints: Array.isArray(payload.endpoints)
        ? payload.endpoints.map((item: any) => ({
            key: String(item.key ?? ""),
            method: String(item.method ?? "") || undefined,
            host: String(item.host ?? "") || undefined,
            path: String(item.path ?? "") || undefined,
            attemptCount: Number(item.attempt_count ?? 0),
            successCount: Number(item.success_count ?? 0),
            failureCount: Number(item.failure_count ?? 0),
            uncertainCount: Number(item.uncertain_count ?? 0),
            possibleBruteforce: Boolean(item.possible_bruteforce),
            usernameVariants: Number(item.username_variants ?? 0) || undefined,
            passwordAttempts: Number(item.password_attempts ?? 0) || undefined,
            captchaCount: Number(item.captcha_count ?? 0) || undefined,
            setCookieCount: Number(item.set_cookie_count ?? 0) || undefined,
            tokenHintCount: Number(item.token_hint_count ?? 0) || undefined,
            statusCodes: Array.isArray(item.status_codes) ? item.status_codes.map(asBucket) : [],
            requestKeys: Array.isArray(item.request_keys) ? item.request_keys.map((value: any) => String(value ?? "")) : [],
            responseIndicators: Array.isArray(item.response_indicators) ? item.response_indicators.map((value: any) => String(value ?? "")) : [],
            samplePacketIds: Array.isArray(item.sample_packet_ids) ? item.sample_packet_ids.map((value: any) => Number(value ?? 0)).filter((value: number) => value > 0) : [],
            notes: Array.isArray(item.notes) ? item.notes.map((value: any) => String(value ?? "")) : [],
          }))
        : [],
      attempts: Array.isArray(payload.attempts)
        ? payload.attempts.map((item: any) => ({
            packetId: Number(item.packet_id ?? 0),
            responsePacketId: Number(item.response_packet_id ?? 0) || undefined,
            streamId: Number(item.stream_id ?? 0),
            time: String(item.time ?? "") || undefined,
            responseTime: String(item.response_time ?? "") || undefined,
            src: String(item.src ?? "") || undefined,
            dst: String(item.dst ?? "") || undefined,
            method: String(item.method ?? "") || undefined,
            host: String(item.host ?? "") || undefined,
            path: String(item.path ?? "") || undefined,
            endpointLabel: String(item.endpoint_label ?? "") || undefined,
            username: String(item.username ?? "") || undefined,
            passwordPresent: Boolean(item.password_present),
            tokenPresent: Boolean(item.token_present),
            captchaPresent: Boolean(item.captcha_present),
            requestKeys: Array.isArray(item.request_keys) ? item.request_keys.map((value: any) => String(value ?? "")) : [],
            requestContentType: String(item.request_content_type ?? "") || undefined,
            requestPreview: String(item.request_preview ?? "") || undefined,
            statusCode: Number(item.status_code ?? 0) || undefined,
            responseLocation: String(item.response_location ?? "") || undefined,
            responseSetCookie: Boolean(item.response_set_cookie),
            responseTokenHint: Boolean(item.response_token_hint),
            responseIndicators: Array.isArray(item.response_indicators) ? item.response_indicators.map((value: any) => String(value ?? "")) : [],
            responsePreview: String(item.response_preview ?? "") || undefined,
            result: String(item.result ?? "") || undefined,
            reason: String(item.reason ?? "") || undefined,
            possibleBruteforce: Boolean(item.possible_bruteforce),
          }))
        : [],
      notes: Array.isArray(payload.notes) ? payload.notes.map((value: any) => String(value ?? "")) : [],
    } as HTTPLoginAnalysis;
  },

  async getSMTPAnalysis(signal?: AbortSignal) {
    const payload = await request<any>("/api/tools/smtp-analysis", { signal });
    return {
      sessionCount: Number(payload.session_count ?? 0),
      messageCount: Number(payload.message_count ?? 0),
      authCount: Number(payload.auth_count ?? 0),
      attachmentHintCount: Number(payload.attachment_hint_count ?? 0),
      sessions: Array.isArray(payload.sessions)
        ? payload.sessions.map((item: any) => ({
            streamId: Number(item.stream_id ?? 0),
            client: String(item.client ?? "") || undefined,
            server: String(item.server ?? "") || undefined,
            clientPort: Number(item.client_port ?? 0) || undefined,
            serverPort: Number(item.server_port ?? 0) || undefined,
            helo: String(item.helo ?? "") || undefined,
            authMechanisms: Array.isArray(item.auth_mechanisms) ? item.auth_mechanisms.map((value: any) => String(value ?? "")) : [],
            authUsername: String(item.auth_username ?? "") || undefined,
            authPasswordSeen: Boolean(item.auth_password_seen),
            mailFrom: Array.isArray(item.mail_from) ? item.mail_from.map((value: any) => String(value ?? "")) : [],
            rcptTo: Array.isArray(item.rcpt_to) ? item.rcpt_to.map((value: any) => String(value ?? "")) : [],
            commandCount: Number(item.command_count ?? 0),
            messageCount: Number(item.message_count ?? 0),
            attachmentHints: Number(item.attachment_hints ?? 0),
            commands: Array.isArray(item.commands)
              ? item.commands.map((row: any) => ({
                  packetId: Number(row.packet_id ?? 0),
                  time: String(row.time ?? "") || undefined,
                  direction: String(row.direction ?? "") || undefined,
                  command: String(row.command ?? "") || undefined,
                  argument: String(row.argument ?? "") || undefined,
                  statusCode: Number(row.status_code ?? 0) || undefined,
                  summary: String(row.summary ?? "") || undefined,
                }))
              : [],
            statusHints: Array.isArray(item.status_hints) ? item.status_hints.map((value: any) => String(value ?? "")) : [],
            messages: Array.isArray(item.messages)
              ? item.messages.map((row: any) => ({
                  sequence: Number(row.sequence ?? 0),
                  mailFrom: String(row.mail_from ?? "") || undefined,
                  rcptTo: Array.isArray(row.rcpt_to) ? row.rcpt_to.map((value: any) => String(value ?? "")) : [],
                  subject: String(row.subject ?? "") || undefined,
                  from: String(row.from ?? "") || undefined,
                  to: String(row.to ?? "") || undefined,
                  date: String(row.date ?? "") || undefined,
                  contentType: String(row.content_type ?? "") || undefined,
                  boundary: String(row.boundary ?? "") || undefined,
                  attachmentNames: Array.isArray(row.attachment_names) ? row.attachment_names.map((value: any) => String(value ?? "")) : [],
                  bodyPreview: String(row.body_preview ?? "") || undefined,
                  packetIds: Array.isArray(row.packet_ids) ? row.packet_ids.map((value: any) => Number(value ?? 0)).filter((value: number) => value > 0) : [],
                }))
              : [],
            possibleCleartext: Boolean(item.possible_cleartext),
          }))
        : [],
      notes: Array.isArray(payload.notes) ? payload.notes.map((value: any) => String(value ?? "")) : [],
    } as SMTPAnalysis;
  },

  async getMySQLAnalysis(signal?: AbortSignal) {
    const payload = await request<any>("/api/tools/mysql-analysis", { signal });
    return {
      sessionCount: Number(payload.session_count ?? 0),
      loginCount: Number(payload.login_count ?? 0),
      queryCount: Number(payload.query_count ?? 0),
      errorCount: Number(payload.error_count ?? 0),
      resultsetCount: Number(payload.resultset_count ?? 0),
      sessions: Array.isArray(payload.sessions)
        ? payload.sessions.map((item: any) => ({
            streamId: Number(item.stream_id ?? 0),
            client: String(item.client ?? "") || undefined,
            server: String(item.server ?? "") || undefined,
            clientPort: Number(item.client_port ?? 0) || undefined,
            serverPort: Number(item.server_port ?? 0) || undefined,
            serverVersion: String(item.server_version ?? "") || undefined,
            connectionId: Number(item.connection_id ?? 0) || undefined,
            username: String(item.username ?? "") || undefined,
            database: String(item.database ?? "") || undefined,
            authPlugin: String(item.auth_plugin ?? "") || undefined,
            loginPacketId: Number(item.login_packet_id ?? 0) || undefined,
            loginSuccess: item.login_packet_id ? Boolean(item.login_success) : undefined,
            queryCount: Number(item.query_count ?? 0),
            okCount: Number(item.ok_count ?? 0),
            errCount: Number(item.err_count ?? 0),
            resultsetCount: Number(item.resultset_count ?? 0),
            commandTypes: Array.isArray(item.command_types) ? item.command_types.map((value: any) => String(value ?? "")) : [],
            queries: Array.isArray(item.queries)
              ? item.queries.map((row: any) => ({
                  packetId: Number(row.packet_id ?? 0),
                  time: String(row.time ?? "") || undefined,
                  command: String(row.command ?? "") || undefined,
                  sql: String(row.sql ?? "") || undefined,
                  database: String(row.database ?? "") || undefined,
                  responsePacketId: Number(row.response_packet_id ?? 0) || undefined,
                  responseKind: String(row.response_kind ?? "") || undefined,
                  responseCode: Number(row.response_code ?? 0) || undefined,
                  responseSummary: String(row.response_summary ?? "") || undefined,
                }))
              : [],
            serverEvents: Array.isArray(item.server_events)
              ? item.server_events.map((row: any) => ({
                  packetId: Number(row.packet_id ?? 0),
                  time: String(row.time ?? "") || undefined,
                  sequence: Number(row.sequence ?? 0) || undefined,
                  kind: String(row.kind ?? "") || undefined,
                  code: Number(row.code ?? 0) || undefined,
                  summary: String(row.summary ?? "") || undefined,
                }))
              : [],
            notes: Array.isArray(item.notes) ? item.notes.map((value: any) => String(value ?? "")) : [],
          }))
        : [],
      notes: Array.isArray(payload.notes) ? payload.notes.map((value: any) => String(value ?? "")) : [],
    } as MySQLAnalysis;
  },

  async getShiroRememberMeAnalysis(candidateKeys?: string[], signal?: AbortSignal) {
    const payload = await request<any>("/api/tools/shiro-rememberme", {
      method: "POST",
      signal,
      body: JSON.stringify({
        candidate_keys: Array.isArray(candidateKeys) ? candidateKeys : [],
      }),
    });
    return {
      candidateCount: Number(payload.candidate_count ?? 0),
      hitCount: Number(payload.hit_count ?? 0),
      candidates: Array.isArray(payload.candidates)
        ? payload.candidates.map((item: any) => ({
            packetId: Number(item.packet_id ?? 0),
            streamId: Number(item.stream_id ?? 0) || undefined,
            time: String(item.time ?? "") || undefined,
            src: String(item.src ?? "") || undefined,
            dst: String(item.dst ?? "") || undefined,
            host: String(item.host ?? "") || undefined,
            path: String(item.path ?? "") || undefined,
            sourceHeader: String(item.source_header ?? "") || undefined,
            cookieName: String(item.cookie_name ?? "") || undefined,
            cookieValue: String(item.cookie_value ?? "") || undefined,
            cookiePreview: String(item.cookie_preview ?? "") || undefined,
            decodeOK: Boolean(item.decode_ok),
            encryptedLength: Number(item.encrypted_length ?? 0) || undefined,
            aesBlockAligned: Boolean(item.aes_block_aligned),
            possibleCBC: Boolean(item.possible_cbc),
            possibleGCM: Boolean(item.possible_gcm),
            keyResults: Array.isArray(item.key_results)
              ? item.key_results.map((row: any) => ({
                  label: String(row.label ?? ""),
                  base64: String(row.base64 ?? "") || undefined,
                  algorithm: String(row.algorithm ?? "") || undefined,
                  hit: Boolean(row.hit),
                  payloadClass: String(row.payload_class ?? "") || undefined,
                  preview: String(row.preview ?? "") || undefined,
                  reason: String(row.reason ?? "") || undefined,
                }))
              : [],
            hitCount: Number(item.hit_count ?? 0) || undefined,
            notes: Array.isArray(item.notes) ? item.notes.map((value: any) => String(value ?? "")) : [],
          }))
        : [],
      notes: Array.isArray(payload.notes) ? payload.notes.map((value: any) => String(value ?? "")) : [],
    } as ShiroRememberMeAnalysis;
  },

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

function asBucket(input: any) {
  return {
    label: String(input.label ?? ""),
    count: Number(input.count ?? 0),
  };
}

function asSpeechBatchTaskStatus(input: any): SpeechBatchTaskStatus {
  return {
    taskId: String(input.task_id ?? ""),
    total: Number(input.total ?? 0),
    queued: Number(input.queued ?? 0),
    running: Number(input.running ?? 0),
    completed: Number(input.completed ?? 0),
    failed: Number(input.failed ?? 0),
    skipped: Number(input.skipped ?? 0),
    currentToken: String(input.current_token ?? "") || undefined,
    currentLabel: String(input.current_label ?? "") || undefined,
    done: Boolean(input.done),
    cancelled: Boolean(input.cancelled),
    items: Array.isArray(input.items)
      ? input.items.map((item: any) => ({
          token: String(item.token ?? ""),
          sessionId: String(item.session_id ?? ""),
          mediaLabel: String(item.media_label ?? ""),
          title: String(item.title ?? ""),
          status: String(item.status ?? "queued") as SpeechBatchTaskStatus["items"][number]["status"],
          error: String(item.error ?? "") || undefined,
          cached: Boolean(item.cached),
          text: String(item.text ?? "") || undefined,
        }))
      : [],
  };
}

function asToolRuntimeSnapshot(input: any): ToolRuntimeSnapshot {
  return {
    config: {
      tsharkPath: String(input?.config?.tshark_path ?? ""),
      ffmpegPath: String(input?.config?.ffmpeg_path ?? ""),
      pythonPath: String(input?.config?.python_path ?? ""),
      voskModelPath: String(input?.config?.vosk_model_path ?? ""),
      yaraEnabled: Boolean(input?.config?.yara_enabled),
      yaraBin: String(input?.config?.yara_bin ?? ""),
      yaraRules: String(input?.config?.yara_rules ?? ""),
      yaraTimeoutMs: Number(input?.config?.yara_timeout_ms ?? 0) || 25000,
    },
    tshark: {
      available: Boolean(input?.tshark?.available),
      path: String(input?.tshark?.path ?? ""),
      message: String(input?.tshark?.message ?? ""),
      customPath: String(input?.tshark?.custom_path ?? "") || undefined,
      usingCustomPath: Boolean(input?.tshark?.using_custom_path),
    },
    ffmpeg: {
      available: Boolean(input?.ffmpeg?.available),
      path: String(input?.ffmpeg?.path ?? ""),
      message: String(input?.ffmpeg?.message ?? ""),
      customPath: String(input?.ffmpeg?.custom_path ?? "") || undefined,
      usingCustomPath: Boolean(input?.ffmpeg?.using_custom_path),
    },
    speech: {
      available: Boolean(input?.speech?.available),
      engine: String(input?.speech?.engine ?? ""),
      language: String(input?.speech?.language ?? ""),
      pythonAvailable: Boolean(input?.speech?.python_available),
      pythonCommand: String(input?.speech?.python_command ?? "") || undefined,
      ffmpegAvailable: Boolean(input?.speech?.ffmpeg_available),
      voskAvailable: Boolean(input?.speech?.vosk_available),
      modelAvailable: Boolean(input?.speech?.model_available),
      modelPath: String(input?.speech?.model_path ?? "") || undefined,
      message: String(input?.speech?.message ?? ""),
    },
    yara: {
      available: Boolean(input?.yara?.available),
      enabled: Boolean(input?.yara?.enabled),
      path: String(input?.yara?.path ?? "") || undefined,
      rulePath: String(input?.yara?.rule_path ?? "") || undefined,
      message: String(input?.yara?.message ?? ""),
      lastScanMessage: String(input?.yara?.last_scan_message ?? "") || undefined,
      customBin: String(input?.yara?.custom_bin ?? "") || undefined,
      customRules: String(input?.yara?.custom_rules ?? "") || undefined,
      usingCustomBin: Boolean(input?.yara?.using_custom_bin),
      usingCustomRules: Boolean(input?.yara?.using_custom_rules),
      timeoutMs: Number(input?.yara?.timeout_ms ?? 0) || 25000,
    },
  };
}

function asConversation(input: any) {
  return {
    label: String(input.label ?? ""),
    protocol: String(input.protocol ?? "") || undefined,
    count: Number(input.count ?? 0),
  };
}

async function selectLocalFile(): Promise<File> {
  if (typeof document === "undefined") {
    throw new Error("当前环境不支持文件选择");
  }

  return new Promise<File>((resolve, reject) => {
    let settled = false;
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".pcap,.pcapng,.cap";
    input.style.display = "none";

    const cleanup = () => {
      if (input.parentNode) {
        input.parentNode.removeChild(input);
      }
    };

    input.onchange = () => {
      const file = input.files?.[0];
      cleanup();
      if (!file) {
        settled = true;
        reject(new Error("未选择文件"));
        return;
      }
      settled = true;
      resolve(file);
    };

    document.body.appendChild(input);
    input.click();

    const onFocus = () => {
      window.setTimeout(() => {
        if (!settled) {
          settled = true;
          cleanup();
          reject(new Error("已取消文件选择"));
        }
      }, 300);
      window.removeEventListener("focus", onFocus);
    };

    window.addEventListener("focus", onFocus);

    window.setTimeout(() => {
      if (!settled && (!input.files || input.files.length === 0)) {
        settled = true;
        window.removeEventListener("focus", onFocus);
        cleanup();
        reject(new Error("文件选择超时"));
      }
    }, 120000);
  });
}
