import type {
  AuditEntry,
  BinaryStream,
  DBCProfile,
  DecryptionConfig,
  ExtractedObject,
  HttpStream,
  IndustrialAnalysis,
  MediaAnalysis,
  Packet,
  PluginItem,
  StreamDecodeResult,
  ThreatHit,
  USBAnalysis,
  VehicleAnalysis,
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

interface TrafficBucket {
  label: string;
  count: number;
}

export interface GlobalTrafficStats {
  totalPackets: number;
  protocolKinds: number;
  timeline: TrafficBucket[];
  protocolDist: TrafficBucket[];
  topTalkers: TrafficBucket[];
  topHostnames: TrafficBucket[];
  topDomains: TrafficBucket[];
  topSrcIPs: TrafficBucket[];
  topDstIPs: TrafficBucket[];
  topComputerNames: TrafficBucket[];
  topDestPorts: TrafficBucket[];
  topSrcPorts: TrafficBucket[];
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
  checkTShark(): Promise<TSharkStatus>;
  setTSharkPath(path: string): Promise<TSharkStatus>;
  openPcapFile(): Promise<OpenFileResult>;
  startStreamingPackets(filePath: string, filter: string): Promise<void>;
  stopStreamingPackets(): Promise<void>;
  listPackets(): Promise<Packet[]>;
  listPacketsPage(cursor: number, limit: number, filter?: string): Promise<PacketsPageResult>;
  locatePacketPage(packetId: number, limit: number, filter?: string): Promise<PacketLocateResult>;
  listThreatHits(prefixes?: string[]): Promise<ThreatHit[]>;
  getHuntingRuntimeConfig(): Promise<HuntingRuntimeConfig>;
  updateHuntingRuntimeConfig(config: HuntingRuntimeConfig): Promise<HuntingRuntimeConfig>;
  listObjects(): Promise<ExtractedObject[]>;
  getHttpStream(streamId: number, signal?: AbortSignal): Promise<HttpStream>;
  getRawStream(protocol: "TCP" | "UDP", streamId: number, signal?: AbortSignal): Promise<BinaryStream>;
  getRawStreamPage(protocol: "TCP" | "UDP", streamId: number, cursor: number, limit: number, signal?: AbortSignal): Promise<BinaryStream>;
  decodeStreamPayload(decoder: string, payload: string, options?: Record<string, unknown>): Promise<StreamDecodeResult>;
  updateStreamPayloads(protocol: "HTTP" | "TCP" | "UDP", streamId: number, patches: Array<{ index: number; body: string }>, signal?: AbortSignal): Promise<HttpStream | BinaryStream>;
  listStreamIds(protocol: "HTTP" | "TCP" | "UDP"): Promise<number[]>;
  getPacketRawHex(packetId: number): Promise<string>;
  getPacketLayers(packetId: number): Promise<Record<string, unknown> | null>;
  getGlobalTrafficStats(): Promise<GlobalTrafficStats>;
  getIndustrialAnalysis(): Promise<IndustrialAnalysis>;
  getVehicleAnalysis(): Promise<VehicleAnalysis>;
  getMediaAnalysis(): Promise<MediaAnalysis>;
  getUSBAnalysis(): Promise<USBAnalysis>;
  downloadMediaArtifact(token: string, filename: string): Promise<void>;
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
  listAuditLogs(): Promise<AuditEntry[]>;
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
    try {
      await request<{ status: string }>("/health");
      return true;
    } catch {
      return false;
    }
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

  async listPackets() {
    const rows = await request<any[]>("/api/packets");
    return rows.map(asPacket);
  },

  async listPacketsPage(cursor: number, limit: number, filter = "") {
    const query = new URLSearchParams({
      cursor: String(cursor),
      limit: String(limit),
    });
    if (filter.trim()) {
      query.set("filter", filter);
    }
    const payload = await request<any>(`/api/packets/page?${query.toString()}`);
    const rows = Array.isArray(payload.items) ? payload.items : [];
    return {
      items: rows.map(asPacket),
      nextCursor: Number(payload.next_cursor ?? rows.length),
      total: Number(payload.total ?? rows.length),
      hasMore: Boolean(payload.has_more),
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

  async listThreatHits(prefixes = ["flag{", "ctf{"]) {
    const query = prefixes.map((p) => `prefix=${encodeURIComponent(p)}`).join("&");
    const rows = await request<any[]>(`/api/hunting?${query}`);
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

  async listObjects() {
    const rows = await request<any[]>("/api/objects");
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

  async decodeStreamPayload(decoder: string, payload: string, options: Record<string, unknown> = {}) {
    const result = await request<any>("/api/streams/decode", {
      method: "POST",
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
    };
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

  async getGlobalTrafficStats() {
    const payload = await request<any>("/api/stats/traffic/global");
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

  async getIndustrialAnalysis() {
    const payload = await request<any>("/api/analysis/industrial");
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
              summary: String(item.summary ?? ""),
            }))
          : [],
      },
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

  async getVehicleAnalysis() {
    const payload = await request<any>("/api/analysis/vehicle");
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

  async getMediaAnalysis() {
    const payload = await request<any>("/api/analysis/media");
    return {
      totalMediaPackets: Number(payload.total_media_packets ?? 0),
      protocols: Array.isArray(payload.protocols) ? payload.protocols.map(asBucket) : [],
      applications: Array.isArray(payload.applications) ? payload.applications.map(asBucket) : [],
      sessions: Array.isArray(payload.sessions)
        ? payload.sessions.map((item: any) => ({
            id: String(item.id ?? ""),
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

  async getUSBAnalysis() {
    const payload = await request<any>("/api/analysis/usb");
    return {
      totalUSBPackets: Number(payload.total_usb_packets ?? 0),
      keyboardPackets: Number(payload.keyboard_packets ?? 0),
      mousePackets: Number(payload.mouse_packets ?? 0),
      otherUSBPackets: Number(payload.other_usb_packets ?? 0),
      protocols: Array.isArray(payload.protocols) ? payload.protocols.map(asBucket) : [],
      transferTypes: Array.isArray(payload.transfer_types) ? payload.transfer_types.map(asBucket) : [],
      directions: Array.isArray(payload.directions) ? payload.directions.map(asBucket) : [],
      devices: Array.isArray(payload.devices) ? payload.devices.map(asBucket) : [],
      endpoints: Array.isArray(payload.endpoints) ? payload.endpoints.map(asBucket) : [],
      setupRequests: Array.isArray(payload.setup_requests) ? payload.setup_requests.map(asBucket) : [],
      records: Array.isArray(payload.records)
        ? payload.records.map((item: any) => ({
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
          }))
        : [],
      keyboardEvents: Array.isArray(payload.keyboard_events)
        ? payload.keyboard_events.map((item: any) => ({
            packetId: Number(item.packet_id ?? 0),
            time: String(item.time ?? ""),
            device: String(item.device ?? ""),
            endpoint: String(item.endpoint ?? ""),
            modifiers: Array.isArray(item.modifiers) ? item.modifiers.map((value: unknown) => String(value ?? "")) : [],
            keys: Array.isArray(item.keys) ? item.keys.map((value: unknown) => String(value ?? "")) : [],
            text: String(item.text ?? "") || undefined,
            summary: String(item.summary ?? ""),
          }))
        : [],
      mouseEvents: Array.isArray(payload.mouse_events)
        ? payload.mouse_events.map((item: any) => ({
            packetId: Number(item.packet_id ?? 0),
            time: String(item.time ?? ""),
            device: String(item.device ?? ""),
            endpoint: String(item.endpoint ?? ""),
            buttons: Array.isArray(item.buttons) ? item.buttons.map((value: unknown) => String(value ?? "")) : [],
            xDelta: Number(item.x_delta ?? 0),
            yDelta: Number(item.y_delta ?? 0),
            wheelVertical: Number(item.wheel_vertical ?? 0),
            wheelHorizontal: Number(item.wheel_horizontal ?? 0),
            positionX: Number(item.position_x ?? 0),
            positionY: Number(item.position_y ?? 0),
            summary: String(item.summary ?? ""),
          }))
        : [],
      otherRecords: Array.isArray(payload.other_records)
        ? payload.other_records.map((item: any) => ({
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
          }))
        : [],
      notes: Array.isArray(payload.notes) ? payload.notes.map((item: unknown) => String(item ?? "")) : [],
    };
  },

  async downloadMediaArtifact(token: string, filename: string) {
    const blob = await requestBlob(`/api/analysis/media/export?token=${encodeURIComponent(token)}`);
    downloadBlob(filename, blob);
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

  async listAuditLogs() {
    const rows = await request<any[]>("/api/audit/logs");
    return rows.map((item) => ({
      time: String(item.time ?? ""),
      method: String(item.method ?? ""),
      path: String(item.path ?? ""),
      action: String(item.action ?? ""),
      risk: String(item.risk ?? "low"),
      origin: String(item.origin ?? "") || undefined,
      remoteAddr: String(item.remote_addr ?? "") || undefined,
      status: Number(item.status ?? 0),
      authenticated: Boolean(item.authenticated),
    }));
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
