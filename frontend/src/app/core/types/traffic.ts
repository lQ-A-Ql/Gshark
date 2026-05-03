import type { StreamChunk, StreamLoadMeta } from "./stream";

export interface HttpStream {
  id: number;
  client: string;
  server: string;
  request: string;
  response: string;
  chunks: StreamChunk[];
  loadMeta?: StreamLoadMeta;
}

export interface BinaryStream {
  id: number;
  protocol: "TCP" | "UDP";
  from: string;
  to: string;
  chunks: StreamChunk[];
  nextCursor?: number;
  totalChunks?: number;
  hasMore?: boolean;
  loadMeta?: StreamLoadMeta;
}

export type StreamProtocol = "HTTP" | "TCP" | "UDP";

export interface StreamSwitchStat {
  count: number;
  lastMs: number;
  p50Ms: number;
  p95Ms: number;
  cacheHitRate: number;
}

export interface StreamSwitchMetrics {
  overall: StreamSwitchStat;
  byProtocol: Record<StreamProtocol, StreamSwitchStat>;
}

export interface PluginItem {
  id: number | string;
  name: string;
  tag: string;
  author: string;
  version: string;
  enabled: boolean;
  entry?: string;
  runtime?: string;
  capabilities?: string[];
}

export interface DecryptionConfig {
  sslKeyLogPath: string;
  privateKeyPath: string;
  privateKeyIpPort: string;
}

export interface RecentCapture {
  path: string;
  name: string;
  sizeBytes: number;
  lastOpenedAt: string;
}

export interface AppUpdateAsset {
  name: string;
  downloadUrl: string;
  sizeBytes: number;
  contentType?: string;
}

export interface AppUpdateStatus {
  currentVersion: string;
  currentVersionDisplay: string;
  currentVersionSource: string;
  currentExecutable: string;
  localHash: string;
  repo: string;
  authMode: string;
  checkedAt: string;
  apiUrl: string;
  hasUpdate: boolean;
  upToDate: boolean;
  hashMismatch: boolean;
  latestTag: string;
  latestName: string;
  latestPublishedAt: string;
  releaseUrl: string;
  releaseNotes: string;
  selectedAsset?: AppUpdateAsset;
  canInstall: boolean;
  message: string;
}

export interface TrafficBucket {
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

export interface AnalysisConversation {
  label: string;
  protocol?: string;
  count: number;
}
