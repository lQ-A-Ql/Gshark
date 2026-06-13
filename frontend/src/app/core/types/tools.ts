import type { SpeechToTextStatus } from "./media";
import type { KnownOrUnknown } from "./unknownEnum";

export interface ToolRuntimeConfig {
  tsharkPath: string;
  ffmpegPath: string;
  pythonPath: string;
  voskModelPath: string;
  yaraEnabled: boolean;
  yaraBin: string;
  yaraRules: string;
  yaraTimeoutMs: number;
}

export interface MCPConfig {
  enabled: boolean;
}

export interface MCPStatus {
  config: MCPConfig;
  enabled: boolean;
  endpoint: string;
  transport: string;
  authRequired: boolean;
  readOnly: boolean;
  remoteSupported: boolean;
  stdioSupported: boolean;
  lastError?: string;
}

export type ToolRuntimeProbeMode = "fast" | "full";
export type ToolRuntimeProbeState =
  | "fast_ready"
  | "full_ready"
  | "partial"
  | "timeout"
  | "failed"
  | "background_probing";

export interface YaraToolStatus {
  available: boolean;
  enabled: boolean;
  path?: string;
  rulePath?: string;
  message: string;
  lastScanMessage?: string;
  customBin?: string;
  customRules?: string;
  usingCustomBin: boolean;
  usingCustomRules: boolean;
  timeoutMs: number;
}

export interface ToolRuntimeSnapshot {
  config: ToolRuntimeConfig;
  tshark: {
    available: boolean;
    path: string;
    message: string;
    customPath?: string;
    usingCustomPath: boolean;
    version?: string;
    fieldProfile?: string;
    fieldCount?: number;
    missingRequiredFields?: string[];
    missingOptionalFields?: string[];
    capabilityMessage?: string;
    capabilityCheckDegraded?: boolean;
  };
  ffmpeg: {
    available: boolean;
    path: string;
    message: string;
    customPath?: string;
    usingCustomPath: boolean;
  };
  speech: SpeechToTextStatus;
  yara: YaraToolStatus;
  probeMode?: KnownOrUnknown<ToolRuntimeProbeMode>;
  probeState?: KnownOrUnknown<ToolRuntimeProbeState>;
  probeTimings?: Record<string, number>;
  probeErrors?: Record<string, string>;
  cached?: boolean;
  updatedAt?: string;
  transport?: "desktop-ipc" | "http-fallback" | "unknown";
  transportError?: string;
}

export interface DNSTunnelHit {
  baseDomain: string;
  queryCount: number;
  uniqueSubdomains: number;
  avgSubdomainLen: number;
  maxPayloadSize: number;
  entropyScore: number;
  confidence: number;
  firstPacketId: number;
  evidence: string;
}

export interface UDPTunnelHit {
  source: string;
  destination: string;
  port: number;
  packetCount: number;
  bytesTotal: number;
  avgPayloadLen: number;
  stddevLen: number;
  durationSec: number;
  confidence: number;
  firstPacketId: number;
  protocol: string;
}

export interface UDPTunnelAnalysis {
  totalSuspicious: number;
  dnsTunnelHits: DNSTunnelHit[];
  udpTunnelHits: UDPTunnelHit[];
  notes: string[];
}

export interface PortScanHit {
  sourceIp: string;
  targetIp: string;
  uniquePortsHit: number;
  synCount: number;
  rstCount: number;
  openPorts: number[];
  durationSec: number;
  scanType: string;
  confidence: number;
  firstPacketId: number;
}

export interface DirBruteforceHit {
  sourceIp: string;
  targetHost: string;
  totalRequests: number;
  status404Count: number;
  status403Count: number;
  status200Count: number;
  uniquePaths: number;
  requestsPerSec: number;
  samplePaths: string[];
  confidence: number;
  firstPacketId: number;
}

export interface BruteforceAnalysis {
  totalSuspicious: number;
  portScanHits: PortScanHit[];
  dirBruteforceHits: DirBruteforceHit[];
  notes: string[];
}
