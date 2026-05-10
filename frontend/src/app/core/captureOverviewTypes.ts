import type {
  ExtractedObject,
  GlobalTrafficStats,
  IndustrialAnalysis,
  MediaAnalysis,
  Packet,
  ThreatHit,
  TrafficBucket,
  USBAnalysis,
  VehicleAnalysis,
} from "./types";

export type CaptureModuleKey = "web" | "industrial" | "vehicle" | "usb" | "media" | "payload";

export interface CaptureQuickFilter {
  label: string;
  filter: string;
  reason: string;
}

export interface CaptureRecommendation {
  key: CaptureModuleKey;
  label: string;
  route: string;
  summary: string;
  score: number;
  filter?: string;
}

export interface CaptureOverviewSnapshot {
  headline: string;
  summary: string;
  topProtocols: TrafficBucket[];
  quickFilters: CaptureQuickFilter[];
  recommendations: CaptureRecommendation[];
  suspiciousHits: ThreatHit[];
}

export interface CaptureOverviewInput {
  stats: GlobalTrafficStats | null;
  packets: Packet[];
  threatHits: ThreatHit[];
  extractedObjects: ExtractedObject[];
  streamIds: { http: number[]; tcp: number[]; udp: number[] };
  industrial: IndustrialAnalysis | null;
  vehicle: VehicleAnalysis | null;
  media: MediaAnalysis | null;
  usb: USBAnalysis | null;
}

export interface CaptureOverviewCounts {
  suspicious: number;
  highRisk: number;
  httpStreams: number;
  tcpStreams: number;
  udpStreams: number;
  objects: number;
  industrial: number;
  vehicle: number;
  usb: number;
  media: number;
}
