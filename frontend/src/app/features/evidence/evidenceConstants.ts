import type { EvidenceSeverity } from "./evidenceSchema";

export const EVIDENCE_MODULE_OPTIONS = [
  { value: "hunting", label: "威胁狩猎" },
  { value: "c2", label: "C2 分析" },
  { value: "apt", label: "APT 画像" },
  { value: "industrial", label: "工控分析" },
  { value: "object", label: "对象导出" },
  { value: "vehicle", label: "车机分析" },
  { value: "usb", label: "USB 分析" },
  { value: "media", label: "媒体分析" },
  { value: "misc", label: "MISC 分析" },
] as const;

export const EVIDENCE_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export const EVIDENCE_CONFIDENCE_LABELS = ["high", "medium", "low", "unknown"] as const;
export const EVIDENCE_VISIBLE_PAGE_SIZE = 200;
export const VERSION_UNAVAILABLE_LABEL = "未提供";
export const IOC_API_UNAVAILABLE_LABEL = "IOC API unavailable";
export const CHINA_CHOPPER_LABEL = "菜刀 / China Chopper";

export const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export interface EvidenceFacetState {
  sourceTypes: string[];
  features: string[];
  entities: string[];
  confidenceLabels: string[];
}

export interface EvidenceFacetOption {
  value: string;
  label: string;
  count: number;
}

export interface EvidenceFacetGroups {
  sourceTypes: EvidenceFacetOption[];
  features: EvidenceFacetOption[];
  entities: EvidenceFacetOption[];
  confidenceLabels: EvidenceFacetOption[];
}

export interface EvidenceSummaryMetrics {
  totalRecords: number;
  visibleRecords: number;
  moduleCount: number;
  criticalHighCount: number;
  mappedPacketCount: number;
  mappedStreamCount: number;
}

export type EvidenceSeverityFilter = EvidenceSeverity | "all";
