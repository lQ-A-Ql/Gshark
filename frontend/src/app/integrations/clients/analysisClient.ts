import type {
  APTAnalysis,
  C2SampleAnalysis,
  GlobalTrafficStats,
  IndustrialAnalysis,
  UnifiedEvidenceRecord,
  USBAnalysis,
  USBHIDSourceMode,
  VehicleAnalysis,
} from "../../core/types";
import { asAPTAnalysis } from "../mappers/aptMapper";
import { asC2SampleAnalysis } from "../mappers/c2SampleMapper";
import { parseEvidenceRecords } from "../mappers/evidenceMapper";
import { asIndustrialAnalysis } from "../mappers/industrialMapper";
import { asGlobalTrafficStats } from "../mappers/trafficMapper";
import { asUSBAnalysis } from "../mappers/usbMapper";
import { asVehicleAnalysis } from "../mappers/vehicleMapper";
import type { EvidenceListWireDTO } from "../wire/evidenceWireDtos";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;
export type AnalysisRequestOptions = { source?: "user" | "warmup" };

export interface AnalysisClient {
  getGlobalTrafficStats(signal?: AbortSignal): Promise<GlobalTrafficStats>;
  getIndustrialAnalysis(signal?: AbortSignal, options?: AnalysisRequestOptions): Promise<IndustrialAnalysis>;
  getVehicleAnalysis(signal?: AbortSignal, options?: AnalysisRequestOptions): Promise<VehicleAnalysis>;
  getUSBAnalysis(
    signal?: AbortSignal,
    hidSource?: USBHIDSourceMode,
    hidEventLimit?: number,
    options?: AnalysisRequestOptions,
  ): Promise<USBAnalysis>;
  getC2SampleAnalysis(signal?: AbortSignal, options?: AnalysisRequestOptions): Promise<C2SampleAnalysis>;
  getAPTAnalysis(signal?: AbortSignal): Promise<APTAnalysis>;
  getEvidence(signal?: AbortSignal): Promise<UnifiedEvidenceRecord[]>;
  getEvidenceWithFilter(modules?: string[], signal?: AbortSignal): Promise<UnifiedEvidenceRecord[]>;
}

export function createAnalysisClient(request: JsonRequest): AnalysisClient {
  return {
    async getGlobalTrafficStats(signal?: AbortSignal) {
      const payload = await request<unknown>("/api/stats/traffic/global", { signal });
      return asGlobalTrafficStats(payload);
    },

    async getIndustrialAnalysis(signal?: AbortSignal, options?: AnalysisRequestOptions) {
      const payload = await request<unknown>(withAnalysisRequestOptions("/api/analysis/industrial", options), {
        signal,
      });
      return asIndustrialAnalysis(payload);
    },

    async getVehicleAnalysis(signal?: AbortSignal, options?: AnalysisRequestOptions) {
      const payload = await request<unknown>(withAnalysisRequestOptions("/api/analysis/vehicle", options), { signal });
      return asVehicleAnalysis(payload);
    },

    async getUSBAnalysis(
      signal?: AbortSignal,
      hidSource: USBHIDSourceMode = "auto",
      hidEventLimit = 20000,
      options?: AnalysisRequestOptions,
    ) {
      const params = new URLSearchParams();
      params.set("hid_source", hidSource);
      params.set("hid_event_limit", String(hidEventLimit));
      appendAnalysisRequestOptions(params, options);
      const payload = await request<unknown>(`/api/analysis/usb?${params.toString()}`, { signal });
      return asUSBAnalysis(payload);
    },

    async getC2SampleAnalysis(signal?: AbortSignal, options?: AnalysisRequestOptions) {
      const payload = await request<unknown>(withAnalysisRequestOptions("/api/c2-analysis", options), { signal });
      return asC2SampleAnalysis(payload);
    },

    async getAPTAnalysis(signal?: AbortSignal) {
      const payload = await request<unknown>("/api/apt-analysis", { signal });
      return asAPTAnalysis(payload);
    },

    async getEvidence(signal?: AbortSignal) {
      const payload = await request<EvidenceListWireDTO>("/api/evidence", { signal });
      return parseEvidenceRecords(payload);
    },

    async getEvidenceWithFilter(modules?: string[], signal?: AbortSignal) {
      const params = new URLSearchParams();
      if (modules && modules.length > 0) {
        params.set("modules", modules.join(","));
      }
      const qs = params.toString();
      const path = qs ? `/api/evidence?${qs}` : "/api/evidence";
      const payload = await request<EvidenceListWireDTO>(path, { signal });
      return parseEvidenceRecords(payload);
    },
  };
}

function withAnalysisRequestOptions(path: string, options?: AnalysisRequestOptions) {
  const params = new URLSearchParams();
  appendAnalysisRequestOptions(params, options);
  const qs = params.toString();
  if (!qs) return path;
  return `${path}${path.includes("?") ? "&" : "?"}${qs}`;
}

function appendAnalysisRequestOptions(params: URLSearchParams, options?: AnalysisRequestOptions) {
  if (options?.source === "warmup") {
    params.set("warmup", "1");
  }
}
