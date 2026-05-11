import type {
  APTAnalysis,
  C2SampleAnalysis,
  GlobalTrafficStats,
  IndustrialAnalysis,
  UnifiedEvidenceRecord,
  USBAnalysis,
  VehicleAnalysis,
} from "../../core/types";
import { asAPTAnalysis } from "../mappers/aptMapper";
import { asC2SampleAnalysis } from "../mappers/c2SampleMapper";
import { parseEvidenceRecords } from "../mappers/evidenceMapper";
import { asIndustrialAnalysis } from "../mappers/industrialMapper";
import { asGlobalTrafficStats } from "../mappers/trafficMapper";
import { asUSBAnalysis } from "../mappers/usbMapper";
import { asVehicleAnalysis } from "../mappers/vehicleMapper";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

export interface AnalysisClient {
  getGlobalTrafficStats(signal?: AbortSignal): Promise<GlobalTrafficStats>;
  getIndustrialAnalysis(signal?: AbortSignal): Promise<IndustrialAnalysis>;
  getVehicleAnalysis(signal?: AbortSignal): Promise<VehicleAnalysis>;
  getUSBAnalysis(signal?: AbortSignal): Promise<USBAnalysis>;
  getC2SampleAnalysis(signal?: AbortSignal): Promise<C2SampleAnalysis>;
  getAPTAnalysis(signal?: AbortSignal): Promise<APTAnalysis>;
  getEvidence(signal?: AbortSignal): Promise<UnifiedEvidenceRecord[]>;
  getEvidenceWithFilter(modules?: string[], signal?: AbortSignal): Promise<UnifiedEvidenceRecord[]>;
}

export function createAnalysisClient(request: JsonRequest): AnalysisClient {
  return {
    async getGlobalTrafficStats(signal?: AbortSignal) {
      const payload = await request<any>("/api/stats/traffic/global", { signal });
      return asGlobalTrafficStats(payload);
    },

    async getIndustrialAnalysis(signal?: AbortSignal) {
      const payload = await request<any>("/api/analysis/industrial", { signal });
      return asIndustrialAnalysis(payload);
    },

    async getVehicleAnalysis(signal?: AbortSignal) {
      const payload = await request<any>("/api/analysis/vehicle", { signal });
      return asVehicleAnalysis(payload);
    },

    async getUSBAnalysis(signal?: AbortSignal) {
      const payload = await request<any>("/api/analysis/usb", { signal });
      return asUSBAnalysis(payload);
    },

    async getC2SampleAnalysis(signal?: AbortSignal) {
      const payload = await request<any>("/api/c2-analysis", { signal });
      return asC2SampleAnalysis(payload);
    },

    async getAPTAnalysis(signal?: AbortSignal) {
      const payload = await request<any>("/api/apt-analysis", { signal });
      return asAPTAnalysis(payload);
    },

    async getEvidence(signal?: AbortSignal) {
      const payload = await request<any>("/api/evidence", { signal });
      return parseEvidenceRecords(payload);
    },

    async getEvidenceWithFilter(modules?: string[], signal?: AbortSignal) {
      const params = new URLSearchParams();
      if (modules && modules.length > 0) {
        params.set("modules", modules.join(","));
      }
      const qs = params.toString();
      const path = qs ? `/api/evidence?${qs}` : "/api/evidence";
      const payload = await request<any>(path, { signal });
      return parseEvidenceRecords(payload);
    },
  };
}
