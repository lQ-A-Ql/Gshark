import type { ThreatHit } from "../../core/types";
import { asPlainObject } from "../mappers/mapperPrimitives";
import { asThreatHit } from "../mappers/packetStreamMapper";
import type { HuntingRuntimeConfigWireDTO, ThreatHitWireDTO } from "../wire/huntingWireDtos";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

export interface HuntingRuntimeConfig {
  prefixes: string[];
  yaraEnabled: boolean;
  yaraBin: string;
  yaraRules: string;
  yaraTimeoutMs: number;
}

export interface HuntingClient {
  listThreatHits(prefixes?: string[], signal?: AbortSignal): Promise<ThreatHit[]>;
  getHuntingRuntimeConfig(): Promise<HuntingRuntimeConfig>;
  updateHuntingRuntimeConfig(config: HuntingRuntimeConfig): Promise<HuntingRuntimeConfig>;
}

function asHuntingRuntimeConfig(input: unknown): HuntingRuntimeConfig {
  const payload: HuntingRuntimeConfigWireDTO | undefined = asPlainObject(input);
  const prefixes = Array.isArray(payload?.prefixes)
    ? payload.prefixes.map((p: unknown) => String(p ?? "").trim()).filter(Boolean)
    : [];
  const yaraTimeoutMs = Number(payload?.yara_timeout_ms ?? 25000);
  return {
    prefixes,
    yaraEnabled: Boolean(payload?.yara_enabled ?? true),
    yaraBin: String(payload?.yara_bin ?? ""),
    yaraRules: String(payload?.yara_rules ?? ""),
    yaraTimeoutMs: Number.isFinite(yaraTimeoutMs) ? yaraTimeoutMs : 25000,
  };
}

export function createHuntingClient(request: JsonRequest): HuntingClient {
  return {
    async listThreatHits(prefixes = ["flag{", "ctf{"], signal?: AbortSignal) {
      const query = prefixes.map((p) => `prefix=${encodeURIComponent(p)}`).join("&");
      const rows = await request<ThreatHitWireDTO[]>(`/api/hunting?${query}`, { signal });
      return rows.map(asThreatHit);
    },

    async getHuntingRuntimeConfig() {
      const payload = await request<HuntingRuntimeConfigWireDTO>("/api/hunting/config");
      return asHuntingRuntimeConfig(payload);
    },

    async updateHuntingRuntimeConfig(config: HuntingRuntimeConfig) {
      const payload = await request<HuntingRuntimeConfigWireDTO>("/api/hunting/config", {
        method: "POST",
        body: JSON.stringify({
          prefixes: config.prefixes,
          yara_enabled: config.yaraEnabled,
          yara_bin: config.yaraBin,
          yara_rules: config.yaraRules,
          yara_timeout_ms: config.yaraTimeoutMs,
        }),
      });
      return asHuntingRuntimeConfig(payload);
    },
  };
}
