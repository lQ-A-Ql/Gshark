import type { C2DecryptRequest, C2DecryptResult } from "../../core/types";
import { asC2DecryptedRecord } from "../mappers/c2DecryptMapper";
import { normalizeC2DecryptResultForDisplay } from "../mappers/c2DecryptDisplayMapper";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

export interface C2DecryptClient {
  decryptC2Traffic(req: C2DecryptRequest, signal?: AbortSignal): Promise<C2DecryptResult>;
}

export function createC2DecryptClient(request: JsonRequest): C2DecryptClient {
  return {
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
  };
}
