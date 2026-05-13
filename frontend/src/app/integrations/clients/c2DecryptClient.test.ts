import { describe, expect, it, vi } from "vitest";

import { createC2DecryptClient } from "./c2DecryptClient";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

describe("c2DecryptClient", () => {
  it("posts scoped VShell decrypt requests and maps result payloads", async () => {
    const signal = new AbortController().signal;
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      expect(path).toBe("/api/c2-analysis/decrypt");
      expect(init?.method).toBe("POST");
      expect(init?.signal).toBe(signal);
      expect(JSON.parse(String(init?.body))).toEqual({
        family: "vshell",
        scope: { packet_ids: [1], stream_ids: [2], use_candidates: true, use_aggregates: false },
        vshell: { vkey: "fallsnow", salt: "paperplane", mode: "auto" },
      });
      return {
        family: "vshell",
        status: "completed",
        total_candidates: 1,
        decrypted_count: 1,
        failed_count: 0,
        records: [{ packet_id: 1, plaintext_preview: "hacked_by_fallsnow&paperplane(QAQ)", confidence: 95 }],
        notes: ["ok"],
      };
    }) as unknown as JsonRequest;

    const result = await createC2DecryptClient(request).decryptC2Traffic(
      {
        family: "vshell",
        scope: { packetIds: [1], streamIds: [2], useCandidates: true, useAggregates: false },
        vshell: { vkey: "fallsnow", salt: "paperplane", mode: "auto" },
      },
      signal,
    );

    expect(result).toMatchObject({ family: "vshell", status: "completed", decryptedCount: 1, notes: ["ok"] });
    expect(result.records[0]).toMatchObject({
      packetId: 1,
      plaintextPreview: "hacked_by_fallsnow&paperplane(QAQ)",
      confidence: 95,
    });
  });

  it("posts CS keyed decrypt requests and falls back to requested family", async () => {
    const request = vi.fn(async (_path: string, init?: RequestInit) => {
      expect(JSON.parse(String(init?.body))).toMatchObject({
        family: "cs",
        cs: { key_mode: "aes_hmac", aes_key: "aa", hmac_key: "bb", transform_mode: "raw" },
      });
      return { status: "failed", records: "bad", notes: ["missing key"] };
    }) as unknown as JsonRequest;

    const result = await createC2DecryptClient(request).decryptC2Traffic({
      family: "cs",
      cs: { keyMode: "aes_hmac", aesKey: "aa", hmacKey: "bb", transformMode: "raw" },
    });

    expect(result).toMatchObject({ family: "cs", status: "failed", records: [], notes: ["missing key"] });
  });
});
