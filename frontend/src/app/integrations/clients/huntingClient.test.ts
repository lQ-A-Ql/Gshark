import { describe, expect, it, vi } from "vitest";

import { createHuntingClient } from "./huntingClient";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

describe("huntingClient", () => {
  it("encodes prefixes and maps threat hits from transport payloads", async () => {
    const request = vi.fn(async (path: string) => {
      expect(path).toBe("/api/hunting?prefix=flag%7B&prefix=ctf%7B");
      return [
        {
          id: 7,
          packet_id: 99,
          category: "CTF",
          rule: "Flag 嗅探",
          level: "high",
          preview: "flag{demo}",
          match: "flag{",
        },
      ];
    }) as unknown as JsonRequest;

    const client = createHuntingClient(request);
    const hits = await client.listThreatHits(["flag{", "ctf{"]);

    expect(hits).toEqual([
      {
        id: 7,
        packetId: 99,
        category: "CTF",
        rule: "Flag 嗅探",
        level: "high",
        preview: "flag{demo}",
        match: "flag{",
      },
    ]);
  });

  it("maps runtime config and update payload shape", async () => {
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      if (path === "/api/hunting/config" && !init) {
        return {
          prefixes: ["flag{", "ctf{"],
          yara_enabled: false,
          yara_bin: "C:/Tools/yara.exe",
          yara_rules: "C:/rules",
          yara_timeout_ms: 15000,
        };
      }
      expect(path).toBe("/api/hunting/config");
      expect(init?.method).toBe("POST");
      expect(init?.body).toBe(
        JSON.stringify({
          prefixes: ["flag{"],
          yara_enabled: true,
          yara_bin: "",
          yara_rules: "",
          yara_timeout_ms: 25000,
        }),
      );
      return {
        prefixes: ["flag{"],
        yara_enabled: true,
        yara_bin: "",
        yara_rules: "",
        yara_timeout_ms: 25000,
      };
    }) as unknown as JsonRequest;

    const client = createHuntingClient(request);
    const config = await client.getHuntingRuntimeConfig();
    const saved = await client.updateHuntingRuntimeConfig({
      prefixes: ["flag{"],
      yaraEnabled: true,
      yaraBin: "",
      yaraRules: "",
      yaraTimeoutMs: 25000,
    });

    expect(config).toEqual({
      prefixes: ["flag{", "ctf{"],
      yaraEnabled: false,
      yaraBin: "C:/Tools/yara.exe",
      yaraRules: "C:/rules",
      yaraTimeoutMs: 15000,
    });
    expect(saved).toEqual({
      prefixes: ["flag{"],
      yaraEnabled: true,
      yaraBin: "",
      yaraRules: "",
      yaraTimeoutMs: 25000,
    });
  });
});
