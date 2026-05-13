import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  downloadBlob: vi.fn(),
}));

vi.mock("../../utils/browserFile", () => ({
  downloadBlob: mocks.downloadBlob,
}));

import { createToolClient } from "./toolClient";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;
type BuildHeaders = (path: string, headersInit?: HeadersInit, body?: BodyInit | null) => Promise<Headers>;

describe("toolClient WinRM methods", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    mocks.downloadBlob.mockReset();
  });

  it("posts WinRM decrypt requests and maps result payloads", async () => {
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      expect(path).toBe("/api/tools/winrm-decrypt");
      expect(init?.method).toBe("POST");
      expect(JSON.parse(String(init?.body))).toEqual({
        port: 5985,
        auth_mode: "nt_hash",
        password: "",
        nt_hash: "hash",
        preview_lines: 8,
        include_error_frames: true,
        extract_command_output: false,
      });
      return {
        result_id: "res-1",
        capture_name: "case.pcap",
        auth_mode: "nt_hash",
        preview_text: "whoami",
        export_filename: "winrm.txt",
      };
    }) as unknown as JsonRequest;
    const buildHeaders = vi.fn() as unknown as BuildHeaders;

    const result = await createToolClient(request, "http://127.0.0.1", buildHeaders).runWinRMDecrypt({
      port: 5985,
      authMode: "nt_hash",
      ntHash: "hash",
      previewLines: 8,
      includeErrorFrames: true,
      extractCommandOutput: false,
    });

    expect(result).toMatchObject({
      resultId: "res-1",
      captureName: "case.pcap",
      port: 5985,
      authMode: "nt_hash",
      previewText: "whoami",
      exportFilename: "winrm.txt",
    });
  });

  it("fetches WinRM result text with auth headers", async () => {
    const request = vi.fn() as unknown as JsonRequest;
    const buildHeaders = vi.fn(async (path: string) => {
      expect(path).toBe("/api/tools/winrm-decrypt/export?result_id=res-1");
      return new Headers({ Authorization: "Bearer token" });
    }) as unknown as BuildHeaders;
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toBe("http://127.0.0.1/api/tools/winrm-decrypt/export?result_id=res-1");
      expect((init?.headers as Headers).get("Authorization")).toBe("Bearer token");
      return new Response("plain text", { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      createToolClient(request, "http://127.0.0.1", buildHeaders).getWinRMDecryptResultText("res-1"),
    ).resolves.toBe("plain text");
  });

  it("exports WinRM result blobs and surfaces JSON errors", async () => {
    const request = vi.fn() as unknown as JsonRequest;
    const buildHeaders = vi.fn(async () => new Headers()) as unknown as BuildHeaders;
    const blob = new Blob(["zip"]);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(blob, { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: "no result" }), { status: 404 }));
    vi.stubGlobal("fetch", fetchMock);
    const client = createToolClient(request, "http://127.0.0.1", buildHeaders);

    await expect(client.exportWinRMDecryptResult("res-1", "winrm.txt")).resolves.toBeUndefined();
    expect(mocks.downloadBlob).toHaveBeenCalledWith("winrm.txt", expect.any(Blob));
    await expect(client.getWinRMDecryptResultText("missing")).rejects.toThrow("no result");
  });
});

describe("toolClient protocol analysis methods", () => {
  it("fetches protocol GET analyses with abort signals and maps payloads", async () => {
    const signal = new AbortController().signal;
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      expect(init?.signal).toBe(signal);
      switch (path) {
        case "/api/tools/http-login-analysis":
          return { total_attempts: 2, candidate_endpoints: 1, notes: ["http"] };
        case "/api/tools/smtp-analysis":
          return { session_count: 1, auth_count: 1, notes: ["smtp"] };
        case "/api/tools/mysql-analysis":
          return { session_count: 1, query_count: 3, notes: ["mysql"] };
        default:
          throw new Error(`unexpected path: ${path}`);
      }
    }) as unknown as JsonRequest;
    const client = createToolClient(request, "http://127.0.0.1", vi.fn() as unknown as BuildHeaders);

    await expect(client.getHTTPLoginAnalysis(signal)).resolves.toMatchObject({
      totalAttempts: 2,
      candidateEndpoints: 1,
      notes: ["http"],
    });
    await expect(client.getSMTPAnalysis(signal)).resolves.toMatchObject({
      sessionCount: 1,
      authCount: 1,
      notes: ["smtp"],
    });
    await expect(client.getMySQLAnalysis(signal)).resolves.toMatchObject({
      sessionCount: 1,
      queryCount: 3,
      notes: ["mysql"],
    });
  });

  it("posts Shiro rememberMe candidate keys and maps payloads", async () => {
    const signal = new AbortController().signal;
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      expect(path).toBe("/api/tools/shiro-rememberme");
      expect(init?.method).toBe("POST");
      expect(init?.signal).toBe(signal);
      expect(JSON.parse(String(init?.body))).toEqual({ candidate_keys: ["k1", "k2"] });
      return { candidate_count: 2, hit_count: 1, notes: ["shiro"] };
    }) as unknown as JsonRequest;

    await expect(
      createToolClient(request, "http://127.0.0.1", vi.fn() as unknown as BuildHeaders).getShiroRememberMeAnalysis(
        ["k1", "k2"],
        signal,
      ),
    ).resolves.toMatchObject({
      candidateCount: 2,
      hitCount: 1,
      notes: ["shiro"],
    });
  });
});
