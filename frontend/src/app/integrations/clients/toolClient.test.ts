import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  downloadBlob: vi.fn(),
}));

vi.mock("../../utils/browserFile", () => ({
  downloadBlob: mocks.downloadBlob,
}));

import { createToolClient } from "./toolClient";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;
type TextRequest = (path: string, init?: RequestInit) => Promise<string>;
type BlobRequest = (path: string, init?: RequestInit) => Promise<Blob>;

const noopTextRequest = vi.fn(async () => "") as unknown as TextRequest;
const noopBlobRequest = vi.fn(async () => new Blob()) as unknown as BlobRequest;

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
    const result = await createToolClient(request, noopTextRequest, noopBlobRequest).runWinRMDecrypt({
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
    const textRequest = vi.fn(async (path: string) => {
      expect(path).toBe("/api/tools/winrm-decrypt/export?result_id=res-1");
      return "plain text";
    }) as unknown as TextRequest;

    await expect(
      createToolClient(request, textRequest, noopBlobRequest).getWinRMDecryptResultText("res-1"),
    ).resolves.toBe("plain text");
  });

  it("exports WinRM result blobs and surfaces text errors", async () => {
    const request = vi.fn() as unknown as JsonRequest;
    const blob = new Blob(["zip"]);
    const blobRequest = vi.fn(async () => blob) as unknown as BlobRequest;
    const textRequest = vi.fn(async () => {
      throw new Error("no result");
    }) as unknown as TextRequest;
    const client = createToolClient(request, textRequest, blobRequest);

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
    const client = createToolClient(request, noopTextRequest, noopBlobRequest);

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
      createToolClient(request, noopTextRequest, noopBlobRequest).getShiroRememberMeAnalysis(["k1", "k2"], signal),
    ).resolves.toMatchObject({
      candidateCount: 2,
      hitCount: 1,
      notes: ["shiro"],
    });
  });
});

describe("toolClient SMB3 and NTLM methods", () => {
  it("lists SMB3 session candidates and NTLM session materials", async () => {
    const request = vi.fn(async (path: string) => {
      switch (path) {
        case "/api/tools/smb3-session-candidates":
          return [{ session_id: "smb-1", username: "alice", nt_proof_str: "proof", complete: true }];
        case "/api/tools/ntlm-sessions":
          return [{ protocol: "HTTP", frame_number: "42", username: "bob", complete: true }];
        default:
          throw new Error(`unexpected path: ${path}`);
      }
    }) as unknown as JsonRequest;
    const client = createToolClient(request, noopTextRequest, noopBlobRequest);

    await expect(client.listSMB3SessionCandidates()).resolves.toMatchObject([
      { sessionId: "smb-1", username: "alice", ntProofStr: "proof", complete: true },
    ]);
    await expect(client.listNTLMSessionMaterials()).resolves.toMatchObject([
      { protocol: "HTTP", frameNumber: "42", username: "bob", complete: true },
    ]);
  });

  it("posts SMB3 session key inputs and maps random session key results", async () => {
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      expect(path).toBe("/api/tools/smb3-random-session-key");
      expect(init?.method).toBe("POST");
      expect(JSON.parse(String(init?.body))).toEqual({
        username: "alice",
        domain: "LAB",
        ntlm_hash: "hash",
        nt_proof_str: "proof",
        encrypted_session_key: "esk",
      });
      return { random_session_key: "rsk", message: "ok" };
    }) as unknown as JsonRequest;

    await expect(
      createToolClient(request, noopTextRequest, noopBlobRequest).generateSMB3RandomSessionKey({
        username: "alice",
        domain: "LAB",
        ntlmHash: "hash",
        ntProofStr: "proof",
        encryptedSessionKey: "esk",
      }),
    ).resolves.toEqual({ randomSessionKey: "rsk", message: "ok" });
  });
});

describe("toolClient MISC module methods", () => {
  it("lists, imports, deletes, and invokes MISC modules", async () => {
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      switch (path) {
        case "/api/tools/misc/modules":
          return [
            {
              id: "decoder",
              title: "Decoder",
              api_prefix: "/api/tools/misc/decoder",
              tags: ["misc"],
              form_schema: { fields: [{ name: "payload", label: "Payload" }] },
            },
          ];
        case "/api/tools/misc/import":
          expect(init?.method).toBe("POST");
          expect(init?.body).toBeInstanceOf(FormData);
          expect((init?.body as FormData).get("file")).toBeInstanceOf(File);
          return { module: { id: "custom" }, installed_path: "plugins/custom", message: "installed" };
        case "/api/tools/misc/packages/module%2F1":
          expect(init?.method).toBe("DELETE");
          return {};
        case "/api/tools/misc/packages/module%2F1/invoke":
          expect(init?.method).toBe("POST");
          expect(JSON.parse(String(init?.body))).toEqual({ values: { payload: "abc" } });
          return { message: "done", text: "decoded" };
        default:
          throw new Error(`unexpected path: ${path}`);
      }
    }) as unknown as JsonRequest;
    const client = createToolClient(request, noopTextRequest, noopBlobRequest);

    await expect(client.listMiscModules()).resolves.toMatchObject([
      { id: "decoder", title: "Decoder", apiPrefix: "/api/tools/misc/decoder", tags: ["misc"] },
    ]);
    await expect(client.importMiscModulePackage(new File(["zip"], "module.zip"))).resolves.toMatchObject({
      module: { id: "custom" },
      installedPath: "plugins/custom",
      message: "installed",
    });
    await expect(client.deleteMiscModule("module/1")).resolves.toBeUndefined();
    await expect(client.runMiscModule("module/1", { payload: "abc" })).resolves.toMatchObject({
      message: "done",
      text: "decoded",
    });
  });
});
