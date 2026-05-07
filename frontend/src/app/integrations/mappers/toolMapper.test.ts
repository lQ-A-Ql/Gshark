import { describe, expect, it } from "vitest";
import {
  asMiscModuleImportResult,
  asMiscModuleManifests,
  asMiscModuleRunResult,
  asNTLMSessionMaterials,
  asSMB3RandomSessionKeyResult,
  asSMB3SessionCandidates,
  asWinRMDecryptResult,
} from "./toolMapper";

describe("toolMapper", () => {
  it("maps WinRM decrypt result with fallback port", () => {
    expect(asWinRMDecryptResult({ result_id: "r1", preview_text: "ok", frame_count: 2 }, 5985)).toMatchObject({
      resultId: "r1",
      port: 5985,
      previewText: "ok",
      frameCount: 2,
      exportFilename: "winrm-decrypt.txt",
    });
  });

  it("maps misc module manifests with form and interface schemas", () => {
    const [module] = asMiscModuleManifests([
      {
        id: "payload-decoder",
        kind: "decoder",
        title: "Payload Decoder",
        tags: ["misc", 1],
        api_prefix: "/api/tools/misc/payload",
        requires_capture: true,
        supports_export: true,
        depends_on: ["python"],
        form_schema: {
          description: "Decode payload",
          submit_label: "Run",
          fields: [
            {
              name: "payload",
              label: "Payload",
              type: "textarea",
              default_value: "abc",
              rows: 5,
              required: true,
              options: [{ value: "auto", label: "Auto" }],
            },
          ],
        },
        interface_schema: {
          method: "POST",
          invoke_path: "/invoke",
          runtime: "python",
          host_bridge: true,
        },
      },
    ]);

    expect(module).toMatchObject({
      id: "payload-decoder",
      tags: ["misc", "1"],
      requiresCapture: true,
      supportsExport: true,
      dependsOn: ["python"],
      formSchema: {
        submitLabel: "Run",
        fields: [{ name: "payload", rows: 5, required: true, options: [{ value: "auto", label: "Auto" }] }],
      },
      interfaceSchema: { method: "POST", runtime: "python", hostBridge: true },
    });
  });

  it("maps misc import and run results", () => {
    expect(
      asMiscModuleImportResult({ module: { id: "m1" }, installed_path: "plugins/m1", message: "ok" }),
    ).toMatchObject({
      module: { id: "m1" },
      installedPath: "plugins/m1",
      message: "ok",
    });

    expect(
      asMiscModuleRunResult({
        message: "done",
        text: "hello",
        table: {
          columns: [{ key: "k", label: "Key" }],
          rows: [{ k: "v", n: 2 }],
        },
      }),
    ).toMatchObject({
      message: "done",
      text: "hello",
      table: { columns: [{ key: "k", label: "Key" }], rows: [{ k: "v", n: "2" }] },
    });
  });

  it("maps SMB3 and NTLM session materials", () => {
    expect(asSMB3SessionCandidates([{ session_id: "s1", nt_proof_str: "proof", complete: true }])[0]).toMatchObject({
      sessionId: "s1",
      ntProofStr: "proof",
      complete: true,
    });

    expect(asSMB3RandomSessionKeyResult({ random_session_key: "abcd", message: "ok" })).toEqual({
      randomSessionKey: "abcd",
      message: "ok",
    });

    expect(
      asNTLMSessionMaterials([
        {
          protocol: "HTTP",
          transport: "TCP",
          frame_number: "7",
          src_port: "1234",
          nt_proof_str: "proof",
          complete: true,
        },
      ])[0],
    ).toMatchObject({
      protocol: "HTTP",
      transport: "TCP",
      frameNumber: "7",
      srcPort: "1234",
      ntProofStr: "proof",
      complete: true,
    });
  });

  it("returns empty arrays for absent list payloads", () => {
    expect(asMiscModuleManifests(null)).toEqual([]);
    expect(asSMB3SessionCandidates(null)).toEqual([]);
    expect(asNTLMSessionMaterials(null)).toEqual([]);
  });
});
