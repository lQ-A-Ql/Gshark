import { describe, expect, it } from "vitest";
import type { C2DecryptResult } from "../core/types";
import { isLikelyVShellLowInfoControlRecord, normalizeC2DecryptResultForDisplay } from "./wailsBridge";

describe("VShell decrypt result display normalization", () => {
  it("hides short low-information control frames without touching meaningful plaintext", () => {
    const result: C2DecryptResult = {
      family: "vshell",
      status: "completed",
      totalCandidates: 4,
      decryptedCount: 4,
      failedCount: 0,
      records: [
        {
          streamId: 23,
          direction: "server_to_client",
          confidence: 90,
          plaintextPreview: "03030000002400",
          rawLength: 35,
          decryptedLength: 7,
        },
        {
          streamId: 23,
          direction: "client_to_server",
          confidence: 90,
          plaintextPreview: "05030000001b000000fceb0200",
          rawLength: 41,
          decryptedLength: 13,
          tags: ["raw-stream-client-hex"],
        },
        {
          streamId: 23,
          direction: "server_to_client",
          confidence: 90,
          plaintextPreview: "05000000342e392e33",
          rawLength: 37,
          decryptedLength: 9,
        },
        {
          streamId: 23,
          direction: "client_to_server",
          confidence: 90,
          plaintextPreview: "{\"cmd\":\"whoami\"}",
          rawLength: 64,
          decryptedLength: 16,
        },
      ],
      notes: ["原始后端说明"],
    };

    const normalized = normalizeC2DecryptResultForDisplay(result);

    expect(normalized.records).toHaveLength(2);
    expect(normalized.decryptedCount).toBe(2);
    expect(normalized.totalCandidates).toBe(4);
    expect(normalized.records[0]?.plaintextPreview).toContain("4.9.3");
    expect(normalized.records[0]?.tags).toContain("utf8-from-hex-preview");
    expect(normalized.records[1]?.plaintextPreview).toBe("{\"cmd\":\"whoami\"}");
    expect(normalized.notes).toContain("前端接口层已将 2 条 VShell hex preview 转为 UTF-8 文本。");
    expect(normalized.notes).toContain("前端接口层已隐藏 1 条 UTF-8 解码后无可见字符的 VShell 记录。");
    expect(normalized.notes).toContain("前端接口层已隐藏 1 条 VShell 短二进制控制帧/心跳帧，避免短控制载荷淹没明文结果。");
  });

  it("hides timestamp-only records without hiding timestamp-like paths", () => {
    const result: C2DecryptResult = {
      family: "vshell",
      status: "completed",
      totalCandidates: 5,
      decryptedCount: 5,
      failedCount: 0,
      records: [
        { confidence: 90, plaintextPreview: "2026-04-16 22:24:44", decryptedLength: 19 },
        { confidence: 90, plaintextPreview: "2026-04-16T14:39:26.139972268Z", decryptedLength: 30 },
        { confidence: 90, plaintextPreview: "22:24:44", decryptedLength: 8 },
        { confidence: 90, plaintextPreview: "1776368684000", decryptedLength: 13 },
        { confidence: 90, plaintextPreview: "~/unzip_202604162244_AstrBot-3/AstrBot-3.5.17", decryptedLength: 49 },
      ],
      notes: [],
    };

    const normalized = normalizeC2DecryptResultForDisplay(result);

    expect(normalized.records).toHaveLength(1);
    expect(normalized.records[0]?.plaintextPreview).toContain("~/unzip_202604162244_AstrBot-3/AstrBot-3.5.17");
    expect(normalized.decryptedCount).toBe(1);
    expect(normalized.notes).toContain("前端接口层已隐藏 4 条仅包含时间戳的 VShell 记录。");
  });

  it("strips ANSI terminal sequences, keeps meaningful shell output, and hides ANSI-only records", () => {
    const result: C2DecryptResult = {
      family: "vshell",
      status: "completed",
      totalCandidates: 2,
      decryptedCount: 2,
      failedCount: 0,
      records: [
        {
          confidence: 90,
          plaintextPreview: "\u001b[32m/root/ops\u001b[0m$ whoami\r\nroot\u001b[K",
          decryptedLength: 32,
        },
        {
          confidence: 90,
          plaintextPreview: "\u001b[32m\u001b[0m\u001b[K",
          decryptedLength: 11,
        },
      ],
      notes: [],
    };

    const normalized = normalizeC2DecryptResultForDisplay(result);

    expect(normalized.records).toHaveLength(1);
    expect(normalized.records[0]?.plaintextPreview).toBe("/root/ops$ whoami\nroot");
    expect(normalized.records[0]?.tags).toContain("ansi-stripped");
    expect(normalized.decryptedCount).toBe(1);
    expect(normalized.notes).toContain("前端接口层已清理 2 条 VShell 记录中的 ANSI/VT100 终端控制序列。");
    expect(normalized.notes).toContain("前端接口层已隐藏 1 条 UTF-8 解码后无可见字符的 VShell 记录。");
  });

  it("extracts best-effort readable text from mixed binary hex previews", () => {
    const mixedHex = "fceb6861636b65645f62795f66616c6c736e6f77267061706572706c616e65285141512900";
    const result: C2DecryptResult = {
      family: "vshell",
      status: "completed",
      totalCandidates: 1,
      decryptedCount: 1,
      failedCount: 0,
      records: [
        {
          confidence: 90,
          plaintextPreview: mixedHex,
          decryptedLength: mixedHex.length / 2,
        },
      ],
      notes: [],
    };

    const normalized = normalizeC2DecryptResultForDisplay(result);

    expect(normalized.records).toHaveLength(1);
    expect(normalized.records[0]?.plaintextPreview).toContain("hacked_by_fallsnow&paperplane(QAQ)");
    expect(normalized.records[0]?.tags).toContain("utf8-best-effort-from-hex-preview");
    expect(normalized.notes).toContain("前端接口层已从 1 条 VShell hex preview 中提取可读文本。");
  });

  it("extracts best-effort readable text from backend-truncated hex previews", () => {
    const truncatedMixedHex = "fceb6861636b65645f62795f66616c6c736e6f77267061706572706c616e65285141512900";
    const result: C2DecryptResult = {
      family: "vshell",
      status: "completed",
      totalCandidates: 1,
      decryptedCount: 1,
      failedCount: 0,
      records: [
        {
          confidence: 90,
          plaintextPreview: truncatedMixedHex,
          decryptedLength: 4096,
          tags: ["raw-stream-server-hex"],
        },
      ],
      notes: [],
    };

    const normalized = normalizeC2DecryptResultForDisplay(result);

    expect(normalized.records).toHaveLength(1);
    expect(normalized.records[0]?.plaintextPreview).toContain("hacked_by_fallsnow&paperplane(QAQ)");
    expect(normalized.records[0]?.tags).toContain("utf8-best-effort-from-hex-preview");
    expect(normalized.records[0]?.tags).toContain("truncated-hex-preview");
    expect(normalized.records[0]?.tags).toContain("raw-stream-server-hex");
    expect(normalized.notes).toContain("前端接口层已从 1 条 VShell hex preview 中提取可读文本。");
    expect(normalized.notes).toContain("前端接口层已从 1 条后端截断的 VShell hex preview 中提取可读文本。");
  });

  it("decodes high-value VShell hex plaintext and hides UTF-8 payloads without visible characters", () => {
    const targetHex = "6861636b65645f62795f66616c6c736e6f77267061706572706c616e6528514151290d0a";
    const result: C2DecryptResult = {
      family: "vshell",
      status: "completed",
      totalCandidates: 2,
      decryptedCount: 2,
      failedCount: 0,
      records: [
        {
          streamId: 23,
          direction: "server_to_client",
          confidence: 90,
          plaintextPreview: targetHex,
          decryptedLength: targetHex.length / 2,
        },
        {
          streamId: 23,
          direction: "server_to_client",
          confidence: 90,
          plaintextPreview: "00000a000d",
          decryptedLength: 5,
        },
      ],
      notes: [],
    };

    const normalized = normalizeC2DecryptResultForDisplay(result);

    expect(normalized.records).toHaveLength(1);
    expect(normalized.records[0]?.plaintextPreview).toContain("hacked_by_fallsnow&paperplane(QAQ)");
    expect(normalized.records[0]?.tags).toContain("utf8-from-hex-preview");
    expect(normalized.decryptedCount).toBe(1);
    expect(normalized.notes).toContain("前端接口层已将 2 条 VShell hex preview 转为 UTF-8 文本。");
    expect(normalized.notes).toContain("前端接口层已隐藏 1 条 UTF-8 解码后无可见字符的 VShell 记录。");
  });

  it("keeps failed records, CS records, parsed records, and readable short values visible", () => {
    expect(isLikelyVShellLowInfoControlRecord({
      confidence: 0,
      decryptedLength: 7,
      plaintextPreview: "03030000002400",
      error: "decrypt failed",
    })).toBe(false);

    expect(isLikelyVShellLowInfoControlRecord({
      confidence: 90,
      decryptedLength: 5,
      plaintextPreview: "4.9.3",
    })).toBe(false);

    expect(isLikelyVShellLowInfoControlRecord({
      confidence: 90,
      decryptedLength: 13,
      plaintextPreview: "05030000001b000000fceb0200",
      tags: ["raw-stream-client-hex"],
    })).toBe(true);

    expect(isLikelyVShellLowInfoControlRecord({
      confidence: 90,
      decryptedLength: 3,
      plaintextPreview: "OK",
    })).toBe(false);

    expect(isLikelyVShellLowInfoControlRecord({
      confidence: 90,
      decryptedLength: 16,
      plaintextPreview: "{\"cmd\":\"whoami\"}",
    })).toBe(false);

    expect(isLikelyVShellLowInfoControlRecord({
      confidence: 90,
      decryptedLength: 32,
      plaintextPreview: "hacked_by_fallsnow&paperplane(QAQ)",
    })).toBe(false);

    const csResult: C2DecryptResult = {
      family: "cs",
      status: "completed",
      totalCandidates: 1,
      decryptedCount: 1,
      failedCount: 0,
      records: [{ confidence: 90, decryptedLength: 7, plaintextPreview: "03030000002400" }],
      notes: [],
    };
    expect(normalizeC2DecryptResultForDisplay(csResult)).toBe(csResult);
  });
});
