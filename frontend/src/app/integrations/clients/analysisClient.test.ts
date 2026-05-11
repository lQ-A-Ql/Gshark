import { describe, expect, it, vi } from "vitest";

import { createAnalysisClient } from "./analysisClient";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

describe("analysisClient", () => {
  it("maps USB and C2 report payloads from transport responses", async () => {
    const request = vi.fn(async (path: string) => {
      if (path === "/api/analysis/usb") {
        return {
          total_usb_packets: 4,
          hid_packets: 1,
          mass_storage_packets: 3,
          protocols: [],
          transfer_types: [],
          directions: [],
          devices: [],
          endpoints: [],
          setup_requests: [],
          records: [],
          keyboard_events: [],
          mouse_events: [],
          other_records: [],
          hid: { keyboard_events: [], mouse_events: [], devices: [], notes: [] },
          mass_storage: {
            total_packets: 0,
            read_packets: 0,
            write_packets: 0,
            control_packets: 0,
            devices: [],
            luns: [],
            commands: [],
            read_operations: [],
            write_operations: [],
            notes: [],
          },
          other: {
            total_packets: 0,
            control_packets: 0,
            devices: [],
            endpoints: [],
            setup_requests: [],
            control_records: [],
            records: [],
            notes: [],
          },
          notes: [],
          report: {
            summary: [{ title: "USB 概览", summary: "USB 包 4 / 设备 0 / Endpoint 0" }],
            evidence: [{ title: "USB 存储写入", severity: "high", packet_id: 21 }],
            details: [],
            recommendations: ["优先定位写操作。"],
          },
        };
      }
      if (path === "/api/c2-analysis") {
        return {
          total_matched_packets: 2,
          families: [],
          conversations: [],
          cs: {
            candidate_count: 1,
            matched_rule_count: 1,
            channels: [],
            indicators: [],
            conversations: [],
            candidates: [{ packet_id: 9, stream_id: 4, family: "cs", summary: "candidate" }],
            notes: [],
            report: {
              summary: [{ title: "CS 候选概览", summary: "候选 1 / 规则位 1 / 通道 0" }],
              evidence: [{ title: "candidate", severity: "high", packet_id: 9, stream_id: 4 }],
              details: [],
              recommendations: ["回到原始包。"],
            },
          },
          vshell: {
            candidate_count: 0,
            matched_rule_count: 0,
            channels: [],
            indicators: [],
            conversations: [],
            candidates: [],
            notes: [],
            report: { summary: [], evidence: [], details: [], recommendations: [] },
          },
          notes: [],
        };
      }
      throw new Error(`unexpected path ${path}`);
    }) as unknown as JsonRequest;

    const client = createAnalysisClient(request);
    const usb = await client.getUSBAnalysis();
    const c2 = await client.getC2SampleAnalysis();

    expect(usb.report?.evidence[0]).toMatchObject({ title: "USB 存储写入", severity: "high", packetId: 21 });
    expect(c2.cs.report?.summary[0]).toMatchObject({ title: "CS 候选概览" });
    expect(c2.cs.report?.evidence[0]).toMatchObject({ title: "candidate", packetId: 9, streamId: 4 });
  });

  it("encodes evidence module filters on the request path and preserves evidence records", async () => {
    const request = vi.fn(async (path: string) => {
      expect(path).toBe("/api/evidence?modules=vehicle%2Cusb");
      return {
        records: [
          {
            id: "vehicle-1",
            module: "vehicle",
            source_type: "uds",
            summary: "UDS 负响应",
            severity: "high",
            confidence: 82,
            tags: ["UDS", "0x27"],
            caveats: [],
          },
        ],
      };
    }) as unknown as JsonRequest;

    const client = createAnalysisClient(request);
    const evidence = await client.getEvidenceWithFilter(["vehicle", "usb"]);

    expect(evidence[0]).toMatchObject({
      id: "vehicle-1",
      module: "vehicle",
      sourceType: "uds",
      summary: "UDS 负响应",
      severity: "high",
    });
  });
});
