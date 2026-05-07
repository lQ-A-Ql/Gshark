import { describe, expect, it } from "vitest";
import { asIndustrialAnalysis } from "./industrialMapper";

describe("asIndustrialAnalysis", () => {
  it("maps industrial snake_case payloads to frontend camelCase contracts", () => {
    const result = asIndustrialAnalysis({
      total_industrial_packets: 4,
      protocols: [{ label: "Modbus", count: 4 }],
      conversations: [{ label: "10.0.0.1 -> 10.0.0.2", protocol: "modbus", count: 2 }],
      modbus: {
        total_frames: 4,
        requests: 2,
        responses: 2,
        exceptions: 1,
        function_codes: [{ label: "Write Multiple Registers", count: 1 }],
        unit_ids: [{ label: "1", count: 4 }],
        reference_hits: [{ label: "40001", count: 1 }],
        exception_codes: [{ label: "Illegal Function", count: 1 }],
        decoded_inputs: [
          {
            start_packet_id: 7,
            end_packet_id: 8,
            source: "10.0.0.1",
            destination: "10.0.0.2",
            unit_id: 1,
            function_code: 16,
            function_name: "Write Multiple Registers",
            reference: "40001",
            encoding: "utf-8",
            text: "start",
            raw_text: "7374617274",
            summary: "decoded",
          },
        ],
        transactions: [
          {
            packet_id: 7,
            time: "2026-05-07T00:00:00Z",
            source: "10.0.0.1",
            destination: "10.0.0.2",
            transaction_id: 12,
            unit_id: 1,
            function_code: 16,
            function_name: "Write Multiple Registers",
            kind: "request",
            reference: "40001",
            quantity: "2",
            exception_code: 0,
            response_time: "1ms",
            register_values: "7374 6172",
            input_text: "start",
            bit_range: { type: "coil", start: 1, count: 2, values: [true, false], preview: "10" },
            summary: "write request",
          },
        ],
      },
      suspicious_writes: [
        {
          target: "40001",
          unit_id: 1,
          function_code: 16,
          function_name: "Write Multiple Registers",
          write_count: 1,
          sources: ["10.0.0.1"],
          first_time: "t1",
          last_time: "t2",
          sample_values: ["7374"],
          sample_packet_id: 7,
        },
      ],
      control_commands: [
        {
          packet_id: 9,
          time: "t3",
          protocol: "modbus",
          source: "10.0.0.1",
          destination: "10.0.0.2",
          operation: "write",
          target: "40001",
          value: "start",
          result: "ok",
          summary: "command",
        },
      ],
      rule_hits: [{ rule: "modbus-write", level: "high", packet_id: 7, summary: "hit" }],
      details: [
        {
          name: "modbus",
          total_frames: 4,
          operations: [{ label: "write", count: 1 }],
          targets: [{ label: "40001", count: 1 }],
          results: [{ label: "ok", count: 1 }],
          records: [{ packet_id: 7, time: "t1", source: "a", destination: "b", operation: "write", summary: "record" }],
        },
      ],
      notes: ["parsed"],
    });

    expect(result.totalIndustrialPackets).toBe(4);
    expect(result.protocols[0]).toEqual({ label: "Modbus", count: 4 });
    expect(result.conversations[0]?.protocol).toBe("modbus");
    expect(result.modbus.decodedInputs?.[0]?.startPacketId).toBe(7);
    expect(result.modbus.decodedInputs?.[0]?.text).toBe("start");
    expect(result.modbus.transactions[0]?.bitRange?.values).toEqual([true, false]);
    expect(result.suspiciousWrites?.[0]?.samplePacketId).toBe(7);
    expect(result.controlCommands?.[0]?.target).toBe("40001");
    expect(result.ruleHits?.[0]?.level).toBe("high");
    expect(result.details[0]?.records[0]?.packetId).toBe(7);
    expect(result.notes).toEqual(["parsed"]);
  });

  it("downgrades unknown rule levels and tolerates missing arrays", () => {
    const result = asIndustrialAnalysis({
      modbus: {},
      rule_hits: [{ rule: "unknown", level: "urgent", summary: "fallback" }],
    });

    expect(result.ruleHits?.[0]?.level).toBe("low");
    expect(result.protocols).toEqual([]);
    expect(result.modbus.transactions).toEqual([]);
    expect(result.details).toEqual([]);
  });
});
