import { describe, expect, it } from "vitest";
import { asVehicleAnalysis } from "./vehicleMapper";

describe("vehicleMapper", () => {
  it("maps vehicle backend payloads into frontend shape", () => {
    const result = asVehicleAnalysis({
      total_vehicle_packets: 12,
      protocols: [{ label: "CAN", count: 10 }],
      conversations: [{ label: "bus0", protocol: "CAN", count: 10 }],
      can: {
        total_frames: 10,
        extended_frames: 1,
        rtr_frames: 2,
        error_frames: 3,
        bus_ids: [{ label: "0", count: 10 }],
        message_ids: [{ label: "0x123", count: 3 }],
        payload_protocols: [{ label: "UDS", count: 2 }],
        payload_records: [
          {
            packet_id: 5,
            time: "0.100000",
            bus_id: "0",
            identifier: "0x7df",
            protocol: "UDS",
            frame_type: "single",
            source_address: "0x7df",
            target_address: "0x01",
            service: "0x10",
            detail: "session control",
            length: 8,
            raw_data: "02 10 03",
            summary: "payload",
          },
        ],
        dbc_profiles: [{ path: "car.dbc", name: "car", message_count: 4, signal_count: 9 }],
        decoded_message_dist: [{ label: "Speed", count: 1 }],
        decoded_signals: [{ label: "VehicleSpeed", count: 1 }],
        decoded_messages: [
          {
            packet_id: 6,
            time: "0.200000",
            bus_id: "0",
            identifier: "0x100",
            database: "car.dbc",
            message_name: "Speed",
            sender: "ECU",
            signals: [{ name: "VehicleSpeed", value: "88", unit: "km/h" }],
            summary: "decoded",
          },
        ],
        signal_timelines: [
          {
            name: "VehicleSpeed",
            samples: [{ packet_id: 6, time: "0.200000", value: 88, unit: "km/h", message_name: "Speed" }],
          },
        ],
        frames: [
          {
            packet_id: 7,
            time: "0.300000",
            identifier: "0x123",
            bus_id: "0",
            length: 8,
            raw_data: "01 02",
            is_extended: true,
            is_rtr: false,
            is_error: true,
            error_flags: "crc",
            summary: "frame",
          },
        ],
      },
      j1939: {
        total_messages: 1,
        pgns: [{ label: "65265", count: 1 }],
        source_addrs: [{ label: "1", count: 1 }],
        target_addrs: [{ label: "255", count: 1 }],
        messages: [
          {
            packet_id: 8,
            time: "0.400000",
            can_id: "0x18FEEE01",
            pgn: "65262",
            priority: 6,
            source_addr: "1",
            target_addr: "255",
            data_preview: "AA BB",
            summary: "j1939",
          },
        ],
      },
      doip: {
        total_messages: 1,
        message_types: [{ label: "diagnostic", count: 1 }],
        vins: [{ label: "VIN123", count: 1 }],
        endpoints: [{ label: "tester", count: 1 }],
        messages: [
          {
            packet_id: 9,
            time: "0.500000",
            source: "10.0.0.1",
            destination: "10.0.0.2",
            type: "diagnostic",
            vin: "VIN123",
            logical_address: "0x0e00",
            source_address: "0x0e00",
            target_address: "0x1000",
            tester_address: "0x0e00",
            response_code: "0x00",
            diagnostic_state: "active",
            summary: "doip",
          },
        ],
      },
      uds: {
        total_messages: 2,
        service_ids: [{ label: "0x10", count: 1 }],
        negative_codes: [{ label: "0x78", count: 1 }],
        dtcs: [{ label: "P0001", count: 1 }],
        vins: [{ label: "VIN123", count: 1 }],
        messages: [
          {
            packet_id: 10,
            time: "0.600000",
            service_id: "0x10",
            service_name: "Diagnostic Session Control",
            is_reply: false,
            sub_function: "0x03",
            source_address: "tester",
            target_address: "ecu",
            data_identifier: "0xf190",
            diagnostic_vin: "VIN123",
            dtc: "P0001",
            negative_code: "0x78",
            summary: "uds",
          },
        ],
        transactions: [
          {
            request_packet_id: 10,
            response_packet_id: 11,
            request_time: "0.600000",
            response_time: "0.650000",
            source_address: "tester",
            target_address: "ecu",
            service_id: "0x10",
            service_name: "Diagnostic Session Control",
            sub_function: "0x03",
            data_identifier: "0xf190",
            dtc: "P0001",
            status: "positive",
            negative_code: "0x78",
            latency_ms: 50,
            request_summary: "req",
            response_summary: "res",
          },
        ],
      },
      recommendations: ["review diagnostics"],
    });

    expect(result.totalVehiclePackets).toBe(12);
    expect(result.protocols).toEqual([{ label: "CAN", count: 10 }]);
    expect(result.can.payloadRecords[0]).toMatchObject({
      packetId: 5,
      sourceAddress: "0x7df",
      rawData: "02 10 03",
    });
    expect(result.can.decodedMessages[0].signals[0]).toEqual({
      name: "VehicleSpeed",
      value: "88",
      unit: "km/h",
    });
    expect(result.can.frames[0]).toMatchObject({
      packetId: 7,
      isExtended: true,
      isError: true,
      errorFlags: "crc",
    });
    expect(result.j1939.messages[0]).toMatchObject({ canId: "0x18FEEE01", priority: 6 });
    expect(result.doip.messages[0]).toMatchObject({ vin: "VIN123", logicalAddress: "0x0e00" });
    expect(result.uds.messages[0]).toMatchObject({
      serviceId: "0x10",
      diagnosticVIN: "VIN123",
      negativeCode: "0x78",
    });
    expect(result.uds.transactions[0]).toMatchObject({
      requestPacketId: 10,
      responsePacketId: 11,
      latencyMs: 50,
    });
    expect(result.recommendations).toEqual(["review diagnostics"]);
  });

  it("returns empty sections for missing payload data", () => {
    const result = asVehicleAnalysis({});

    expect(result.totalVehiclePackets).toBe(0);
    expect(result.can.frames).toEqual([]);
    expect(result.j1939.messages).toEqual([]);
    expect(result.doip.messages).toEqual([]);
    expect(result.uds.transactions).toEqual([]);
    expect(result.recommendations).toEqual([]);
  });

  it("defaults malformed wire payloads without trusting nested shapes", () => {
    const result = asVehicleAnalysis({ protocols: "bad", conversations: [null], recommendations: 7 });

    expect(result.protocols).toEqual([]);
    expect(result.conversations).toEqual([{ label: "", count: 0 }]);
    expect(result.recommendations).toEqual([]);
    expect(asVehicleAnalysis(null).totalVehiclePackets).toBe(0);
  });
});
