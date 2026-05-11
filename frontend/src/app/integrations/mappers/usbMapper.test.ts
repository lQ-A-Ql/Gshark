import { describe, expect, it } from "vitest";
import { asUSBAnalysis } from "./usbMapper";

describe("usbMapper", () => {
  it("maps USB summary, HID events, and mass storage operations", () => {
    const result = asUSBAnalysis({
      total_usb_packets: 9,
      keyboard_packets: 2,
      mouse_packets: 1,
      other_usb_packets: 3,
      hid_packets: 3,
      mass_storage_packets: 4,
      protocols: [{ label: "USB", count: 9 }],
      transfer_types: [{ label: "BULK", count: 4 }],
      directions: [{ label: "IN", count: 5 }],
      devices: [{ label: "1.2", count: 4 }],
      endpoints: [{ label: "0x81", count: 2 }],
      setup_requests: [{ label: "GET_DESCRIPTOR", count: 1 }],
      records: [
        {
          packet_id: 1,
          time: "0.1",
          protocol: "USB",
          bus_id: "1",
          device_address: "2",
          endpoint: "0x81",
          direction: "IN",
          transfer_type: "INTERRUPT",
          urb_type: "SUBMIT",
          status: "OK",
          data_length: 8,
          setup_request: "GET_DESCRIPTOR",
          payload_preview: "00 04",
          summary: "record",
        },
      ],
      keyboard_events: [
        {
          packet_id: 2,
          time: "0.2",
          device: "kbd",
          endpoint: "0x81",
          modifiers: ["shift"],
          keys: ["A", 1],
          pressed_modifiers: ["shift"],
          released_modifiers: [],
          pressed_keys: ["A"],
          released_keys: [],
          text: "A",
          summary: "key",
        },
      ],
      mouse_events: [
        {
          packet_id: 3,
          time: "0.3",
          device: "mouse",
          endpoint: "0x82",
          buttons: ["left"],
          pressed_buttons: ["left"],
          released_buttons: [],
          x_delta: 4,
          y_delta: -2,
          wheel_vertical: 1,
          wheel_horizontal: 0,
          position_x: 10,
          position_y: 20,
          summary: "mouse",
        },
      ],
      other_records: [{ packet_id: 4, summary: "other" }],
      hid: {
        keyboard_events: [{ packet_id: 5, summary: "hid key" }],
        mouse_events: [{ packet_id: 6, summary: "hid mouse" }],
        devices: [{ label: "hid", count: 2 }],
        notes: ["hid note"],
      },
      mass_storage: {
        total_packets: 4,
        read_packets: 1,
        write_packets: 2,
        control_packets: 1,
        devices: [{ label: "disk", count: 4 }],
        luns: [{ label: "0", count: 4 }],
        commands: [{ label: "WRITE(10)", count: 2 }],
        read_operations: [
          {
            packet_id: 7,
            time: "0.7",
            device: "disk",
            endpoint: "0x01",
            lun: "0",
            command: "READ(10)",
            operation: "read",
            transfer_length: 512,
            direction: "IN",
            status: "OK",
            request_frame: 70,
            response_frame: 71,
            latency_ms: 3.5,
            data_residue: 0,
            summary: "read",
          },
        ],
        write_operations: [{ packet_id: 8, command: "WRITE(10)", operation: "write", summary: "write" }],
        notes: ["mass note"],
      },
      other: {
        total_packets: 3,
        control_packets: 1,
        devices: [{ label: "other", count: 1 }],
        endpoints: [{ label: "0", count: 1 }],
        setup_requests: [{ label: "SETUP", count: 1 }],
        control_records: [{ packet_id: 9, summary: "control" }],
        records: [{ packet_id: 10, summary: "record" }],
        notes: ["other note"],
      },
      notes: ["usb note"],
      report: {
        summary: [{ title: "USB 概览", summary: "USB 包 9 / 设备 1 / Endpoint 1" }],
        evidence: [{ title: "USB 存储写入: WRITE(10)", severity: "medium", packet_id: 8 }],
        details: [{ title: "USB 键盘事件", packet_id: 2 }],
        recommendations: ["优先定位 USB Mass Storage 写操作。"],
      },
    });

    expect(result.totalUSBPackets).toBe(9);
    expect(result.records[0]).toMatchObject({ packetId: 1, payloadPreview: "00 04" });
    expect(result.keyboardEvents[0]).toMatchObject({ packetId: 2, keys: ["A", "1"], text: "A" });
    expect(result.mouseEvents[0]).toMatchObject({ packetId: 3, xDelta: 4, positionY: 20 });
    expect(result.hid.notes).toEqual(["hid note"]);
    expect(result.massStorage.readOperations[0]).toMatchObject({
      packetId: 7,
      requestFrame: 70,
      responseFrame: 71,
      latencyMs: 3.5,
      dataResidue: 0,
    });
    expect(result.other.controlRecords[0]).toMatchObject({ packetId: 9 });
    expect(result.notes).toEqual(["usb note"]);
    expect(result.report?.evidence[0]).toMatchObject({
      title: "USB 存储写入: WRITE(10)",
      severity: "medium",
      packetId: 8,
    });
  });

  it("returns empty defaults for missing sections", () => {
    const result = asUSBAnalysis({});
    expect(result.records).toEqual([]);
    expect(result.hid.keyboardEvents).toEqual([]);
    expect(result.massStorage.writeOperations).toEqual([]);
    expect(result.other.records).toEqual([]);
    expect(result.report?.summary).toEqual([]);
  });
});
