import type { USBAnalysis } from "../core/types";

export function createUSBAnalysis(overrides: Partial<USBAnalysis> = {}): USBAnalysis {
  return {
    totalUSBPackets: 0,
    keyboardPackets: 0,
    mousePackets: 0,
    otherUSBPackets: 0,
    hidPackets: 0,
    massStoragePackets: 0,
    protocols: [],
    transferTypes: [],
    directions: [],
    devices: [],
    endpoints: [],
    setupRequests: [],
    records: [],
    keyboardEvents: [],
    mouseEvents: [],
    otherRecords: [],
    hid: {
      keyboardEvents: [],
      mouseEvents: [],
      devices: [],
      notes: [],
    },
    massStorage: {
      totalPackets: 0,
      readPackets: 0,
      writePackets: 0,
      controlPackets: 0,
      devices: [],
      luns: [],
      commands: [],
      readOperations: [],
      writeOperations: [],
      notes: [],
    },
    other: {
      totalPackets: 0,
      controlPackets: 0,
      devices: [],
      endpoints: [],
      setupRequests: [],
      controlRecords: [],
      records: [],
      notes: [],
    },
    notes: [],
    ...overrides,
  };
}

export function createUSBMassStorageAnalysis(): USBAnalysis {
  return createUSBAnalysis({
    totalUSBPackets: 2,
    massStoragePackets: 2,
    massStorage: {
      totalPackets: 2,
      readPackets: 1,
      writePackets: 1,
      controlPackets: 0,
      devices: [{ label: "Disk A", count: 2 }],
      luns: [{ label: "LUN 0", count: 2 }],
      commands: [
        { label: "READ(10)", count: 1 },
        { label: "WRITE(10)", count: 1 },
      ],
      readOperations: [
        {
          packetId: 10,
          time: "1.000000",
          device: "Disk A",
          endpoint: "EP 0x81 (IN)",
          lun: "LUN 0",
          command: "READ(10)",
          operation: "read",
          transferLength: 512,
          direction: "IN",
          status: "ok",
          requestFrame: 10,
          responseFrame: 12,
          latencyMs: 1.25,
          summary: "READ(10)",
        },
      ],
      writeOperations: [
        {
          packetId: 20,
          time: "2.000000",
          device: "Disk A",
          endpoint: "EP 0x02 (OUT)",
          lun: "LUN 0",
          command: "WRITE(10)",
          operation: "write",
          transferLength: 512,
          direction: "OUT",
          status: "ok",
          requestFrame: 20,
          responseFrame: 21,
          latencyMs: 1.5,
          summary: "WRITE(10)",
        },
      ],
      notes: ["storage note"],
    },
  });
}

export function createUSBHidAnalysis(): USBAnalysis {
  return createUSBAnalysis({
    totalUSBPackets: 2,
    hidPackets: 2,
    keyboardPackets: 1,
    mousePackets: 1,
    hid: {
      keyboardEvents: [
        {
          packetId: 1,
          time: "1.000000",
          device: "Keyboard A",
          endpoint: "EP 0x81 (IN)",
          modifiers: ["Left Shift"],
          keys: ["A"],
          pressedModifiers: ["Left Shift"],
          releasedModifiers: [],
          pressedKeys: ["A"],
          releasedKeys: [],
          text: "A",
          summary: "press Left Shift + A",
        },
      ],
      mouseEvents: [
        {
          packetId: 2,
          time: "1.100000",
          device: "Mouse A",
          endpoint: "EP 0x82 (IN)",
          buttons: ["Left"],
          pressedButtons: ["Left"],
          releasedButtons: [],
          xDelta: 8,
          yDelta: 2,
          wheelVertical: 0,
          wheelHorizontal: 0,
          positionX: 8,
          positionY: 2,
          summary: "press Left / move=(+8,+2)",
        },
      ],
      devices: [
        { label: "Keyboard A", count: 1 },
        { label: "Mouse A", count: 1 },
      ],
      notes: ["hid note"],
    },
  });
}

export function createUSBOtherAnalysis(): USBAnalysis {
  return createUSBAnalysis({
    totalUSBPackets: 2,
    otherUSBPackets: 2,
    other: {
      totalPackets: 2,
      controlPackets: 1,
      devices: [{ label: "Bus 1 / Device 5", count: 2 }],
      endpoints: [{ label: "Bus 1 / Device 5 / EP 0x00 (OUT)", count: 2 }],
      setupRequests: [{ label: "GET_DESCRIPTOR", count: 1 }],
      controlRecords: [
        {
          packetId: 3,
          time: "3.000000",
          protocol: "USB",
          busId: "1",
          deviceAddress: "5",
          endpoint: "EP 0x00 (OUT)",
          direction: "OUT",
          transferType: "Control",
          urbType: "Submit",
          status: "ok",
          dataLength: 18,
          setupRequest: "GET_DESCRIPTOR wValue=0x0100",
          payloadPreview: "descriptor",
          summary: "GET_DESCRIPTOR",
        },
      ],
      records: [
        {
          packetId: 4,
          time: "4.000000",
          protocol: "USB",
          busId: "1",
          deviceAddress: "5",
          endpoint: "EP 0x00 (OUT)",
          direction: "OUT",
          transferType: "Control",
          urbType: "Complete",
          status: "ok",
          dataLength: 18,
          setupRequest: "GET_DESCRIPTOR wValue=0x0100",
          payloadPreview: "descriptor",
          summary: "raw record",
        },
      ],
      notes: ["other note"],
    },
  });
}
