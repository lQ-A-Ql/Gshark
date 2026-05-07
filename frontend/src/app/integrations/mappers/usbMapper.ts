import type { USBAnalysis } from "../../core/types";
import { asBucket, asStringList } from "./mapperPrimitives";

function asUSBPacketRecord(item: any) {
  return {
    packetId: Number(item.packet_id ?? 0),
    time: String(item.time ?? ""),
    protocol: String(item.protocol ?? ""),
    busId: String(item.bus_id ?? ""),
    deviceAddress: String(item.device_address ?? ""),
    endpoint: String(item.endpoint ?? ""),
    direction: String(item.direction ?? ""),
    transferType: String(item.transfer_type ?? ""),
    urbType: String(item.urb_type ?? ""),
    status: String(item.status ?? ""),
    dataLength: Number(item.data_length ?? 0),
    setupRequest: String(item.setup_request ?? "") || undefined,
    payloadPreview: String(item.payload_preview ?? "") || undefined,
    summary: String(item.summary ?? ""),
  };
}

function asUSBKeyboardEvent(item: any) {
  return {
    packetId: Number(item.packet_id ?? 0),
    time: String(item.time ?? ""),
    device: String(item.device ?? ""),
    endpoint: String(item.endpoint ?? ""),
    modifiers: asStringList(item.modifiers),
    keys: asStringList(item.keys),
    pressedModifiers: asStringList(item.pressed_modifiers),
    releasedModifiers: asStringList(item.released_modifiers),
    pressedKeys: asStringList(item.pressed_keys),
    releasedKeys: asStringList(item.released_keys),
    text: String(item.text ?? "") || undefined,
    summary: String(item.summary ?? ""),
  };
}

function asUSBMouseEvent(item: any) {
  return {
    packetId: Number(item.packet_id ?? 0),
    time: String(item.time ?? ""),
    device: String(item.device ?? ""),
    endpoint: String(item.endpoint ?? ""),
    buttons: asStringList(item.buttons),
    pressedButtons: asStringList(item.pressed_buttons),
    releasedButtons: asStringList(item.released_buttons),
    xDelta: Number(item.x_delta ?? 0),
    yDelta: Number(item.y_delta ?? 0),
    wheelVertical: Number(item.wheel_vertical ?? 0),
    wheelHorizontal: Number(item.wheel_horizontal ?? 0),
    positionX: Number(item.position_x ?? 0),
    positionY: Number(item.position_y ?? 0),
    summary: String(item.summary ?? ""),
  };
}

function asUSBMassStorageOperation(item: any) {
  return {
    packetId: Number(item.packet_id ?? 0),
    time: String(item.time ?? ""),
    device: String(item.device ?? ""),
    endpoint: String(item.endpoint ?? ""),
    lun: String(item.lun ?? ""),
    command: String(item.command ?? ""),
    operation: String(item.operation ?? "other"),
    transferLength: Number(item.transfer_length ?? 0),
    direction: String(item.direction ?? ""),
    status: String(item.status ?? ""),
    requestFrame: item.request_frame == null ? undefined : Number(item.request_frame),
    responseFrame: item.response_frame == null ? undefined : Number(item.response_frame),
    latencyMs: item.latency_ms == null ? undefined : Number(item.latency_ms),
    dataResidue: item.data_residue == null ? undefined : Number(item.data_residue),
    summary: String(item.summary ?? ""),
  };
}

export function asUSBAnalysis(payload: any): USBAnalysis {
  return {
    totalUSBPackets: Number(payload?.total_usb_packets ?? 0),
    keyboardPackets: Number(payload?.keyboard_packets ?? 0),
    mousePackets: Number(payload?.mouse_packets ?? 0),
    otherUSBPackets: Number(payload?.other_usb_packets ?? 0),
    hidPackets: Number(payload?.hid_packets ?? 0),
    massStoragePackets: Number(payload?.mass_storage_packets ?? 0),
    protocols: Array.isArray(payload?.protocols) ? payload.protocols.map(asBucket) : [],
    transferTypes: Array.isArray(payload?.transfer_types) ? payload.transfer_types.map(asBucket) : [],
    directions: Array.isArray(payload?.directions) ? payload.directions.map(asBucket) : [],
    devices: Array.isArray(payload?.devices) ? payload.devices.map(asBucket) : [],
    endpoints: Array.isArray(payload?.endpoints) ? payload.endpoints.map(asBucket) : [],
    setupRequests: Array.isArray(payload?.setup_requests) ? payload.setup_requests.map(asBucket) : [],
    records: Array.isArray(payload?.records) ? payload.records.map(asUSBPacketRecord) : [],
    keyboardEvents: Array.isArray(payload?.keyboard_events) ? payload.keyboard_events.map(asUSBKeyboardEvent) : [],
    mouseEvents: Array.isArray(payload?.mouse_events) ? payload.mouse_events.map(asUSBMouseEvent) : [],
    otherRecords: Array.isArray(payload?.other_records) ? payload.other_records.map(asUSBPacketRecord) : [],
    hid: {
      keyboardEvents: Array.isArray(payload?.hid?.keyboard_events)
        ? payload.hid.keyboard_events.map(asUSBKeyboardEvent)
        : [],
      mouseEvents: Array.isArray(payload?.hid?.mouse_events) ? payload.hid.mouse_events.map(asUSBMouseEvent) : [],
      devices: Array.isArray(payload?.hid?.devices) ? payload.hid.devices.map(asBucket) : [],
      notes: asStringList(payload?.hid?.notes),
    },
    massStorage: {
      totalPackets: Number(payload?.mass_storage?.total_packets ?? 0),
      readPackets: Number(payload?.mass_storage?.read_packets ?? 0),
      writePackets: Number(payload?.mass_storage?.write_packets ?? 0),
      controlPackets: Number(payload?.mass_storage?.control_packets ?? 0),
      devices: Array.isArray(payload?.mass_storage?.devices) ? payload.mass_storage.devices.map(asBucket) : [],
      luns: Array.isArray(payload?.mass_storage?.luns) ? payload.mass_storage.luns.map(asBucket) : [],
      commands: Array.isArray(payload?.mass_storage?.commands) ? payload.mass_storage.commands.map(asBucket) : [],
      readOperations: Array.isArray(payload?.mass_storage?.read_operations)
        ? payload.mass_storage.read_operations.map(asUSBMassStorageOperation)
        : [],
      writeOperations: Array.isArray(payload?.mass_storage?.write_operations)
        ? payload.mass_storage.write_operations.map(asUSBMassStorageOperation)
        : [],
      notes: asStringList(payload?.mass_storage?.notes),
    },
    other: {
      totalPackets: Number(payload?.other?.total_packets ?? 0),
      controlPackets: Number(payload?.other?.control_packets ?? 0),
      devices: Array.isArray(payload?.other?.devices) ? payload.other.devices.map(asBucket) : [],
      endpoints: Array.isArray(payload?.other?.endpoints) ? payload.other.endpoints.map(asBucket) : [],
      setupRequests: Array.isArray(payload?.other?.setup_requests) ? payload.other.setup_requests.map(asBucket) : [],
      controlRecords: Array.isArray(payload?.other?.control_records)
        ? payload.other.control_records.map(asUSBPacketRecord)
        : [],
      records: Array.isArray(payload?.other?.records) ? payload.other.records.map(asUSBPacketRecord) : [],
      notes: asStringList(payload?.other?.notes),
    },
    notes: asStringList(payload?.notes),
  };
}
