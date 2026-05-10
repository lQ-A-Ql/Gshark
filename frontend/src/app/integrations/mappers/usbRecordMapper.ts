import type { USBPacketRecord } from "../../core/types";

export function asUSBPacketRecord(item: any): USBPacketRecord {
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
