import { optionalString } from "./mapperPrimitives";

export function asCANPayloadRecord(item: any) {
  return {
    packetId: Number(item.packet_id ?? 0),
    time: String(item.time ?? ""),
    busId: String(item.bus_id ?? ""),
    identifier: String(item.identifier ?? ""),
    protocol: String(item.protocol ?? ""),
    frameType: optionalString(item.frame_type),
    sourceAddress: optionalString(item.source_address),
    targetAddress: optionalString(item.target_address),
    service: optionalString(item.service),
    detail: optionalString(item.detail),
    length: Number(item.length ?? 0),
    rawData: optionalString(item.raw_data),
    summary: String(item.summary ?? ""),
  };
}

export function asCANFrameSummary(item: any) {
  return {
    packetId: Number(item.packet_id ?? 0),
    time: String(item.time ?? ""),
    identifier: String(item.identifier ?? ""),
    busId: String(item.bus_id ?? ""),
    length: Number(item.length ?? 0),
    rawData: optionalString(item.raw_data),
    isExtended: Boolean(item.is_extended),
    isRTR: Boolean(item.is_rtr),
    isError: Boolean(item.is_error),
    errorFlags: optionalString(item.error_flags),
    summary: String(item.summary ?? ""),
  };
}
