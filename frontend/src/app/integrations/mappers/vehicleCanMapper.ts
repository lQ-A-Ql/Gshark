import { asBucket, optionalString } from "./mapperPrimitives";

export function asCANSection(input: any) {
  return {
    totalFrames: Number(input?.total_frames ?? 0),
    extendedFrames: Number(input?.extended_frames ?? 0),
    rtrFrames: Number(input?.rtr_frames ?? 0),
    errorFrames: Number(input?.error_frames ?? 0),
    busIds: Array.isArray(input?.bus_ids) ? input.bus_ids.map(asBucket) : [],
    messageIds: Array.isArray(input?.message_ids) ? input.message_ids.map(asBucket) : [],
    payloadProtocols: Array.isArray(input?.payload_protocols) ? input.payload_protocols.map(asBucket) : [],
    payloadRecords: Array.isArray(input?.payload_records) ? input.payload_records.map(asCANPayloadRecord) : [],
    dbcProfiles: Array.isArray(input?.dbc_profiles) ? input.dbc_profiles.map(asDBCProfile) : [],
    decodedMessageDist: Array.isArray(input?.decoded_message_dist) ? input.decoded_message_dist.map(asBucket) : [],
    decodedSignals: Array.isArray(input?.decoded_signals) ? input.decoded_signals.map(asBucket) : [],
    decodedMessages: Array.isArray(input?.decoded_messages) ? input.decoded_messages.map(asCANDBCMessage) : [],
    signalTimelines: Array.isArray(input?.signal_timelines) ? input.signal_timelines.map(asCANSignalTimeline) : [],
    frames: Array.isArray(input?.frames) ? input.frames.map(asCANFrameSummary) : [],
  };
}

function asCANPayloadRecord(item: any) {
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

function asDBCProfile(item: any) {
  return {
    path: String(item.path ?? ""),
    name: String(item.name ?? ""),
    messageCount: Number(item.message_count ?? 0),
    signalCount: Number(item.signal_count ?? 0),
  };
}

function asCANDBCMessage(item: any) {
  return {
    packetId: Number(item.packet_id ?? 0),
    time: String(item.time ?? ""),
    busId: String(item.bus_id ?? ""),
    identifier: String(item.identifier ?? ""),
    database: String(item.database ?? ""),
    messageName: String(item.message_name ?? ""),
    sender: optionalString(item.sender),
    signals: Array.isArray(item.signals)
      ? item.signals.map((signal: any) => ({
          name: String(signal.name ?? ""),
          value: String(signal.value ?? ""),
          unit: optionalString(signal.unit),
        }))
      : [],
    summary: String(item.summary ?? ""),
  };
}

function asCANSignalTimeline(item: any) {
  return {
    name: String(item.name ?? ""),
    samples: Array.isArray(item.samples)
      ? item.samples.map((sample: any) => ({
          packetId: Number(sample.packet_id ?? 0),
          time: String(sample.time ?? ""),
          value: Number(sample.value ?? 0),
          unit: optionalString(sample.unit),
          messageName: optionalString(sample.message_name),
        }))
      : [],
  };
}

function asCANFrameSummary(item: any) {
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
