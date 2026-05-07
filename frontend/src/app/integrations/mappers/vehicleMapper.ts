import type { VehicleAnalysis } from "../../core/types";
import { asBucket, asConversation } from "./mapperPrimitives";

function asCANPayloadRecord(item: any) {
  return {
    packetId: Number(item.packet_id ?? 0),
    time: String(item.time ?? ""),
    busId: String(item.bus_id ?? ""),
    identifier: String(item.identifier ?? ""),
    protocol: String(item.protocol ?? ""),
    frameType: String(item.frame_type ?? "") || undefined,
    sourceAddress: String(item.source_address ?? "") || undefined,
    targetAddress: String(item.target_address ?? "") || undefined,
    service: String(item.service ?? "") || undefined,
    detail: String(item.detail ?? "") || undefined,
    length: Number(item.length ?? 0),
    rawData: String(item.raw_data ?? "") || undefined,
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
    sender: String(item.sender ?? "") || undefined,
    signals: Array.isArray(item.signals)
      ? item.signals.map((signal: any) => ({
          name: String(signal.name ?? ""),
          value: String(signal.value ?? ""),
          unit: String(signal.unit ?? "") || undefined,
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
          unit: String(sample.unit ?? "") || undefined,
          messageName: String(sample.message_name ?? "") || undefined,
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
    rawData: String(item.raw_data ?? "") || undefined,
    isExtended: Boolean(item.is_extended),
    isRTR: Boolean(item.is_rtr),
    isError: Boolean(item.is_error),
    errorFlags: String(item.error_flags ?? "") || undefined,
    summary: String(item.summary ?? ""),
  };
}

function asJ1939Message(item: any) {
  return {
    packetId: Number(item.packet_id ?? 0),
    time: String(item.time ?? ""),
    canId: String(item.can_id ?? ""),
    pgn: String(item.pgn ?? ""),
    priority: Number(item.priority ?? 0),
    sourceAddr: String(item.source_addr ?? ""),
    targetAddr: String(item.target_addr ?? ""),
    dataPreview: String(item.data_preview ?? "") || undefined,
    summary: String(item.summary ?? ""),
  };
}

function asDoIPMessage(item: any) {
  return {
    packetId: Number(item.packet_id ?? 0),
    time: String(item.time ?? ""),
    source: String(item.source ?? ""),
    destination: String(item.destination ?? ""),
    type: String(item.type ?? ""),
    vin: String(item.vin ?? "") || undefined,
    logicalAddress: String(item.logical_address ?? "") || undefined,
    sourceAddress: String(item.source_address ?? "") || undefined,
    targetAddress: String(item.target_address ?? "") || undefined,
    testerAddress: String(item.tester_address ?? "") || undefined,
    responseCode: String(item.response_code ?? "") || undefined,
    diagnosticState: String(item.diagnostic_state ?? "") || undefined,
    summary: String(item.summary ?? ""),
  };
}

function asUDSMessage(item: any) {
  return {
    packetId: Number(item.packet_id ?? 0),
    time: String(item.time ?? ""),
    serviceId: String(item.service_id ?? ""),
    serviceName: String(item.service_name ?? ""),
    isReply: Boolean(item.is_reply),
    subFunction: String(item.sub_function ?? "") || undefined,
    sourceAddress: String(item.source_address ?? "") || undefined,
    targetAddress: String(item.target_address ?? "") || undefined,
    dataIdentifier: String(item.data_identifier ?? "") || undefined,
    diagnosticVIN: String(item.diagnostic_vin ?? "") || undefined,
    dtc: String(item.dtc ?? "") || undefined,
    negativeCode: String(item.negative_code ?? "") || undefined,
    summary: String(item.summary ?? ""),
  };
}

function asUDSTransaction(item: any) {
  return {
    requestPacketId: Number(item.request_packet_id ?? 0),
    responsePacketId: Number(item.response_packet_id ?? 0) || undefined,
    requestTime: String(item.request_time ?? ""),
    responseTime: String(item.response_time ?? "") || undefined,
    sourceAddress: String(item.source_address ?? "") || undefined,
    targetAddress: String(item.target_address ?? "") || undefined,
    serviceId: String(item.service_id ?? ""),
    serviceName: String(item.service_name ?? ""),
    subFunction: String(item.sub_function ?? "") || undefined,
    dataIdentifier: String(item.data_identifier ?? "") || undefined,
    dtc: String(item.dtc ?? "") || undefined,
    status: String(item.status ?? ""),
    negativeCode: String(item.negative_code ?? "") || undefined,
    latencyMs: Number(item.latency_ms ?? 0) || undefined,
    requestSummary: String(item.request_summary ?? "") || undefined,
    responseSummary: String(item.response_summary ?? "") || undefined,
  };
}

export function asVehicleAnalysis(payload: any): VehicleAnalysis {
  return {
    totalVehiclePackets: Number(payload?.total_vehicle_packets ?? 0),
    protocols: Array.isArray(payload?.protocols) ? payload.protocols.map(asBucket) : [],
    conversations: Array.isArray(payload?.conversations) ? payload.conversations.map(asConversation) : [],
    can: {
      totalFrames: Number(payload?.can?.total_frames ?? 0),
      extendedFrames: Number(payload?.can?.extended_frames ?? 0),
      rtrFrames: Number(payload?.can?.rtr_frames ?? 0),
      errorFrames: Number(payload?.can?.error_frames ?? 0),
      busIds: Array.isArray(payload?.can?.bus_ids) ? payload.can.bus_ids.map(asBucket) : [],
      messageIds: Array.isArray(payload?.can?.message_ids) ? payload.can.message_ids.map(asBucket) : [],
      payloadProtocols: Array.isArray(payload?.can?.payload_protocols)
        ? payload.can.payload_protocols.map(asBucket)
        : [],
      payloadRecords: Array.isArray(payload?.can?.payload_records)
        ? payload.can.payload_records.map(asCANPayloadRecord)
        : [],
      dbcProfiles: Array.isArray(payload?.can?.dbc_profiles) ? payload.can.dbc_profiles.map(asDBCProfile) : [],
      decodedMessageDist: Array.isArray(payload?.can?.decoded_message_dist)
        ? payload.can.decoded_message_dist.map(asBucket)
        : [],
      decodedSignals: Array.isArray(payload?.can?.decoded_signals) ? payload.can.decoded_signals.map(asBucket) : [],
      decodedMessages: Array.isArray(payload?.can?.decoded_messages)
        ? payload.can.decoded_messages.map(asCANDBCMessage)
        : [],
      signalTimelines: Array.isArray(payload?.can?.signal_timelines)
        ? payload.can.signal_timelines.map(asCANSignalTimeline)
        : [],
      frames: Array.isArray(payload?.can?.frames) ? payload.can.frames.map(asCANFrameSummary) : [],
    },
    j1939: {
      totalMessages: Number(payload?.j1939?.total_messages ?? 0),
      pgns: Array.isArray(payload?.j1939?.pgns) ? payload.j1939.pgns.map(asBucket) : [],
      sourceAddrs: Array.isArray(payload?.j1939?.source_addrs) ? payload.j1939.source_addrs.map(asBucket) : [],
      targetAddrs: Array.isArray(payload?.j1939?.target_addrs) ? payload.j1939.target_addrs.map(asBucket) : [],
      messages: Array.isArray(payload?.j1939?.messages) ? payload.j1939.messages.map(asJ1939Message) : [],
    },
    doip: {
      totalMessages: Number(payload?.doip?.total_messages ?? 0),
      messageTypes: Array.isArray(payload?.doip?.message_types) ? payload.doip.message_types.map(asBucket) : [],
      vins: Array.isArray(payload?.doip?.vins) ? payload.doip.vins.map(asBucket) : [],
      endpoints: Array.isArray(payload?.doip?.endpoints) ? payload.doip.endpoints.map(asBucket) : [],
      messages: Array.isArray(payload?.doip?.messages) ? payload.doip.messages.map(asDoIPMessage) : [],
    },
    uds: {
      totalMessages: Number(payload?.uds?.total_messages ?? 0),
      serviceIDs: Array.isArray(payload?.uds?.service_ids) ? payload.uds.service_ids.map(asBucket) : [],
      negativeCodes: Array.isArray(payload?.uds?.negative_codes) ? payload.uds.negative_codes.map(asBucket) : [],
      dtcs: Array.isArray(payload?.uds?.dtcs) ? payload.uds.dtcs.map(asBucket) : [],
      vins: Array.isArray(payload?.uds?.vins) ? payload.uds.vins.map(asBucket) : [],
      messages: Array.isArray(payload?.uds?.messages) ? payload.uds.messages.map(asUDSMessage) : [],
      transactions: Array.isArray(payload?.uds?.transactions) ? payload.uds.transactions.map(asUDSTransaction) : [],
    },
    recommendations: Array.isArray(payload?.recommendations)
      ? payload.recommendations.map((item: unknown) => String(item ?? ""))
      : [],
  };
}
