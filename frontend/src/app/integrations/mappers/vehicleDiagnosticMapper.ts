import { asBucket, optionalNumber, optionalString } from "./mapperPrimitives";

export function asJ1939Section(input: any) {
  return {
    totalMessages: Number(input?.total_messages ?? 0),
    pgns: Array.isArray(input?.pgns) ? input.pgns.map(asBucket) : [],
    sourceAddrs: Array.isArray(input?.source_addrs) ? input.source_addrs.map(asBucket) : [],
    targetAddrs: Array.isArray(input?.target_addrs) ? input.target_addrs.map(asBucket) : [],
    messages: Array.isArray(input?.messages) ? input.messages.map(asJ1939Message) : [],
  };
}

export function asDoIPSection(input: any) {
  return {
    totalMessages: Number(input?.total_messages ?? 0),
    messageTypes: Array.isArray(input?.message_types) ? input.message_types.map(asBucket) : [],
    vins: Array.isArray(input?.vins) ? input.vins.map(asBucket) : [],
    endpoints: Array.isArray(input?.endpoints) ? input.endpoints.map(asBucket) : [],
    messages: Array.isArray(input?.messages) ? input.messages.map(asDoIPMessage) : [],
  };
}

export function asUDSSection(input: any) {
  return {
    totalMessages: Number(input?.total_messages ?? 0),
    serviceIDs: Array.isArray(input?.service_ids) ? input.service_ids.map(asBucket) : [],
    negativeCodes: Array.isArray(input?.negative_codes) ? input.negative_codes.map(asBucket) : [],
    dtcs: Array.isArray(input?.dtcs) ? input.dtcs.map(asBucket) : [],
    vins: Array.isArray(input?.vins) ? input.vins.map(asBucket) : [],
    messages: Array.isArray(input?.messages) ? input.messages.map(asUDSMessage) : [],
    transactions: Array.isArray(input?.transactions) ? input.transactions.map(asUDSTransaction) : [],
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
    dataPreview: optionalString(item.data_preview),
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
    vin: optionalString(item.vin),
    logicalAddress: optionalString(item.logical_address),
    sourceAddress: optionalString(item.source_address),
    targetAddress: optionalString(item.target_address),
    testerAddress: optionalString(item.tester_address),
    responseCode: optionalString(item.response_code),
    diagnosticState: optionalString(item.diagnostic_state),
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
    subFunction: optionalString(item.sub_function),
    sourceAddress: optionalString(item.source_address),
    targetAddress: optionalString(item.target_address),
    dataIdentifier: optionalString(item.data_identifier),
    diagnosticVIN: optionalString(item.diagnostic_vin),
    dtc: optionalString(item.dtc),
    negativeCode: optionalString(item.negative_code),
    summary: String(item.summary ?? ""),
  };
}

function asUDSTransaction(item: any) {
  return {
    requestPacketId: Number(item.request_packet_id ?? 0),
    responsePacketId: optionalNumber(item.response_packet_id),
    requestTime: String(item.request_time ?? ""),
    responseTime: optionalString(item.response_time),
    sourceAddress: optionalString(item.source_address),
    targetAddress: optionalString(item.target_address),
    serviceId: String(item.service_id ?? ""),
    serviceName: String(item.service_name ?? ""),
    subFunction: optionalString(item.sub_function),
    dataIdentifier: optionalString(item.data_identifier),
    dtc: optionalString(item.dtc),
    status: String(item.status ?? ""),
    negativeCode: optionalString(item.negative_code),
    latencyMs: optionalNumber(item.latency_ms),
    requestSummary: optionalString(item.request_summary),
    responseSummary: optionalString(item.response_summary),
  };
}
