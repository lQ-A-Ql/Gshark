import { asArray, asBucket, asPlainObject, optionalNumber, optionalString } from "./mapperPrimitives";

export function asUDSSection(input: unknown) {
  const payload = asPlainObject(input) ?? {};
  return {
    totalMessages: Number(payload.total_messages ?? 0),
    serviceIDs: asArray(payload.service_ids).map(asBucket),
    negativeCodes: asArray(payload.negative_codes).map(asBucket),
    dtcs: asArray(payload.dtcs).map(asBucket),
    vins: asArray(payload.vins).map(asBucket),
    messages: asArray(payload.messages).map(asUDSMessage),
    transactions: asArray(payload.transactions).map(asUDSTransaction),
  };
}

function asUDSMessage(input: unknown) {
  const item = asPlainObject(input) ?? {};
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

function asUDSTransaction(input: unknown) {
  const item = asPlainObject(input) ?? {};
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
