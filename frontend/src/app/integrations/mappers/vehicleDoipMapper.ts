import { asArray, asBucket, asPlainObject, optionalString } from "./mapperPrimitives";

export function asDoIPSection(input: unknown) {
  const payload = asPlainObject(input) ?? {};
  return {
    totalMessages: Number(payload.total_messages ?? 0),
    messageTypes: asArray(payload.message_types).map(asBucket),
    vins: asArray(payload.vins).map(asBucket),
    endpoints: asArray(payload.endpoints).map(asBucket),
    messages: asArray(payload.messages).map(asDoIPMessage),
  };
}

function asDoIPMessage(input: unknown) {
  const item = asPlainObject(input) ?? {};
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
