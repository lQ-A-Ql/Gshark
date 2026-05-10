import { asBucket, optionalString } from "./mapperPrimitives";

export function asDoIPSection(input: any) {
  return {
    totalMessages: Number(input?.total_messages ?? 0),
    messageTypes: Array.isArray(input?.message_types) ? input.message_types.map(asBucket) : [],
    vins: Array.isArray(input?.vins) ? input.vins.map(asBucket) : [],
    endpoints: Array.isArray(input?.endpoints) ? input.endpoints.map(asBucket) : [],
    messages: Array.isArray(input?.messages) ? input.messages.map(asDoIPMessage) : [],
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
