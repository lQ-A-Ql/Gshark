import { asArray, asBucket, asPlainObject, optionalString } from "./mapperPrimitives";

export function asJ1939Section(input: unknown) {
  const payload = asPlainObject(input) ?? {};
  return {
    totalMessages: Number(payload.total_messages ?? 0),
    pgns: asArray(payload.pgns).map(asBucket),
    sourceAddrs: asArray(payload.source_addrs).map(asBucket),
    targetAddrs: asArray(payload.target_addrs).map(asBucket),
    messages: asArray(payload.messages).map(asJ1939Message),
  };
}

function asJ1939Message(input: unknown) {
  const item = asPlainObject(input) ?? {};
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
