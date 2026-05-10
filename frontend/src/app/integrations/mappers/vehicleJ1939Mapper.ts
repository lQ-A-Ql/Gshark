import { asBucket, optionalString } from "./mapperPrimitives";

export function asJ1939Section(input: any) {
  return {
    totalMessages: Number(input?.total_messages ?? 0),
    pgns: Array.isArray(input?.pgns) ? input.pgns.map(asBucket) : [],
    sourceAddrs: Array.isArray(input?.source_addrs) ? input.source_addrs.map(asBucket) : [],
    targetAddrs: Array.isArray(input?.target_addrs) ? input.target_addrs.map(asBucket) : [],
    messages: Array.isArray(input?.messages) ? input.messages.map(asJ1939Message) : [],
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
