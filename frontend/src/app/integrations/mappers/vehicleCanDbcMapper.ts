import { optionalString } from "./mapperPrimitives";

export function asDBCProfile(item: any) {
  return {
    path: String(item.path ?? ""),
    name: String(item.name ?? ""),
    messageCount: Number(item.message_count ?? 0),
    signalCount: Number(item.signal_count ?? 0),
  };
}

export function asCANDBCMessage(item: any) {
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

export function asCANSignalTimeline(item: any) {
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
