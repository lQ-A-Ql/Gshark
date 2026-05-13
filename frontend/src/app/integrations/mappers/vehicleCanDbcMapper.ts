import { asArray, asPlainObject, optionalString } from "./mapperPrimitives";

export function asDBCProfile(input: unknown) {
  const item = asPlainObject(input) ?? {};
  return {
    path: String(item.path ?? ""),
    name: String(item.name ?? ""),
    messageCount: Number(item.message_count ?? 0),
    signalCount: Number(item.signal_count ?? 0),
  };
}

export function asCANDBCMessage(input: unknown) {
  const item = asPlainObject(input) ?? {};
  return {
    packetId: Number(item.packet_id ?? 0),
    time: String(item.time ?? ""),
    busId: String(item.bus_id ?? ""),
    identifier: String(item.identifier ?? ""),
    database: String(item.database ?? ""),
    messageName: String(item.message_name ?? ""),
    sender: optionalString(item.sender),
    signals: asArray(item.signals).map(asCANSignalValue),
    summary: String(item.summary ?? ""),
  };
}

export function asCANSignalTimeline(input: unknown) {
  const item = asPlainObject(input) ?? {};
  return {
    name: String(item.name ?? ""),
    samples: asArray(item.samples).map(asCANSignalSample),
  };
}

function asCANSignalValue(input: unknown) {
  const signal = asPlainObject(input) ?? {};
  return { name: String(signal.name ?? ""), value: String(signal.value ?? ""), unit: optionalString(signal.unit) };
}

function asCANSignalSample(input: unknown) {
  const sample = asPlainObject(input) ?? {};
  return {
    packetId: Number(sample.packet_id ?? 0),
    time: String(sample.time ?? ""),
    value: Number(sample.value ?? 0),
    unit: optionalString(sample.unit),
    messageName: optionalString(sample.message_name),
  };
}
