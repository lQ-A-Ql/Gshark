import type { ModbusDecodedInput } from "../../core/types";

export function asModbusDecodedInputs(input: any): ModbusDecodedInput[] {
  return Array.isArray(input) ? input.map(asModbusDecodedInput) : [];
}

function asModbusDecodedInput(item: any): ModbusDecodedInput {
  return {
    startPacketId: Number(item.start_packet_id ?? 0),
    endPacketId: Number(item.end_packet_id ?? 0),
    source: String(item.source ?? "") || undefined,
    destination: String(item.destination ?? "") || undefined,
    unitId: Number(item.unit_id ?? 0) || undefined,
    functionCode: Number(item.function_code ?? 0) || undefined,
    functionName: String(item.function_name ?? "") || undefined,
    reference: String(item.reference ?? "") || undefined,
    encoding: String(item.encoding ?? ""),
    text: String(item.text ?? ""),
    rawText: String(item.raw_text ?? "") || undefined,
    summary: String(item.summary ?? "") || undefined,
  };
}
