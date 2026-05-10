import type { ModbusTransaction } from "../../core/types";

export function asModbusTransactions(input: any): ModbusTransaction[] {
  return Array.isArray(input) ? input.map(asModbusTransaction) : [];
}

function asModbusTransaction(item: any): ModbusTransaction {
  return {
    packetId: Number(item.packet_id ?? 0),
    time: String(item.time ?? ""),
    source: String(item.source ?? ""),
    destination: String(item.destination ?? ""),
    transactionId: Number(item.transaction_id ?? 0),
    unitId: Number(item.unit_id ?? 0),
    functionCode: Number(item.function_code ?? 0),
    functionName: String(item.function_name ?? ""),
    kind: String(item.kind ?? ""),
    reference: String(item.reference ?? ""),
    quantity: String(item.quantity ?? ""),
    exceptionCode: Number(item.exception_code ?? 0),
    responseTime: String(item.response_time ?? ""),
    registerValues: String(item.register_values ?? "") || undefined,
    inputText: String(item.input_text ?? "") || undefined,
    bitRange: asModbusBitRange(item.bit_range),
    summary: String(item.summary ?? ""),
  };
}

function asModbusBitRange(input: any): ModbusTransaction["bitRange"] {
  if (!input || typeof input !== "object") return undefined;
  return {
    type: String(input.type ?? "") || undefined,
    start: Number(input.start ?? 0) || undefined,
    count: Number(input.count ?? 0) || undefined,
    values: Array.isArray(input.values) ? input.values.map((value: unknown) => Boolean(value)) : undefined,
    preview: String(input.preview ?? "") || undefined,
  };
}
