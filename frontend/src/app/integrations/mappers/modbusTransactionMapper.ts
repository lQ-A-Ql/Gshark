import type { ModbusTransaction } from "../../core/types";
import { asArray, asPlainObject } from "./mapperPrimitives";

export function asModbusTransactions(input: unknown): ModbusTransaction[] {
  return asArray(input).map(asModbusTransaction);
}

function asModbusTransaction(input: unknown): ModbusTransaction {
  const item = asPlainObject(input);
  return {
    packetId: Number(item?.packet_id ?? 0),
    time: String(item?.time ?? ""),
    source: String(item?.source ?? ""),
    destination: String(item?.destination ?? ""),
    transactionId: Number(item?.transaction_id ?? 0),
    unitId: Number(item?.unit_id ?? 0),
    functionCode: Number(item?.function_code ?? 0),
    functionName: String(item?.function_name ?? ""),
    kind: String(item?.kind ?? ""),
    reference: String(item?.reference ?? ""),
    quantity: String(item?.quantity ?? ""),
    exceptionCode: Number(item?.exception_code ?? 0),
    responseTime: String(item?.response_time ?? ""),
    registerValues: String(item?.register_values ?? "") || undefined,
    inputText: String(item?.input_text ?? "") || undefined,
    bitRange: asModbusBitRange(item?.bit_range),
    summary: String(item?.summary ?? ""),
  };
}

function asModbusBitRange(input: unknown): ModbusTransaction["bitRange"] {
  const payload = asPlainObject(input);
  if (!payload) return undefined;
  return {
    type: String(payload.type ?? "") || undefined,
    start: Number(payload.start ?? 0) || undefined,
    count: Number(payload.count ?? 0) || undefined,
    values: Array.isArray(payload.values) ? payload.values.map((value: unknown) => Boolean(value)) : undefined,
    preview: String(payload.preview ?? "") || undefined,
  };
}
