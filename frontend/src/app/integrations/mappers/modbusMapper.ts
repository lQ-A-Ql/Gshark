import type { ModbusAnalysis, ModbusDecodedInput, ModbusSuspiciousWrite, ModbusTransaction } from "../../core/types";
import { asBucket } from "./mapperPrimitives";

export function asModbusAnalysis(input: any): ModbusAnalysis {
  return {
    totalFrames: Number(input.total_frames ?? 0),
    requests: Number(input.requests ?? 0),
    responses: Number(input.responses ?? 0),
    exceptions: Number(input.exceptions ?? 0),
    functionCodes: Array.isArray(input.function_codes) ? input.function_codes.map(asBucket) : [],
    unitIds: Array.isArray(input.unit_ids) ? input.unit_ids.map(asBucket) : [],
    referenceHits: Array.isArray(input.reference_hits) ? input.reference_hits.map(asBucket) : [],
    exceptionCodes: Array.isArray(input.exception_codes) ? input.exception_codes.map(asBucket) : [],
    decodedInputs: Array.isArray(input.decoded_inputs) ? input.decoded_inputs.map(asModbusDecodedInput) : [],
    transactions: Array.isArray(input.transactions) ? input.transactions.map(asModbusTransaction) : [],
  };
}

export function asModbusSuspiciousWrites(input: any): ModbusSuspiciousWrite[] {
  return Array.isArray(input)
    ? input.map((item: any) => ({
        target: String(item.target ?? ""),
        unitId: Number(item.unit_id ?? 0),
        functionCode: Number(item.function_code ?? 0),
        functionName: String(item.function_name ?? ""),
        writeCount: Number(item.write_count ?? 0),
        sources: Array.isArray(item.sources) ? item.sources.map((value: unknown) => String(value ?? "")) : [],
        firstTime: String(item.first_time ?? ""),
        lastTime: String(item.last_time ?? ""),
        sampleValues: Array.isArray(item.sample_values)
          ? item.sample_values.map((value: unknown) => String(value ?? ""))
          : [],
        samplePacketId: Number(item.sample_packet_id ?? 0),
      }))
    : [];
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
