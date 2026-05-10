import type { ModbusAnalysis } from "../../core/types";
import { asBucket } from "./mapperPrimitives";
import { asModbusDecodedInputs } from "./modbusDecodedInputMapper";
import { asModbusTransactions } from "./modbusTransactionMapper";

export { asModbusSuspiciousWrites } from "./modbusSuspiciousWriteMapper";

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
    decodedInputs: asModbusDecodedInputs(input.decoded_inputs),
    transactions: asModbusTransactions(input.transactions),
  };
}
