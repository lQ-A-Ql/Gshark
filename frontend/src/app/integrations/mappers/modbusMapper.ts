import type { ModbusAnalysis } from "../../core/types";
import { asArray, asBucket, asPlainObject } from "./mapperPrimitives";
import { asModbusDecodedInputs } from "./modbusDecodedInputMapper";
import { asModbusTransactions } from "./modbusTransactionMapper";

export { asModbusSuspiciousWrites } from "./modbusSuspiciousWriteMapper";

export function asModbusAnalysis(input: unknown): ModbusAnalysis {
  const payload = asPlainObject(input);
  return {
    totalFrames: Number(payload?.total_frames ?? 0),
    requests: Number(payload?.requests ?? 0),
    responses: Number(payload?.responses ?? 0),
    exceptions: Number(payload?.exceptions ?? 0),
    functionCodes: asArray(payload?.function_codes).map(asBucket),
    unitIds: asArray(payload?.unit_ids).map(asBucket),
    referenceHits: asArray(payload?.reference_hits).map(asBucket),
    exceptionCodes: asArray(payload?.exception_codes).map(asBucket),
    decodedInputs: asModbusDecodedInputs(payload?.decoded_inputs),
    transactions: asModbusTransactions(payload?.transactions),
  };
}
