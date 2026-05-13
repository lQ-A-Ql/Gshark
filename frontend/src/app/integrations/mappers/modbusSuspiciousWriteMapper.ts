import type { ModbusSuspiciousWrite } from "../../core/types";
import { asArray, asPlainObject, asStringList } from "./mapperPrimitives";

export function asModbusSuspiciousWrites(input: unknown): ModbusSuspiciousWrite[] {
  return asArray(input).map((value) => {
    const item = asPlainObject(value);
    return {
      target: String(item?.target ?? ""),
      unitId: Number(item?.unit_id ?? 0),
      functionCode: Number(item?.function_code ?? 0),
      functionName: String(item?.function_name ?? ""),
      writeCount: Number(item?.write_count ?? 0),
      sources: asStringList(item?.sources),
      firstTime: String(item?.first_time ?? ""),
      lastTime: String(item?.last_time ?? ""),
      sampleValues: asStringList(item?.sample_values),
      samplePacketId: Number(item?.sample_packet_id ?? 0),
    };
  });
}
