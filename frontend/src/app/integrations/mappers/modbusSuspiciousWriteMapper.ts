import type { ModbusSuspiciousWrite } from "../../core/types";

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
