import type { IndustrialControlCommand, IndustrialProtocolDetail, IndustrialRuleHit } from "../../core/types";
import { asArray, asBucket, asPlainObject } from "./mapperPrimitives";

export function asIndustrialControlCommands(input: unknown): IndustrialControlCommand[] {
  return asArray(input).map((value) => {
    const item = asPlainObject(value);
    return {
      packetId: Number(item?.packet_id ?? 0),
      time: String(item?.time ?? ""),
      protocol: String(item?.protocol ?? ""),
      source: String(item?.source ?? ""),
      destination: String(item?.destination ?? ""),
      operation: String(item?.operation ?? ""),
      target: String(item?.target ?? ""),
      value: String(item?.value ?? ""),
      result: String(item?.result ?? ""),
      summary: String(item?.summary ?? ""),
    };
  });
}

export function asIndustrialRuleHits(input: unknown): IndustrialRuleHit[] {
  return asArray(input).map((value) => {
    const item = asPlainObject(value);
    return {
      rule: String(item?.rule ?? ""),
      level: asIndustrialLevel(String(item?.level ?? "low")),
      packetId: Number(item?.packet_id ?? 0) || undefined,
      time: String(item?.time ?? "") || undefined,
      source: String(item?.source ?? "") || undefined,
      destination: String(item?.destination ?? "") || undefined,
      functionCode: Number(item?.function_code ?? 0) || undefined,
      functionName: String(item?.function_name ?? "") || undefined,
      target: String(item?.target ?? "") || undefined,
      evidence: String(item?.evidence ?? "") || undefined,
      summary: String(item?.summary ?? ""),
    };
  });
}

export function asIndustrialDetails(input: unknown): IndustrialProtocolDetail[] {
  return asArray(input).map((value) => {
    const detail = asPlainObject(value);
    return {
      name: String(detail?.name ?? ""),
      totalFrames: Number(detail?.total_frames ?? 0),
      operations: asArray(detail?.operations).map(asBucket),
      targets: asArray(detail?.targets).map(asBucket),
      results: asArray(detail?.results).map(asBucket),
      records: asArray(detail?.records).map(asIndustrialDetailRecord),
    };
  });
}

function asIndustrialDetailRecord(input: unknown): IndustrialProtocolDetail["records"][number] {
  const item = asPlainObject(input);
  return {
    packetId: Number(item?.packet_id ?? 0),
    time: String(item?.time ?? ""),
    source: String(item?.source ?? ""),
    destination: String(item?.destination ?? ""),
    operation: String(item?.operation ?? ""),
    target: String(item?.target ?? "") || undefined,
    result: String(item?.result ?? "") || undefined,
    value: String(item?.value ?? "") || undefined,
    summary: String(item?.summary ?? ""),
  };
}

function asIndustrialLevel(value: string): IndustrialRuleHit["level"] {
  if (value === "critical" || value === "high" || value === "medium" || value === "low") {
    return value;
  }
  return "low";
}
