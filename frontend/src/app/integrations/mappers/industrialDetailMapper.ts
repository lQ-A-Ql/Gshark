import type { IndustrialControlCommand, IndustrialProtocolDetail, IndustrialRuleHit } from "../../core/types";
import { asBucket } from "./mapperPrimitives";

export function asIndustrialControlCommands(input: any): IndustrialControlCommand[] {
  return Array.isArray(input)
    ? input.map((item: any) => ({
        packetId: Number(item.packet_id ?? 0),
        time: String(item.time ?? ""),
        protocol: String(item.protocol ?? ""),
        source: String(item.source ?? ""),
        destination: String(item.destination ?? ""),
        operation: String(item.operation ?? ""),
        target: String(item.target ?? ""),
        value: String(item.value ?? ""),
        result: String(item.result ?? ""),
        summary: String(item.summary ?? ""),
      }))
    : [];
}

export function asIndustrialRuleHits(input: any): IndustrialRuleHit[] {
  return Array.isArray(input)
    ? input.map((item: any) => ({
        rule: String(item.rule ?? ""),
        level: asIndustrialLevel(String(item.level ?? "low")),
        packetId: Number(item.packet_id ?? 0) || undefined,
        time: String(item.time ?? "") || undefined,
        source: String(item.source ?? "") || undefined,
        destination: String(item.destination ?? "") || undefined,
        functionCode: Number(item.function_code ?? 0) || undefined,
        functionName: String(item.function_name ?? "") || undefined,
        target: String(item.target ?? "") || undefined,
        evidence: String(item.evidence ?? "") || undefined,
        summary: String(item.summary ?? ""),
      }))
    : [];
}

export function asIndustrialDetails(input: any): IndustrialProtocolDetail[] {
  return Array.isArray(input)
    ? input.map((detail: any) => ({
        name: String(detail.name ?? ""),
        totalFrames: Number(detail.total_frames ?? 0),
        operations: Array.isArray(detail.operations) ? detail.operations.map(asBucket) : [],
        targets: Array.isArray(detail.targets) ? detail.targets.map(asBucket) : [],
        results: Array.isArray(detail.results) ? detail.results.map(asBucket) : [],
        records: Array.isArray(detail.records)
          ? detail.records.map((item: any) => ({
              packetId: Number(item.packet_id ?? 0),
              time: String(item.time ?? ""),
              source: String(item.source ?? ""),
              destination: String(item.destination ?? ""),
              operation: String(item.operation ?? ""),
              target: String(item.target ?? "") || undefined,
              result: String(item.result ?? "") || undefined,
              value: String(item.value ?? "") || undefined,
              summary: String(item.summary ?? ""),
            }))
          : [],
      }))
    : [];
}

function asIndustrialLevel(value: string): IndustrialRuleHit["level"] {
  if (value === "critical" || value === "high" || value === "medium" || value === "low") {
    return value;
  }
  return "low";
}
