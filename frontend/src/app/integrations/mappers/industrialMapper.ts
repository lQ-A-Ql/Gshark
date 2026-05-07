import type { IndustrialAnalysis, IndustrialRuleHit } from "../../core/types";
import { asBucket, asConversation } from "./mapperPrimitives";

function asIndustrialLevel(value: string): IndustrialRuleHit["level"] {
  if (value === "critical" || value === "high" || value === "medium" || value === "low") {
    return value;
  }
  return "low";
}

export function asIndustrialAnalysis(payload: any): IndustrialAnalysis {
  return {
    totalIndustrialPackets: Number(payload.total_industrial_packets ?? 0),
    protocols: Array.isArray(payload.protocols) ? payload.protocols.map(asBucket) : [],
    conversations: Array.isArray(payload.conversations) ? payload.conversations.map(asConversation) : [],
    modbus: {
      totalFrames: Number(payload.modbus?.total_frames ?? 0),
      requests: Number(payload.modbus?.requests ?? 0),
      responses: Number(payload.modbus?.responses ?? 0),
      exceptions: Number(payload.modbus?.exceptions ?? 0),
      functionCodes: Array.isArray(payload.modbus?.function_codes) ? payload.modbus.function_codes.map(asBucket) : [],
      unitIds: Array.isArray(payload.modbus?.unit_ids) ? payload.modbus.unit_ids.map(asBucket) : [],
      referenceHits: Array.isArray(payload.modbus?.reference_hits) ? payload.modbus.reference_hits.map(asBucket) : [],
      exceptionCodes: Array.isArray(payload.modbus?.exception_codes)
        ? payload.modbus.exception_codes.map(asBucket)
        : [],
      decodedInputs: Array.isArray(payload.modbus?.decoded_inputs)
        ? payload.modbus.decoded_inputs.map((item: any) => ({
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
          }))
        : [],
      transactions: Array.isArray(payload.modbus?.transactions)
        ? payload.modbus.transactions.map((item: any) => ({
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
            bitRange:
              item.bit_range && typeof item.bit_range === "object"
                ? {
                    type: String(item.bit_range.type ?? "") || undefined,
                    start: Number(item.bit_range.start ?? 0) || undefined,
                    count: Number(item.bit_range.count ?? 0) || undefined,
                    values: Array.isArray(item.bit_range.values)
                      ? item.bit_range.values.map((value: unknown) => Boolean(value))
                      : undefined,
                    preview: String(item.bit_range.preview ?? "") || undefined,
                  }
                : undefined,
            summary: String(item.summary ?? ""),
          }))
        : [],
    },
    suspiciousWrites: Array.isArray(payload.suspicious_writes)
      ? payload.suspicious_writes.map((item: any) => ({
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
      : [],
    controlCommands: Array.isArray(payload.control_commands)
      ? payload.control_commands.map((item: any) => ({
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
      : [],
    ruleHits: Array.isArray(payload.rule_hits)
      ? payload.rule_hits.map((item: any) => ({
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
      : [],
    details: Array.isArray(payload.details)
      ? payload.details.map((detail: any) => ({
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
      : [],
    notes: Array.isArray(payload.notes) ? payload.notes.map((item: unknown) => String(item ?? "")) : [],
  };
}
