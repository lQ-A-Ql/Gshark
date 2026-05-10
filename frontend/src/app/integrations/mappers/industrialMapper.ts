import type { IndustrialAnalysis } from "../../core/types";
import { asBucket, asConversation } from "./mapperPrimitives";
import { asIndustrialControlCommands, asIndustrialDetails, asIndustrialRuleHits } from "./industrialDetailMapper";
import { asModbusAnalysis, asModbusSuspiciousWrites } from "./modbusMapper";

export function asIndustrialAnalysis(payload: any): IndustrialAnalysis {
  return {
    totalIndustrialPackets: Number(payload.total_industrial_packets ?? 0),
    protocols: Array.isArray(payload.protocols) ? payload.protocols.map(asBucket) : [],
    conversations: Array.isArray(payload.conversations) ? payload.conversations.map(asConversation) : [],
    modbus: asModbusAnalysis(payload.modbus ?? {}),
    suspiciousWrites: asModbusSuspiciousWrites(payload.suspicious_writes),
    controlCommands: asIndustrialControlCommands(payload.control_commands),
    ruleHits: asIndustrialRuleHits(payload.rule_hits),
    details: asIndustrialDetails(payload.details),
    notes: Array.isArray(payload.notes) ? payload.notes.map((item: unknown) => String(item ?? "")) : [],
  };
}
