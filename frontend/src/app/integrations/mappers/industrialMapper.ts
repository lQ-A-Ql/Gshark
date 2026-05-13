import type { IndustrialAnalysis } from "../../core/types";
import { asInvestigationReport } from "./investigationReportMapper";
import { asArray, asBucket, asConversation, asPlainObject, asStringList } from "./mapperPrimitives";
import { asIndustrialControlCommands, asIndustrialDetails, asIndustrialRuleHits } from "./industrialDetailMapper";
import { asModbusAnalysis, asModbusSuspiciousWrites } from "./modbusMapper";

interface IndustrialAnalysisWire {
  total_industrial_packets?: unknown;
  protocols?: unknown;
  conversations?: unknown;
  modbus?: unknown;
  suspicious_writes?: unknown;
  control_commands?: unknown;
  rule_hits?: unknown;
  details?: unknown;
  notes?: unknown;
  report?: unknown;
}

export function asIndustrialAnalysis(input: unknown): IndustrialAnalysis {
  const payload = asPlainObject(input) as IndustrialAnalysisWire | undefined;
  return {
    totalIndustrialPackets: Number(payload?.total_industrial_packets ?? 0),
    protocols: asArray(payload?.protocols).map(asBucket),
    conversations: asArray(payload?.conversations).map(asConversation),
    modbus: asModbusAnalysis(payload?.modbus ?? {}),
    suspiciousWrites: asModbusSuspiciousWrites(payload?.suspicious_writes),
    controlCommands: asIndustrialControlCommands(payload?.control_commands),
    ruleHits: asIndustrialRuleHits(payload?.rule_hits),
    details: asIndustrialDetails(payload?.details),
    notes: asStringList(payload?.notes),
    report: asInvestigationReport(payload?.report),
  };
}
