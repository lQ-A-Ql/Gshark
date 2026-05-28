import type { InvestigationReport, InvestigationReportItem, InvestigationSeverity } from "../../core/types";
import type { InvestigationReportItemWireDTO, InvestigationReportWireDTO } from "../wire/reportWireDtos";
import { asPlainObject, asStringList, optionalNumber, optionalString } from "./mapperPrimitives";

const VALID_SEVERITIES = new Set<string>(["critical", "high", "medium", "low", "info"]);

function asInvestigationSeverity(raw: unknown): InvestigationSeverity | undefined {
  const s = optionalString(raw)?.toLowerCase();
  if (!s) return undefined;
  return VALID_SEVERITIES.has(s) ? (s as InvestigationSeverity) : undefined;
}

function asInvestigationReportItem(input: unknown): InvestigationReportItem {
  const raw: InvestigationReportItemWireDTO = asPlainObject(input) ?? {};
  return {
    title: String(raw.title ?? ""),
    summary: optionalString(raw.summary),
    severity: asInvestigationSeverity(raw.severity),
    packetId: optionalNumber(raw.packet_id),
    streamId: optionalNumber(raw.stream_id),
    ruleId: optionalString(raw.rule_id),
    reason: optionalString(raw.reason),
    confidence: optionalNumber(raw.confidence),
    caveats: asStringList(raw.caveats),
    tags: asStringList(raw.tags),
  };
}
const asItems = (input: unknown) =>
  Array.isArray(input) ? input.map(asInvestigationReportItem).filter((item) => item.title) : [];
export function asInvestigationReport(input: unknown): InvestigationReport {
  const report: InvestigationReportWireDTO = asPlainObject(input) ?? {};
  return {
    summary: asItems(report.summary),
    evidence: asItems(report.evidence),
    details: asItems(report.details),
    recommendations: asStringList(report.recommendations),
  };
}
