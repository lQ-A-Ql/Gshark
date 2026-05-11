import type { InvestigationReport, InvestigationReportItem } from "../../core/types";
import { asStringList, optionalNumber, optionalString } from "./mapperPrimitives";

function asInvestigationReportItem(input: any): InvestigationReportItem {
  return {
    title: String(input?.title ?? ""),
    summary: optionalString(input?.summary),
    severity: optionalString(input?.severity) as InvestigationReportItem["severity"],
    packetId: optionalNumber(input?.packet_id),
    streamId: optionalNumber(input?.stream_id),
    tags: asStringList(input?.tags),
  };
}

function asInvestigationReportItems(input: any): InvestigationReportItem[] {
  return Array.isArray(input) ? input.map(asInvestigationReportItem).filter((item) => item.title) : [];
}

export function asInvestigationReport(input: any): InvestigationReport {
  return {
    summary: asInvestigationReportItems(input?.summary),
    evidence: asInvestigationReportItems(input?.evidence),
    details: asInvestigationReportItems(input?.details),
    recommendations: asStringList(input?.recommendations),
  };
}
