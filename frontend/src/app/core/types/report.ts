export type InvestigationSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface InvestigationReportItem {
  title: string;
  summary?: string;
  severity?: InvestigationSeverity;
  packetId?: number;
  streamId?: number;
  tags?: string[];
}

export interface InvestigationReport {
  summary: InvestigationReportItem[];
  evidence: InvestigationReportItem[];
  details: InvestigationReportItem[];
  recommendations: string[];
}

export const EMPTY_INVESTIGATION_REPORT: InvestigationReport = {
  summary: [],
  evidence: [],
  details: [],
  recommendations: [],
};
