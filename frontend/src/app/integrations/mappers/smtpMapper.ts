import type { SMTPAnalysis } from "../../core/types";
import type { SMTPAnalysisWireDTO } from "../wire/protocolToolWireDtos";
import { asInvestigationReport } from "./investigationReportMapper";
import { asArray, asPlainObject, asStringList } from "./mapperPrimitives";
import { asSMTPSession } from "./smtpRecordMapper";

export function asSMTPAnalysis(input: unknown): SMTPAnalysis {
  const payload: SMTPAnalysisWireDTO = asPlainObject(input) ?? {};
  return {
    sessionCount: Number(payload.session_count ?? 0),
    messageCount: Number(payload.message_count ?? 0),
    authCount: Number(payload.auth_count ?? 0),
    attachmentHintCount: Number(payload.attachment_hint_count ?? 0),
    sessions: asArray(payload.sessions).map(asSMTPSession),
    notes: asStringList(payload.notes),
    report: asInvestigationReport(payload.report),
  };
}
