import type { MySQLAnalysis } from "../../core/types";
import type { MySQLAnalysisWireDTO } from "../wire/protocolToolWireDtos";
import { asInvestigationReport } from "./investigationReportMapper";
import { asArray, asPlainObject, asStringList } from "./mapperPrimitives";
import { asMySQLSession } from "./mysqlRecordMapper";

export function asMySQLAnalysis(input: unknown): MySQLAnalysis {
  const payload: MySQLAnalysisWireDTO = asPlainObject(input) ?? {};
  return {
    sessionCount: Number(payload.session_count ?? 0),
    loginCount: Number(payload.login_count ?? 0),
    queryCount: Number(payload.query_count ?? 0),
    errorCount: Number(payload.error_count ?? 0),
    resultsetCount: Number(payload.resultset_count ?? 0),
    sessions: asArray(payload.sessions).map(asMySQLSession),
    notes: asStringList(payload.notes),
    report: asInvestigationReport(payload.report),
  };
}
