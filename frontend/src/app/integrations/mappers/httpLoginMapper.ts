import type { HTTPLoginAnalysis } from "../../core/types";
import type { HTTPLoginAnalysisWireDTO } from "../wire/protocolToolWireDtos";
import { asInvestigationReport } from "./investigationReportMapper";
import { asHTTPLoginAttempt, asHTTPLoginEndpoint } from "./httpLoginRecordMapper";
import { asArray, asPlainObject, asStringList } from "./mapperPrimitives";

export function asHTTPLoginAnalysis(input: unknown): HTTPLoginAnalysis {
  const payload: HTTPLoginAnalysisWireDTO = asPlainObject(input) ?? {};
  return {
    totalAttempts: Number(payload.total_attempts ?? 0),
    candidateEndpoints: Number(payload.candidate_endpoints ?? 0),
    successCount: Number(payload.success_count ?? 0),
    failureCount: Number(payload.failure_count ?? 0),
    uncertainCount: Number(payload.uncertain_count ?? 0),
    bruteforceCount: Number(payload.bruteforce_count ?? 0),
    endpoints: asArray(payload.endpoints).map(asHTTPLoginEndpoint),
    attempts: asArray(payload.attempts).map(asHTTPLoginAttempt),
    notes: asStringList(payload.notes),
    report: asInvestigationReport(payload.report),
  };
}
