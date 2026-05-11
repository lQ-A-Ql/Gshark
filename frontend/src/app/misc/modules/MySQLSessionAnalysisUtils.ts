import type { MySQLAnalysis, MySQLSession } from "../../core/types";
import { renderInvestigationReportText } from "./investigationReportText";

export type MySQLSessionFilter = "ALL" | "LOGIN" | "ERROR";

export const MYSQL_SESSION_FILTERS: MySQLSessionFilter[] = ["ALL", "LOGIN", "ERROR"];

export function filterMySQLSessions(sessions: MySQLSession[], sessionFilter: MySQLSessionFilter, query: string) {
  const keyword = query.trim().toLowerCase();
  return sessions.filter((item) => {
    if (sessionFilter === "LOGIN" && !item.username) return false;
    if (sessionFilter === "ERROR" && item.errCount <= 0) return false;
    if (!keyword) return true;
    const haystack = [
      item.streamId,
      item.client,
      item.server,
      item.username,
      item.database,
      item.serverVersion,
      item.authPlugin,
      item.commandTypes?.join(" "),
      item.notes?.join(" "),
      item.queries
        .map((row) => [row.command, row.sql, row.database, row.responseKind, row.responseSummary].join(" "))
        .join(" "),
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(keyword);
  });
}

export function selectMySQLSession(sessions: MySQLSession[], selectedStreamId: number) {
  return sessions.find((item) => item.streamId === selectedStreamId) ?? sessions[0] ?? null;
}

export function renderMySQLSessionTitle(session: MySQLSession) {
  const left = session.client
    ? `${session.client}${session.clientPort ? `:${session.clientPort}` : ""}`
    : `stream #${session.streamId}`;
  const right = session.server
    ? `${session.server}${session.serverPort ? `:${session.serverPort}` : ""}`
    : "MySQL server";
  return `${left} → ${right}`;
}

export function renderMySQLAnalysisText(analysis: MySQLAnalysis) {
  const lines: string[] = [
    `MySQL session count: ${analysis.sessionCount}`,
    `login count: ${analysis.loginCount}`,
    `query count: ${analysis.queryCount}`,
    `error count: ${analysis.errorCount}`,
    `resultset count: ${analysis.resultsetCount}`,
    "",
  ];
  if (analysis.notes.length > 0) {
    lines.push("Notes:");
    for (const note of analysis.notes) {
      lines.push(`- ${note}`);
    }
    lines.push("");
  }
  for (const session of analysis.sessions) {
    lines.push(`[MySQL stream #${session.streamId}] ${renderMySQLSessionTitle(session)}`);
    lines.push(`Version: ${session.serverVersion || "--"}`);
    lines.push(`User: ${session.username || "--"}`);
    lines.push(`Database: ${session.database || "--"}`);
    lines.push(`Plugin: ${session.authPlugin || "--"}`);
    for (const row of session.queries) {
      lines.push(
        `  - ${row.command || "CMD"}: ${row.sql || row.database || row.responseSummary || "--"} [${row.responseKind || "--"}]`,
      );
    }
    lines.push("");
  }
  const reportText = renderInvestigationReportText(analysis.report);
  if (reportText) {
    lines.push(reportText);
  }
  return lines.join("\n");
}
