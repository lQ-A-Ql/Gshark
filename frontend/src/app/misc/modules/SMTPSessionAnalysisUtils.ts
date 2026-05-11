import type { SMTPAnalysis, SMTPSession } from "../../core/types";
import { renderInvestigationReportText } from "./investigationReportText";

export type SMTPSessionFilter = "ALL" | "AUTH" | "ATTACHMENT";

export const SMTP_SESSION_FILTERS: SMTPSessionFilter[] = ["ALL", "AUTH", "ATTACHMENT"];

export function filterSMTPSessions(sessions: SMTPSession[], sessionFilter: SMTPSessionFilter, query: string) {
  const keyword = query.trim().toLowerCase();
  return sessions.filter((item) => {
    if (sessionFilter === "AUTH" && !item.authUsername && (item.authMechanisms?.length ?? 0) === 0) return false;
    if (sessionFilter === "ATTACHMENT" && (item.attachmentHints ?? 0) <= 0) return false;
    if (!keyword) return true;
    const haystack = [
      item.streamId,
      item.client,
      item.server,
      item.helo,
      item.authUsername,
      item.mailFrom?.join(" "),
      item.rcptTo?.join(" "),
      item.authMechanisms?.join(" "),
      item.statusHints?.join(" "),
      item.messages
        ?.map((row) => [row.subject, row.from, row.to, row.attachmentNames?.join(" "), row.bodyPreview].join(" "))
        .join(" "),
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(keyword);
  });
}

export function selectSMTPSession(sessions: SMTPSession[], selectedStreamId: number) {
  return sessions.find((item) => item.streamId === selectedStreamId) ?? sessions[0] ?? null;
}

export function countSMTPSessionMessages(sessions: SMTPSession[]) {
  return sessions.reduce((sum, item) => sum + (item.messageCount ?? item.messages?.length ?? 0), 0);
}

export function renderSMTPSessionTitle(session: SMTPSession) {
  const left = session.client
    ? `${session.client}${session.clientPort ? `:${session.clientPort}` : ""}`
    : `stream #${session.streamId}`;
  const right = session.server
    ? `${session.server}${session.serverPort ? `:${session.serverPort}` : ""}`
    : "SMTP server";
  return `${left} → ${right}`;
}

export function renderSMTPAnalysisText(analysis: SMTPAnalysis) {
  const lines: string[] = [
    `SMTP session count: ${analysis.sessionCount}`,
    `message count: ${analysis.messageCount}`,
    `auth count: ${analysis.authCount}`,
    `attachment hints: ${analysis.attachmentHintCount}`,
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
    lines.push(`[SMTP stream #${session.streamId}] ${renderSMTPSessionTitle(session)}`);
    lines.push(`HELO: ${session.helo || "--"}`);
    lines.push(`AUTH: ${(session.authMechanisms ?? []).join(", ") || "--"}`);
    lines.push(`AUTH username: ${session.authUsername || "--"}`);
    lines.push(`MAIL FROM: ${(session.mailFrom ?? []).join(", ") || "--"}`);
    lines.push(`RCPT TO: ${(session.rcptTo ?? []).join(", ") || "--"}`);
    lines.push(`Status: ${(session.statusHints ?? []).join(", ") || "--"}`);
    lines.push(`Messages: ${session.messageCount}`);
    for (const message of session.messages ?? []) {
      lines.push(`  - Message #${message.sequence}: ${message.subject || "(no subject)"}`);
      if (message.from) lines.push(`    From: ${message.from}`);
      if (message.to) lines.push(`    To: ${message.to}`);
      if (message.attachmentNames?.length) lines.push(`    Attachments: ${message.attachmentNames.join(", ")}`);
      if (message.bodyPreview) lines.push(`    Body: ${message.bodyPreview}`);
    }
    lines.push("");
  }
  const reportText = renderInvestigationReportText(analysis.report);
  if (reportText) {
    lines.push(reportText);
  }
  return lines.join("\n");
}
