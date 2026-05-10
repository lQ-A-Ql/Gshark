import type { SMTPAnalysis } from "../../core/types";
import { asPositiveFiniteNumbers, asStringList, optionalNumber, optionalString } from "./mapperPrimitives";

export function asSMTPAnalysis(input: any): SMTPAnalysis {
  return {
    sessionCount: Number(input.session_count ?? 0),
    messageCount: Number(input.message_count ?? 0),
    authCount: Number(input.auth_count ?? 0),
    attachmentHintCount: Number(input.attachment_hint_count ?? 0),
    sessions: Array.isArray(input.sessions)
      ? input.sessions.map((item: any) => ({
          streamId: Number(item.stream_id ?? 0),
          client: optionalString(item.client),
          server: optionalString(item.server),
          clientPort: optionalNumber(item.client_port),
          serverPort: optionalNumber(item.server_port),
          helo: optionalString(item.helo),
          authMechanisms: asStringList(item.auth_mechanisms),
          authUsername: optionalString(item.auth_username),
          authPasswordSeen: Boolean(item.auth_password_seen),
          mailFrom: asStringList(item.mail_from),
          rcptTo: asStringList(item.rcpt_to),
          commandCount: Number(item.command_count ?? 0),
          messageCount: Number(item.message_count ?? 0),
          attachmentHints: Number(item.attachment_hints ?? 0),
          commands: Array.isArray(item.commands)
            ? item.commands.map((row: any) => ({
                packetId: Number(row.packet_id ?? 0),
                time: optionalString(row.time),
                direction: optionalString(row.direction),
                command: optionalString(row.command),
                argument: optionalString(row.argument),
                statusCode: optionalNumber(row.status_code),
                summary: optionalString(row.summary),
              }))
            : [],
          statusHints: asStringList(item.status_hints),
          messages: Array.isArray(item.messages)
            ? item.messages.map((row: any) => ({
                sequence: Number(row.sequence ?? 0),
                mailFrom: optionalString(row.mail_from),
                rcptTo: asStringList(row.rcpt_to),
                subject: optionalString(row.subject),
                from: optionalString(row.from),
                to: optionalString(row.to),
                date: optionalString(row.date),
                contentType: optionalString(row.content_type),
                boundary: optionalString(row.boundary),
                attachmentNames: asStringList(row.attachment_names),
                bodyPreview: optionalString(row.body_preview),
                packetIds: asPositiveFiniteNumbers(row.packet_ids),
              }))
            : [],
          possibleCleartext: Boolean(item.possible_cleartext),
        }))
      : [],
    notes: asStringList(input.notes),
  };
}
