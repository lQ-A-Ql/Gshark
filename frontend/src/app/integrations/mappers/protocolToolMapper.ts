import type { HTTPLoginAnalysis, MySQLAnalysis, ShiroRememberMeAnalysis, SMTPAnalysis } from "../../core/types";
import { asBucket, asPositiveFiniteNumbers, asStringList } from "./mapperPrimitives";

export function asHTTPLoginAnalysis(input: any): HTTPLoginAnalysis {
  return {
    totalAttempts: Number(input.total_attempts ?? 0),
    candidateEndpoints: Number(input.candidate_endpoints ?? 0),
    successCount: Number(input.success_count ?? 0),
    failureCount: Number(input.failure_count ?? 0),
    uncertainCount: Number(input.uncertain_count ?? 0),
    bruteforceCount: Number(input.bruteforce_count ?? 0),
    endpoints: Array.isArray(input.endpoints)
      ? input.endpoints.map((item: any) => ({
          key: String(item.key ?? ""),
          method: optionalString(item.method),
          host: optionalString(item.host),
          path: optionalString(item.path),
          attemptCount: Number(item.attempt_count ?? 0),
          successCount: Number(item.success_count ?? 0),
          failureCount: Number(item.failure_count ?? 0),
          uncertainCount: Number(item.uncertain_count ?? 0),
          possibleBruteforce: Boolean(item.possible_bruteforce),
          usernameVariants: optionalNumber(item.username_variants),
          passwordAttempts: optionalNumber(item.password_attempts),
          captchaCount: optionalNumber(item.captcha_count),
          setCookieCount: optionalNumber(item.set_cookie_count),
          tokenHintCount: optionalNumber(item.token_hint_count),
          statusCodes: Array.isArray(item.status_codes) ? item.status_codes.map(asBucket) : [],
          requestKeys: asStringList(item.request_keys),
          responseIndicators: asStringList(item.response_indicators),
          samplePacketIds: asPositiveFiniteNumbers(item.sample_packet_ids),
          notes: asStringList(item.notes),
        }))
      : [],
    attempts: Array.isArray(input.attempts)
      ? input.attempts.map((item: any) => ({
          packetId: Number(item.packet_id ?? 0),
          responsePacketId: optionalNumber(item.response_packet_id),
          streamId: Number(item.stream_id ?? 0),
          time: optionalString(item.time),
          responseTime: optionalString(item.response_time),
          src: optionalString(item.src),
          dst: optionalString(item.dst),
          method: optionalString(item.method),
          host: optionalString(item.host),
          path: optionalString(item.path),
          endpointLabel: optionalString(item.endpoint_label),
          username: optionalString(item.username),
          passwordPresent: Boolean(item.password_present),
          tokenPresent: Boolean(item.token_present),
          captchaPresent: Boolean(item.captcha_present),
          requestKeys: asStringList(item.request_keys),
          requestContentType: optionalString(item.request_content_type),
          requestPreview: optionalString(item.request_preview),
          statusCode: optionalNumber(item.status_code),
          responseLocation: optionalString(item.response_location),
          responseSetCookie: Boolean(item.response_set_cookie),
          responseTokenHint: Boolean(item.response_token_hint),
          responseIndicators: asStringList(item.response_indicators),
          responsePreview: optionalString(item.response_preview),
          result: optionalString(item.result),
          reason: optionalString(item.reason),
          possibleBruteforce: Boolean(item.possible_bruteforce),
        }))
      : [],
    notes: asStringList(input.notes),
  };
}

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

export function asMySQLAnalysis(input: any): MySQLAnalysis {
  return {
    sessionCount: Number(input.session_count ?? 0),
    loginCount: Number(input.login_count ?? 0),
    queryCount: Number(input.query_count ?? 0),
    errorCount: Number(input.error_count ?? 0),
    resultsetCount: Number(input.resultset_count ?? 0),
    sessions: Array.isArray(input.sessions)
      ? input.sessions.map((item: any) => ({
          streamId: Number(item.stream_id ?? 0),
          client: optionalString(item.client),
          server: optionalString(item.server),
          clientPort: optionalNumber(item.client_port),
          serverPort: optionalNumber(item.server_port),
          serverVersion: optionalString(item.server_version),
          connectionId: optionalNumber(item.connection_id),
          username: optionalString(item.username),
          database: optionalString(item.database),
          authPlugin: optionalString(item.auth_plugin),
          loginPacketId: optionalNumber(item.login_packet_id),
          loginSuccess: item.login_packet_id ? Boolean(item.login_success) : undefined,
          queryCount: Number(item.query_count ?? 0),
          okCount: Number(item.ok_count ?? 0),
          errCount: Number(item.err_count ?? 0),
          resultsetCount: Number(item.resultset_count ?? 0),
          commandTypes: asStringList(item.command_types),
          queries: Array.isArray(item.queries)
            ? item.queries.map((row: any) => ({
                packetId: Number(row.packet_id ?? 0),
                time: optionalString(row.time),
                command: optionalString(row.command),
                sql: optionalString(row.sql),
                database: optionalString(row.database),
                responsePacketId: optionalNumber(row.response_packet_id),
                responseKind: optionalString(row.response_kind),
                responseCode: optionalNumber(row.response_code),
                responseSummary: optionalString(row.response_summary),
              }))
            : [],
          serverEvents: Array.isArray(item.server_events)
            ? item.server_events.map((row: any) => ({
                packetId: Number(row.packet_id ?? 0),
                time: optionalString(row.time),
                sequence: optionalNumber(row.sequence),
                kind: optionalString(row.kind),
                code: optionalNumber(row.code),
                summary: optionalString(row.summary),
              }))
            : [],
          notes: asStringList(item.notes),
        }))
      : [],
    notes: asStringList(input.notes),
  };
}

export function asShiroRememberMeAnalysis(input: any): ShiroRememberMeAnalysis {
  return {
    candidateCount: Number(input.candidate_count ?? 0),
    hitCount: Number(input.hit_count ?? 0),
    candidates: Array.isArray(input.candidates)
      ? input.candidates.map((item: any) => ({
          packetId: Number(item.packet_id ?? 0),
          streamId: optionalNumber(item.stream_id),
          time: optionalString(item.time),
          src: optionalString(item.src),
          dst: optionalString(item.dst),
          host: optionalString(item.host),
          path: optionalString(item.path),
          sourceHeader: optionalString(item.source_header),
          cookieName: optionalString(item.cookie_name),
          cookieValue: optionalString(item.cookie_value),
          cookiePreview: optionalString(item.cookie_preview),
          decodeOK: Boolean(item.decode_ok),
          encryptedLength: optionalNumber(item.encrypted_length),
          aesBlockAligned: Boolean(item.aes_block_aligned),
          possibleCBC: Boolean(item.possible_cbc),
          possibleGCM: Boolean(item.possible_gcm),
          keyResults: Array.isArray(item.key_results)
            ? item.key_results.map((row: any) => ({
                label: String(row.label ?? ""),
                base64: optionalString(row.base64),
                algorithm: optionalString(row.algorithm),
                hit: Boolean(row.hit),
                payloadClass: optionalString(row.payload_class),
                preview: optionalString(row.preview),
                reason: optionalString(row.reason),
              }))
            : [],
          hitCount: optionalNumber(item.hit_count),
          notes: asStringList(item.notes),
        }))
      : [],
    notes: asStringList(input.notes),
  };
}

function optionalString(input: unknown): string | undefined {
  const value = String(input ?? "");
  return value || undefined;
}

function optionalNumber(input: unknown): number | undefined {
  const value = Number(input ?? 0);
  return value || undefined;
}
