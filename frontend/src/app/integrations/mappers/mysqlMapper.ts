import type { MySQLAnalysis } from "../../core/types";
import { asStringList, optionalNumber, optionalString } from "./mapperPrimitives";

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
