import { describe, expect, it } from "vitest";
import { asHTTPLoginAnalysis, asMySQLAnalysis, asShiroRememberMeAnalysis, asSMTPAnalysis } from "./protocolToolMapper";

describe("protocolToolMapper", () => {
  it("maps HTTP login endpoint and attempt records", () => {
    const result = asHTTPLoginAnalysis({
      total_attempts: 2,
      candidate_endpoints: 1,
      success_count: 1,
      failure_count: 1,
      uncertain_count: 0,
      bruteforce_count: 1,
      endpoints: [
        {
          key: "POST example.test/login",
          method: "POST",
          host: "example.test",
          path: "/login",
          attempt_count: 2,
          success_count: 1,
          failure_count: 1,
          possible_bruteforce: true,
          status_codes: [{ label: "200", count: 1 }],
          sample_packet_ids: [10, 0, "11"],
          request_keys: ["username", "password"],
        },
      ],
      attempts: [
        {
          packet_id: 10,
          response_packet_id: 12,
          stream_id: 3,
          username: "admin",
          password_present: true,
          status_code: 200,
          response_indicators: ["set-cookie"],
          possible_bruteforce: true,
        },
      ],
      notes: ["http note"],
    });

    expect(result).toMatchObject({ totalAttempts: 2, candidateEndpoints: 1, bruteforceCount: 1 });
    expect(result.endpoints[0]).toMatchObject({
      key: "POST example.test/login",
      possibleBruteforce: true,
      statusCodes: [{ label: "200", count: 1 }],
      samplePacketIds: [10, 11],
    });
    expect(result.attempts[0]).toMatchObject({
      packetId: 10,
      responsePacketId: 12,
      username: "admin",
      passwordPresent: true,
    });
  });

  it("maps SMTP sessions with commands and message metadata", () => {
    const result = asSMTPAnalysis({
      session_count: 1,
      message_count: 1,
      auth_count: 1,
      attachment_hint_count: 1,
      sessions: [
        {
          stream_id: 5,
          client: "10.0.0.2",
          server: "10.0.0.3",
          client_port: 51111,
          helo: "mail.example",
          auth_mechanisms: ["LOGIN"],
          auth_username: "user",
          auth_password_seen: true,
          mail_from: ["a@example.test"],
          rcpt_to: ["b@example.test"],
          command_count: 4,
          message_count: 1,
          commands: [{ packet_id: 20, command: "AUTH", status_code: 235 }],
          messages: [{ sequence: 1, subject: "Report", packet_ids: [21, "22"] }],
          possible_cleartext: true,
        },
      ],
    });

    expect(result.sessions[0]).toMatchObject({
      streamId: 5,
      authMechanisms: ["LOGIN"],
      authPasswordSeen: true,
      possibleCleartext: true,
    });
    expect(result.sessions[0].commands?.[0]).toMatchObject({ packetId: 20, statusCode: 235 });
    expect(result.sessions[0].messages?.[0]).toMatchObject({ subject: "Report", packetIds: [21, 22] });
  });

  it("maps MySQL sessions with login, query, and server events", () => {
    const result = asMySQLAnalysis({
      session_count: 1,
      login_count: 1,
      query_count: 2,
      error_count: 1,
      resultset_count: 1,
      sessions: [
        {
          stream_id: 7,
          server_version: "8.0",
          connection_id: 99,
          username: "app",
          database: "inventory",
          login_packet_id: 30,
          login_success: true,
          query_count: 2,
          err_count: 1,
          command_types: ["QUERY"],
          queries: [{ packet_id: 31, sql: "SELECT 1", response_code: 0 }],
          server_events: [{ packet_id: 32, kind: "ERR", code: 1064 }],
          notes: ["mysql note"],
        },
      ],
    });

    expect(result.sessions[0]).toMatchObject({
      streamId: 7,
      serverVersion: "8.0",
      connectionId: 99,
      loginPacketId: 30,
      loginSuccess: true,
    });
    expect(result.sessions[0].queries[0]).toMatchObject({ packetId: 31, sql: "SELECT 1", responseCode: undefined });
    expect(result.sessions[0].serverEvents[0]).toMatchObject({ packetId: 32, kind: "ERR", code: 1064 });
  });

  it("maps Shiro rememberMe candidates and key results", () => {
    const result = asShiroRememberMeAnalysis({
      candidate_count: 1,
      hit_count: 1,
      candidates: [
        {
          packet_id: 40,
          stream_id: 8,
          host: "shiro.example",
          cookie_name: "rememberMe",
          decode_ok: true,
          encrypted_length: 64,
          possible_cbc: true,
          key_results: [
            {
              label: "default",
              base64: "kPH+bIxk5D2deZiIxcaaaA==",
              algorithm: "AES-CBC",
              hit: true,
              payload_class: "org.apache.shiro.subject.SimplePrincipalCollection",
            },
          ],
          hit_count: 1,
        },
      ],
      notes: ["shiro note"],
    });

    expect(result).toMatchObject({ candidateCount: 1, hitCount: 1 });
    expect(result.candidates[0]).toMatchObject({
      packetId: 40,
      streamId: 8,
      host: "shiro.example",
      decodeOK: true,
      encryptedLength: 64,
      possibleCBC: true,
      hitCount: 1,
    });
    expect(result.candidates[0].keyResults?.[0]).toMatchObject({
      label: "default",
      hit: true,
      payloadClass: "org.apache.shiro.subject.SimplePrincipalCollection",
    });
  });

  it("returns empty defaults for missing protocol sections", () => {
    expect(asHTTPLoginAnalysis({}).endpoints).toEqual([]);
    expect(asSMTPAnalysis({}).sessions).toEqual([]);
    expect(asMySQLAnalysis({}).sessions).toEqual([]);
    expect(asShiroRememberMeAnalysis({}).candidates).toEqual([]);
  });
});
