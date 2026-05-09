export function createSMTPAnalysisFixture() {
  return {
    sessionCount: 1,
    messageCount: 1,
    authCount: 1,
    attachmentHintCount: 1,
    sessions: [
      {
        streamId: 7,
        client: "10.0.0.10",
        server: "10.0.0.20",
        clientPort: 51234,
        serverPort: 25,
        helo: "demo.local",
        authMechanisms: ["LOGIN"],
        authUsername: "alice",
        authPasswordSeen: true,
        mailFrom: ["alice@example.com"],
        rcptTo: ["bob@example.com"],
        commandCount: 6,
        messageCount: 1,
        attachmentHints: 1,
        commands: [
          { packetId: 201, direction: "client", command: "EHLO", summary: "EHLO demo.local" },
          { packetId: 202, direction: "client", command: "AUTH", summary: "AUTH LOGIN" },
        ],
        statusHints: ["AUTH"],
        messages: [
          {
            sequence: 1,
            subject: "Quarterly Report",
            from: "Alice <alice@example.com>",
            to: "Bob <bob@example.com>",
            attachmentNames: ["report.zip"],
            bodyPreview: "Please find the report attached.",
            packetIds: [203, 204],
          },
        ],
        possibleCleartext: true,
      },
    ],
    notes: ["SMTP note"],
  };
}

export function createMySQLAnalysisFixture() {
  return {
    sessionCount: 1,
    loginCount: 1,
    queryCount: 2,
    errorCount: 1,
    resultsetCount: 1,
    sessions: [
      {
        streamId: 12,
        client: "10.0.0.10",
        server: "10.0.0.30",
        clientPort: 52000,
        serverPort: 3306,
        serverVersion: "8.0.36",
        connectionId: 77,
        username: "app",
        database: "inventory",
        authPlugin: "mysql_native_password",
        loginPacketId: 301,
        loginSuccess: true,
        queryCount: 2,
        okCount: 1,
        errCount: 1,
        resultsetCount: 1,
        commandTypes: ["LOGIN", "COM_QUERY"],
        queries: [
          {
            packetId: 302,
            command: "COM_QUERY",
            sql: "SELECT * FROM users",
            responseKind: "RESULTSET",
            responsePacketId: 303,
          },
          {
            packetId: 304,
            command: "COM_QUERY",
            sql: "DELETE FROM audit_logs",
            responseKind: "ERR",
            responseCode: 1096,
            responsePacketId: 305,
            responseSummary: "syntax error",
          },
        ],
        serverEvents: [
          { packetId: 300, kind: "HANDSHAKE", summary: "8.0.36" },
          { packetId: 305, kind: "ERR", code: 1096, summary: "syntax error" },
        ],
        notes: ["识别到用户名 app"],
      },
    ],
    notes: ["MySQL note"],
  };
}

export function createShiroRememberMeAnalysisFixture() {
  return {
    candidateCount: 1,
    hitCount: 1,
    candidates: [
      {
        packetId: 401,
        streamId: 44,
        time: "2026-04-26T13:14:15Z",
        src: "10.0.0.10",
        dst: "10.0.0.20",
        host: "shiro.demo",
        path: "/dashboard",
        sourceHeader: "Cookie",
        cookieName: "rememberMe",
        cookiePreview: "QmFzZTY0U2FtcGxl",
        decodeOK: true,
        encryptedLength: 48,
        aesBlockAligned: true,
        possibleCBC: true,
        possibleGCM: true,
        hitCount: 1,
        keyResults: [
          {
            label: "shiro-default",
            base64: "kPH+bIxk5D2deZiIxcaaaA==",
            algorithm: "AES-CBC",
            hit: true,
            payloadClass: "org.apache.shiro.subject.SimplePrincipalCollection",
            preview: "org.apache.shiro.subject.SimplePrincipalCollection",
          },
        ],
        notes: ["命中 1 个候选密钥"],
      },
    ],
    notes: ["Shiro note"],
  };
}

export function createNTLMSessionMaterialsFixture() {
  return [
    {
      protocol: "HTTP",
      transport: "NTLMSSP",
      frameNumber: "55",
      timestamp: "Apr 21",
      src: "10.0.0.10",
      dst: "10.0.0.20",
      direction: "client->server",
      username: "Administrator",
      domain: "LAB",
      userDisplay: "LAB\\Administrator",
      challenge: "11223344",
      ntProofStr: "00112233445566778899aabbccddeeff",
      encryptedSessionKey: "ffeeddccbbaa99887766554433221100",
      sessionId: "0x99",
      info: "NTLM auth",
      complete: true,
      displayLabel: "LAB\\Administrator | HTTP | 帧 #55",
    },
    {
      protocol: "SMB3",
      transport: "NTLMSSP",
      frameNumber: "56",
      timestamp: "Apr 21",
      src: "10.0.0.10",
      dst: "10.0.0.20",
      direction: "server->client",
      username: "Guest",
      domain: "",
      userDisplay: "Guest",
      challenge: "",
      ntProofStr: "",
      encryptedSessionKey: "",
      sessionId: "0x100",
      info: "guest auth",
      complete: false,
      displayLabel: "Guest | SMB3 | 帧 #56",
    },
  ];
}

export function createSMB3SessionCandidatesFixture() {
  return [
    {
      sessionId: "0x1122334455667788",
      username: "Administrator",
      domain: "LAB",
      ntProofStr: "00112233445566778899aabbccddeeff",
      encryptedSessionKey: "ffeeddccbbaa99887766554433221100",
      src: "10.0.0.10",
      dst: "10.0.0.20",
      frameNumber: "101",
      timestamp: "Apr 21",
      complete: true,
      displayLabel: "0x1122334455667788 | LAB\\Administrator | 10.0.0.10 -> 10.0.0.20 | 帧 #101",
    },
    {
      sessionId: "0x1122334455667788",
      username: "Guest",
      domain: "",
      ntProofStr: "",
      encryptedSessionKey: "",
      src: "10.0.0.10",
      dst: "10.0.0.20",
      frameNumber: "102",
      timestamp: "Apr 21",
      complete: false,
      displayLabel: "0x1122334455667788 | Guest | 10.0.0.10 -> 10.0.0.20 | 帧 #102",
    },
  ];
}
