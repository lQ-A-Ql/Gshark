import { fireEvent, screen } from "@testing-library/react";

export function resetMiscToolsMocks(mocks: any) {
  window.localStorage.clear();
  mocks.sentinelState.fileMeta.path = "C:/captures/capture.pcapng";
  mocks.sentinelState.fileMeta.name = "capture.pcapng";
  mocks.sentinelState.locatePacketById.mockReset();
  mocks.sentinelState.preparePacketStream.mockReset();
  mocks.sentinelState.setActiveStream.mockReset();
  mocks.sentinelState.locatePacketById.mockResolvedValue(null);
  mocks.sentinelState.preparePacketStream.mockResolvedValue({ packet: null, protocol: "HTTP", streamId: 44 });
  mocks.sentinelState.setActiveStream.mockResolvedValue(undefined);
  mocks.listMiscModules.mockReset();
  mocks.importMiscModulePackage.mockReset();
  mocks.deleteMiscModule.mockReset();
  mocks.runMiscModule.mockReset();
  mocks.getHTTPLoginAnalysis.mockReset();
  mocks.getMySQLAnalysis.mockReset();
  mocks.getSMTPAnalysis.mockReset();
  mocks.getShiroRememberMeAnalysis.mockReset();
  mocks.decodeStreamPayload.mockReset();
  mocks.inspectStreamPayload.mockReset();
  mocks.listStreamPayloadSources.mockReset();
  mocks.listNTLMSessionMaterials.mockReset();
  mocks.listSMB3SessionCandidates.mockReset();
  mocks.generateSMB3RandomSessionKey.mockReset();
  mocks.runWinRMDecrypt.mockReset();
  mocks.getWinRMDecryptResultText.mockReset();
  mocks.exportWinRMDecryptResult.mockReset();
  mocks.navigate.mockReset();
  mocks.deleteMiscModule.mockResolvedValue(undefined);
  mocks.runMiscModule.mockResolvedValue({
    message: "ok",
    text: "generic result",
    table: {
      columns: [
        { key: "field", label: "Field" },
        { key: "value", label: "Value" },
      ],
      rows: [{ field: "keyword", value: "cmd.exe" }],
    },
  });
  mocks.getHTTPLoginAnalysis.mockResolvedValue({
    totalAttempts: 1,
    candidateEndpoints: 1,
    successCount: 1,
    failureCount: 0,
    uncertainCount: 0,
    bruteforceCount: 0,
    endpoints: [
      {
        key: "POST|demo.local|/login",
        method: "POST",
        host: "demo.local",
        path: "/login",
        attemptCount: 1,
        successCount: 1,
        failureCount: 0,
        uncertainCount: 0,
        requestKeys: ["username", "password"],
        responseIndicators: ["set-cookie"],
      },
    ],
    attempts: [
      {
        packetId: 11,
        streamId: 9,
        method: "POST",
        host: "demo.local",
        path: "/login",
        username: "alice",
        passwordPresent: true,
        statusCode: 302,
        result: "success",
        reason: "redirect",
      },
    ],
    notes: ["demo note"],
  });
  mocks.getSMTPAnalysis.mockResolvedValue({
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
  });
  mocks.getMySQLAnalysis.mockResolvedValue({
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
  });
  mocks.getShiroRememberMeAnalysis.mockResolvedValue({
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
  });
  mocks.inspectStreamPayload.mockResolvedValue({
    normalizedPayload: "pass=YXNzZXJ0KCRfUE9TVFsnY21kJ10pOw==",
    candidates: [
      {
        id: "form-0",
        label: "参数 pass",
        kind: "form",
        paramName: "pass",
        value: "YXNzZXJ0KCRfUE9TVFsnY21kJ10pOw==",
        preview: "YXNzZXJ0KCRfUE9TVFsnY21kJ10pOw==",
        confidence: 88,
        decoderHints: ["antsword", "base64"],
        fingerprints: ["script-after-base64"],
        familyHint: "antsword_like",
        sourceRole: "script_or_command",
        decoderOptionsHint: {
          decoder: "antsword",
          pass: "pass",
          extractParam: true,
          urlDecodeRounds: 1,
        },
      },
    ],
    suggestedCandidateId: "form-0",
    suggestedDecoder: "antsword",
    suggestedFamily: "antsword_like",
    confidence: 88,
    reasons: ["Base64 解码后出现 assert/eval 等脚本特征。"],
  });
  mocks.decodeStreamPayload.mockResolvedValue({
    decoder: "base64",
    summary: "Base64 自动解码",
    text: "assert($_POST['cmd']);",
    bytesHex: "61:73:73:65:72:74",
    encoding: "base64",
    confidence: 96,
    warnings: ["实验性 webshell 解码，需人工复核。"],
    signals: ["keyword:assert"],
    attemptErrors: ["Behinder (ECB): AES-ECB 密文长度非法"],
  });
  mocks.listStreamPayloadSources.mockResolvedValue([]);
  mocks.listNTLMSessionMaterials.mockResolvedValue([
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
  ]);
  mocks.listMiscModules.mockResolvedValue([
    {
      id: "http-login-analysis",
      kind: "builtin",
      title: "HTTP 登录行为分析",
      summary: "http auth summary",
      tags: ["HTTP", "Login"],
      apiPrefix: "/api/tools/http-login-analysis",
      docsPath: "docs/misc-module-interface.md",
      requiresCapture: true,
      protocolDomain: "HTTP / Auth",
      supportsExport: true,
      cancellable: true,
      dependsOn: ["capture", "http"],
    },
    {
      id: "payload-webshell-decoder",
      kind: "builtin",
      title: "Payload / WebShell 解码工作台",
      summary: "payload decoder summary",
      tags: ["Payload", "WebShell", "Decode", "Base64"],
      apiPrefix: "/api/streams",
      docsPath: "docs/misc-module-interface.md",
      requiresCapture: false,
      protocolDomain: "Payload / WebShell",
      supportsExport: true,
      cancellable: true,
      dependsOn: ["payload", "decode"],
    },
    {
      id: "mysql-session-analysis",
      kind: "builtin",
      title: "MySQL 会话重建",
      summary: "mysql summary",
      tags: ["MySQL", "DB"],
      apiPrefix: "/api/tools/mysql-analysis",
      docsPath: "docs/misc-module-interface.md",
      requiresCapture: true,
      protocolDomain: "MySQL / Database",
      supportsExport: true,
      cancellable: true,
      dependsOn: ["capture", "mysql"],
    },
    {
      id: "smtp-session-analysis",
      kind: "builtin",
      title: "SMTP 会话重建",
      summary: "smtp summary",
      tags: ["SMTP", "Mail"],
      apiPrefix: "/api/tools/smtp-analysis",
      docsPath: "docs/misc-module-interface.md",
      requiresCapture: true,
      protocolDomain: "SMTP / Mail",
      supportsExport: true,
      cancellable: true,
      dependsOn: ["capture", "smtp"],
    },
    {
      id: "shiro-rememberme-analysis",
      kind: "builtin",
      title: "Shiro rememberMe 分析",
      summary: "shiro summary",
      tags: ["Shiro", "rememberMe"],
      apiPrefix: "/api/tools/shiro-rememberme",
      docsPath: "docs/misc-module-interface.md",
      requiresCapture: true,
      protocolDomain: "HTTP / Shiro",
      supportsExport: true,
      cancellable: true,
      dependsOn: ["capture", "http"],
    },
    {
      id: "winrm-decrypt",
      kind: "builtin",
      title: "WinRM 解密辅助",
      summary: "winrm summary",
      tags: ["WinRM"],
      apiPrefix: "/api/tools/winrm-decrypt",
      docsPath: "docs/misc-module-interface.md",
      requiresCapture: true,
      protocolDomain: "NTLM / WinRM",
      supportsExport: true,
      cancellable: true,
      dependsOn: ["capture", "http", "ntlm"],
    },
    {
      id: "ntlm-session-materials",
      kind: "builtin",
      title: "NTLM 会话材料中心",
      summary: "ntlm summary",
      tags: ["NTLM", "HTTP", "WinRM", "SMB3"],
      apiPrefix: "/api/tools/ntlm-sessions",
      docsPath: "docs/misc-module-interface.md",
      requiresCapture: true,
      protocolDomain: "NTLM",
      supportsExport: true,
      cancellable: false,
      dependsOn: ["capture", "ntlm"],
    },
    {
      id: "smb3-session-key",
      kind: "builtin",
      title: "SMB3 Random Session Key",
      summary: "smb summary",
      tags: ["SMB3"],
      apiPrefix: "/api/tools/smb3",
      docsPath: "docs/misc-module-interface.md",
      requiresCapture: true,
      protocolDomain: "SMB3 / NTLM",
      supportsExport: false,
      cancellable: false,
      dependsOn: ["capture", "ntlm"],
    },
  ]);
  mocks.listSMB3SessionCandidates.mockResolvedValue([
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
  ]);
}

export async function expandModule(moduleID: string) {
  const toggle = await screen.findByTestId(`misc-module-toggle-${moduleID}`);
  fireEvent.click(toggle);
}
