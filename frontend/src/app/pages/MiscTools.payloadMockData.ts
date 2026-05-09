export function createHTTPLoginAnalysisFixture() {
  return {
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
  };
}

export function createPayloadInspectionFixture() {
  return {
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
  };
}

export function createPayloadDecodeFixture() {
  return {
    decoder: "base64",
    summary: "Base64 自动解码",
    text: "assert($_POST['cmd']);",
    bytesHex: "61:73:73:65:72:74",
    encoding: "base64",
    confidence: 96,
    warnings: ["实验性 webshell 解码，需人工复核。"],
    signals: ["keyword:assert"],
    attemptErrors: ["Behinder (ECB): AES-ECB 密文长度非法"],
  };
}
