import type { UnifiedEvidenceRecord } from "./evidenceSchema";

export function record(overrides: Partial<UnifiedEvidenceRecord>): UnifiedEvidenceRecord {
  return {
    id: "evidence-1",
    module: "c2",
    sourceType: "stream",
    summary: "C2 candidate",
    confidence: 50,
    confidenceLabel: "medium",
    severity: "medium",
    tags: [],
    caveats: [],
    ...overrides,
  };
}

export function optionalContractRows() {
  return [
    record({ id: "ja3", module: "hunting", sourceType: "ja3", summary: "TLS client fingerprint", ja3Hash: "72a589", tags: ["tls"] }),
    record({ id: "ja3s", module: "hunting", sourceType: "ja3s", summary: "TLS server fingerprint", ja3sHash: "b742b4", tags: ["server"] }),
    record({ id: "webshell", module: "misc", sourceType: "webshell", summary: "WebShell payload candidate", tags: ["webshell", "antsword"] }),
    record({ id: "china-chopper", module: "misc", sourceType: "china_chopper", summary: "China Chopper parameter", value: "password=z1", tags: ["china-chopper"] }),
    record({ id: "dnp3", module: "industrial", sourceType: "dnp3", summary: "DNP3 operate command", value: "function=operate", protocol: "dnp3", tags: [] }),
    record({ id: "ioc", module: "hunting", sourceType: "ioc", summary: "IOC match", iocType: "domain", iocValue: "evil.example", tags: [] }),
    record({ id: "playbook", module: "hunting", sourceType: "playbook", summary: "Correlation lead", playbookId: "PB-001", playbookName: "Playbook: beacon triage", tags: [] }),
    record({ id: "rule", module: "hunting", sourceType: "rule", summary: "Detection hit", ruleId: "SIGMA-001", ruleName: "Suspicious Sigma rule", tags: [] }),
  ];
}
