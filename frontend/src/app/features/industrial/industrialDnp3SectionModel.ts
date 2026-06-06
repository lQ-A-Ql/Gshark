import type { IndustrialControlCommand, IndustrialProtocolDetail, IndustrialRuleHit } from "../../core/types";

export type Dnp3SectionRow = {
  sourceType: "detail" | "command" | "rule";
  sourceLabel: string;
  packetId?: number;
  time?: string;
  source?: string;
  destination?: string;
  operation?: string;
  target?: string;
  result?: string;
  value?: string;
  summary: string;
};

export function deriveIndustrialDnp3Section(
  details: IndustrialProtocolDetail[],
  commands: IndustrialControlCommand[],
  ruleHits: IndustrialRuleHit[],
) {
  const dnp3Details = details.filter((detail) => matchesDnp3(detail.name));
  const dnp3Commands = commands.filter((command) => matchesDnp3(command.protocol));
  const dnp3Rules = ruleHits.filter((ruleHit) => matchesDnp3(ruleHit.rule));
  if (dnp3Details.length === 0 && dnp3Commands.length === 0 && dnp3Rules.length === 0) return null;

  const rows = buildDnp3Rows(dnp3Details, dnp3Commands, dnp3Rules);
  const operations = mergeBuckets(
    dnp3Details.flatMap((detail) => detail.operations),
    dnp3Commands.map((command) => command.operation),
    dnp3Rules.map((ruleHit) => ruleHit.functionName || ruleHit.rule),
  );
  return {
    detailRecordCount: dnp3Details.reduce((sum, detail) => sum + detail.records.length, 0),
    commandCount: dnp3Commands.length,
    ruleCount: dnp3Rules.length,
    operationKinds: operations.length,
    operations,
    targets: mergeBuckets(
      dnp3Details.flatMap((detail) => detail.targets),
      dnp3Commands.map((command) => command.target),
      dnp3Rules.map((ruleHit) => ruleHit.target),
    ),
    results: mergeBuckets(
      dnp3Details.flatMap((detail) => detail.results),
      dnp3Commands.map((command) => command.result),
      dnp3Rules.map((ruleHit) => ruleHit.level),
    ),
    rowCount: rows.length,
    rows,
  };
}

export function mergeBuckets(
  existingBuckets: Array<{ label: string; count: number }>,
  ...derivedLabelGroups: Array<Array<string | undefined>>
) {
  const counts = new Map<string, number>();
  for (const bucket of existingBuckets) addBucket(counts, bucket.label, Number(bucket.count ?? 0));
  for (const derivedLabels of derivedLabelGroups) {
    for (const labelValue of derivedLabels) addBucket(counts, labelValue, 1);
  }
  return Array.from(counts.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label));
}

export function matchesDnp3(value: string | undefined) {
  return String(value ?? "").toLowerCase().includes("dnp3");
}

function addBucket(counts: Map<string, number>, value: string | undefined, count: number) {
  const label = String(value ?? "").trim();
  if (label) counts.set(label, (counts.get(label) ?? 0) + count);
}

function buildDnp3Rows(
  details: IndustrialProtocolDetail[],
  commands: IndustrialControlCommand[],
  rules: IndustrialRuleHit[],
): Dnp3SectionRow[] {
  return [
    ...details.flatMap((detail) =>
      detail.records.map((record) => ({
        sourceType: "detail" as const,
        sourceLabel: "明细",
        packetId: record.packetId || undefined,
        time: record.time || undefined,
        source: record.source || undefined,
        destination: record.destination || undefined,
        operation: record.operation || undefined,
        target: record.target,
        result: record.result,
        value: record.value,
        summary: record.summary || `${detail.name} record`,
      })),
    ),
    ...commands.map((command) => ({
      sourceType: "command" as const,
      sourceLabel: "控制",
      packetId: command.packetId || undefined,
      time: command.time || undefined,
      source: command.source || undefined,
      destination: command.destination || undefined,
      operation: command.operation || undefined,
      target: command.target || undefined,
      result: command.result || undefined,
      value: command.value || undefined,
      summary: command.summary || "DNP3 command",
    })),
    ...rules.map((ruleHit) => ({
      sourceType: "rule" as const,
      sourceLabel: "规则",
      packetId: ruleHit.packetId,
      time: ruleHit.time,
      source: ruleHit.source,
      destination: ruleHit.destination,
      operation: ruleHit.functionName || ruleHit.rule || undefined,
      target: ruleHit.target,
      result: ruleHit.level || undefined,
      value: ruleHit.evidence,
      summary: ruleHit.summary || ruleHit.rule || "DNP3 rule hit",
    })),
  ];
}
