import { Shield } from "lucide-react";
import type { IndustrialControlCommand, IndustrialProtocolDetail, IndustrialRuleHit } from "../../core/types";
import {
  AnalysisBadge,
  AnalysisBucketChart as BucketChart,
  AnalysisCallout,
  AnalysisDataTable as DataTable,
  AnalysisPanel as Panel,
  AnalysisStatCard as StatCard,
  type AnalysisTone,
} from "../../components/analysis/AnalysisPrimitives";

export function IndustrialRuleHitsPanel({ ruleHits }: { ruleHits: IndustrialRuleHit[] }) {
  if (ruleHits.length === 0) return null;

  return (
    <Panel title={`规则检测 / Modbus 异常命中 (${ruleHits.length})`} className="mt-0">
      <AnalysisCallout className="mb-2" tone="blue" icon={<Shield className="h-4 w-4" />}>
        基于主从角色、功能码、数量字段、位长度一致性和高频写入行为生成规则命中，可直接定位可疑包与目标地址。
      </AnalysisCallout>
      <DataTable
        columns={[
          {
            key: "level",
            header: "等级",
            widthClassName: "w-20",
            render: (item) => (
              <AnalysisBadge tone={toneForIndustrialRuleLevel(item.level)}>{item.level || "info"}</AnalysisBadge>
            ),
          },
          {
            key: "rule",
            header: "规则",
            widthClassName: "w-28",
            cellClassName: "font-medium",
            render: (item) => item.rule,
          },
          {
            key: "packet",
            header: "包号",
            widthClassName: "w-20",
            cellClassName: "font-mono text-slate-500",
            render: (item) => item.packetId || "--",
          },
          {
            key: "time",
            header: "时间",
            widthClassName: "w-28",
            cellClassName: "font-mono",
            render: (item) => item.time || "--",
          },
          {
            key: "source",
            header: "源",
            widthClassName: "w-32",
            cellClassName: "break-all",
            render: (item) => item.source || "--",
          },
          {
            key: "destination",
            header: "目标",
            widthClassName: "w-32",
            cellClassName: "break-all",
            render: (item) => item.destination || "--",
          },
          {
            key: "function",
            header: "功能码",
            widthClassName: "w-24",
            render: (item) =>
              item.functionCode != null ? (
                <div>
                  <div className="font-mono">{String(item.functionCode).padStart(2, "0")}</div>
                  {item.functionName && <div className="text-slate-500">{item.functionName}</div>}
                </div>
              ) : (
                "--"
              ),
          },
          {
            key: "target",
            header: "对象",
            widthClassName: "w-32",
            cellClassName: "break-all font-mono",
            render: (item) => item.target || "--",
          },
          {
            key: "evidence",
            header: "证据",
            widthClassName: "w-40",
            cellClassName: "break-all font-mono text-[11px] text-slate-500",
            render: (item) => item.evidence || "--",
          },
          { key: "summary", header: "摘要", render: (item) => item.summary || "--" },
        ]}
        data={ruleHits}
        rowKey={(item, idx) => `${item.rule}-${item.packetId}-${idx}`}
        maxHeightClassName="max-h-[460px]"
        tableClassName="min-w-[1120px]"
        emptyText="暂无规则命中"
      />
    </Panel>
  );
}

export function IndustrialControlCommandsPanel({ commands }: { commands: IndustrialControlCommand[] }) {
  if (commands.length === 0) return null;

  return (
    <Panel title={`控制指令 (${commands.length})`} className="mt-0">
      <AnalysisCallout className="mb-2" tone="rose" icon={<Shield className="h-4 w-4" />}>
        以下为从 IEC 104、DNP3、BACnet 等协议中提取的控制/操作类指令，可能涉及遥控、设点或设备重启。
      </AnalysisCallout>
      <DataTable
        columns={[
          {
            key: "packet",
            header: "包号",
            widthClassName: "w-20",
            cellClassName: "font-mono text-slate-500",
            render: (cmd) => cmd.packetId,
          },
          {
            key: "time",
            header: "时间",
            widthClassName: "w-28",
            cellClassName: "font-mono",
            render: (cmd) => cmd.time || "--",
          },
          {
            key: "protocol",
            header: "协议",
            widthClassName: "w-20",
            render: (cmd) => <AnalysisBadge tone="blue">{cmd.protocol}</AnalysisBadge>,
          },
          { key: "source", header: "源", widthClassName: "w-32", render: (cmd) => cmd.source || "--" },
          { key: "destination", header: "目标", widthClassName: "w-32", render: (cmd) => cmd.destination || "--" },
          {
            key: "operation",
            header: "操作",
            widthClassName: "w-36",
            cellClassName: "font-mono font-semibold text-rose-700",
            render: (cmd) => cmd.operation || "--",
          },
          {
            key: "target",
            header: "对象",
            widthClassName: "w-28",
            cellClassName: "font-mono",
            render: (cmd) => cmd.target || "--",
          },
          {
            key: "value",
            header: "值",
            widthClassName: "w-24",
            cellClassName: "font-mono",
            render: (cmd) => cmd.value || "--",
          },
          { key: "result", header: "结果", widthClassName: "w-24", render: (cmd) => cmd.result || "--" },
          { key: "summary", header: "摘要", render: (cmd) => cmd.summary || "--" },
        ]}
        data={commands}
        rowKey={(_cmd, idx) => `cmd-${idx}`}
        maxHeightClassName="max-h-[520px]"
        tableClassName="min-w-[1120px]"
        emptyText="暂无控制指令"
      />
    </Panel>
  );
}

export function IndustrialDnp3Panel({
  details,
  commands,
  ruleHits,
}: {
  details: IndustrialProtocolDetail[];
  commands: IndustrialControlCommand[];
  ruleHits: IndustrialRuleHit[];
}) {
  const dnp3 = deriveIndustrialDnp3Section(details, commands, ruleHits);

  if (!dnp3) return null;

  return (
    <Panel title={`DNP3 专项 (${dnp3.rowCount})`} className="mt-0">
      <AnalysisCallout className="mb-3" tone="blue" icon={<Shield className="h-4 w-4" />}>
        基于现有工业分析结果中的 DNP3
        协议明细、控制指令和规则命中聚合，突出遥控、目标点位与执行结果，不重复整页通用工控表格。
      </AnalysisCallout>
      <div className="mb-3 grid grid-cols-2 gap-0 lg:grid-cols-4">
        <StatCard title="明细记录" value={String(dnp3.detailRecordCount)} />
        <StatCard title="控制指令" value={String(dnp3.commandCount)} />
        <StatCard title="规则命中" value={String(dnp3.ruleCount)} />
        <StatCard title="操作类型" value={String(dnp3.operationKinds)} />
      </div>
      <div className="grid grid-cols-1 gap-0 xl:grid-cols-3">
        <Panel title="操作分布">
          <BucketChart data={dnp3.operations} barClassName="bg-blue-500" />
        </Panel>
        <Panel title="目标对象">
          <BucketChart data={dnp3.targets} barClassName="bg-emerald-500" />
        </Panel>
        <Panel title="结果 / 状态">
          <BucketChart data={dnp3.results} barClassName="bg-amber-500" />
        </Panel>
      </div>
      <div className="mt-0">
        <DataTable
          columns={[
            {
              key: "sourceType",
              header: "来源",
              widthClassName: "w-24",
              render: (item) => (
                <AnalysisBadge tone={toneForDnp3Source(item.sourceType)}>{item.sourceLabel}</AnalysisBadge>
              ),
            },
            {
              key: "packet",
              header: "包号",
              widthClassName: "w-20",
              cellClassName: "font-mono text-slate-500",
              render: (item) => item.packetId || "--",
            },
            {
              key: "time",
              header: "时间",
              widthClassName: "w-28",
              cellClassName: "font-mono",
              render: (item) => item.time || "--",
            },
            {
              key: "source",
              header: "源",
              widthClassName: "w-32",
              cellClassName: "break-all",
              render: (item) => item.source || "--",
            },
            {
              key: "destination",
              header: "目标",
              widthClassName: "w-32",
              cellClassName: "break-all",
              render: (item) => item.destination || "--",
            },
            {
              key: "operation",
              header: "操作",
              widthClassName: "w-32",
              cellClassName: "font-mono",
              render: (item) => item.operation || "--",
            },
            {
              key: "target",
              header: "对象",
              widthClassName: "w-28",
              cellClassName: "break-all font-mono",
              render: (item) => item.target || "--",
            },
            { key: "result", header: "结果", widthClassName: "w-24", render: (item) => item.result || "--" },
            {
              key: "value",
              header: "值",
              widthClassName: "w-24",
              cellClassName: "break-all font-mono",
              render: (item) => item.value || "--",
            },
            { key: "summary", header: "摘要", render: (item) => item.summary || "--" },
          ]}
          data={dnp3.rows}
          rowKey={(item, idx) => `${item.sourceType}-${item.packetId}-${idx}`}
          maxHeightClassName="max-h-[520px]"
          tableClassName="min-w-[1120px]"
          emptyText="暂无 DNP3 专项记录"
        />
      </div>
    </Panel>
  );
}

export function IndustrialProtocolDetailsPanel({ details }: { details: IndustrialProtocolDetail[] }) {
  return (
    <>
      {details.map((detail) => (
        <Panel key={detail.name} title={`${detail.name} 明细 (${detail.records.length})`} className="mt-0">
          <div className="mb-3 grid grid-cols-2 gap-0 lg:grid-cols-4">
            <StatCard title="总帧数" value={detail.totalFrames.toLocaleString()} />
            <StatCard title="操作类型" value={String(detail.operations.length)} />
            <StatCard title="目标对象" value={String(detail.targets.length)} />
            <StatCard title="结果项" value={String(detail.results.length)} />
          </div>
          <div className="grid grid-cols-1 gap-0 xl:grid-cols-3">
            <Panel title="操作分布">
              <BucketChart data={detail.operations} barClassName="bg-blue-500" />
            </Panel>
            <Panel title="目标对象">
              <BucketChart data={detail.targets} barClassName="bg-emerald-500" />
            </Panel>
            <Panel title="结果 / 状态">
              <BucketChart data={detail.results} barClassName="bg-amber-500" />
            </Panel>
          </div>
          <div className="mt-0">
            <DataTable
              headers={["包号", "时间", "源", "目标", "操作", "对象", "结果", "值", "摘要"]}
              rows={detail.records.map((item) => [
                item.packetId,
                item.time || "--",
                item.source || "--",
                item.destination || "--",
                item.operation || "--",
                item.target || "--",
                item.result || "--",
                item.value || "--",
                item.summary || "--",
              ])}
            />
          </div>
        </Panel>
      ))}
    </>
  );
}

type Dnp3SectionRow = {
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

function deriveIndustrialDnp3Section(
  details: IndustrialProtocolDetail[],
  commands: IndustrialControlCommand[],
  ruleHits: IndustrialRuleHit[],
) {
  const dnp3Details = details.filter((detail) => matchesDnp3(detail.name));
  const dnp3Commands = commands.filter((command) => matchesDnp3(command.protocol));
  const dnp3Rules = ruleHits.filter((ruleHit) => matchesDnp3(ruleHit.rule));

  if (dnp3Details.length === 0 && dnp3Commands.length === 0 && dnp3Rules.length === 0) {
    return null;
  }

  const rows: Dnp3SectionRow[] = [
    ...dnp3Details.flatMap((detail) =>
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
    ...dnp3Commands.map((command) => ({
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
    ...dnp3Rules.map((ruleHit) => ({
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

  return {
    detailRecordCount: dnp3Details.reduce((sum, detail) => sum + detail.records.length, 0),
    commandCount: dnp3Commands.length,
    ruleCount: dnp3Rules.length,
    operationKinds: mergeBuckets(
      dnp3Details.flatMap((detail) => detail.operations),
      dnp3Commands.map((command) => command.operation),
      dnp3Rules.map((ruleHit) => ruleHit.functionName || ruleHit.rule),
    ).length,
    operations: mergeBuckets(
      dnp3Details.flatMap((detail) => detail.operations),
      dnp3Commands.map((command) => command.operation),
      dnp3Rules.map((ruleHit) => ruleHit.functionName || ruleHit.rule),
    ),
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

function mergeBuckets(
  existingBuckets: Array<{ label: string; count: number }>,
  ...derivedLabelGroups: Array<Array<string | undefined>>
) {
  const counts = new Map<string, number>();

  for (const bucket of existingBuckets) {
    const label = String(bucket.label ?? "").trim();
    if (!label) continue;
    counts.set(label, (counts.get(label) ?? 0) + Number(bucket.count ?? 0));
  }

  for (const derivedLabels of derivedLabelGroups) {
    for (const labelValue of derivedLabels) {
      const label = String(labelValue ?? "").trim();
      if (!label) continue;
      counts.set(label, (counts.get(label) ?? 0) + 1);
    }
  }

  return Array.from(counts.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label));
}

function matchesDnp3(value: string | undefined) {
  return String(value ?? "")
    .toLowerCase()
    .includes("dnp3");
}

function toneForIndustrialRuleLevel(level: string): AnalysisTone {
  switch (String(level ?? "").toLowerCase()) {
    case "critical":
    case "high":
      return "rose";
    case "warning":
      return "amber";
    default:
      return "blue";
  }
}

function toneForDnp3Source(sourceType: Dnp3SectionRow["sourceType"]): AnalysisTone {
  switch (sourceType) {
    case "command":
      return "rose";
    case "rule":
      return "amber";
    default:
      return "blue";
  }
}
