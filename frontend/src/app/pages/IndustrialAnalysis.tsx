import { Factory, Workflow } from "lucide-react";
import { useMemo, useState } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import { StatusHint } from "../components/DesignSystem";
import {
  AnalysisBucketChart as BucketChart,
  AnalysisCallout,
  AnalysisPanel as Panel,
  AnalysisStatCard as StatCard,
  AnalysisList as ConversationList,
} from "../components/analysis/AnalysisPrimitives";
import { useSentinel } from "../state/SentinelContext";
import { useIndustrialAnalysis } from "../features/industrial/useIndustrialAnalysis";
import { IndustrialModbusPanels } from "../features/industrial/IndustrialModbusPanels";
import {
  IndustrialControlCommandsPanel,
  IndustrialProtocolDetailsPanel,
  IndustrialRuleHitsPanel,
} from "../features/industrial/IndustrialAuxiliaryPanels";

const INDUSTRIAL_PROTOCOL_TAGS = [
  "Modbus",
  "S7",
  "DNP3",
  "CIP",
  "BACnet",
  "IEC104",
  "OPC UA",
  "PROFINET",
];

export default function IndustrialAnalysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision } = useSentinel();
  const { analysis, loading, error, refreshAnalysis } = useIndustrialAnalysis({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
  });

  const [modbusUnitFilter, setModbusUnitFilter] = useState("all");
  const [modbusFunctionFilter, setModbusFunctionFilter] = useState("all");

  const modbusUnitOptions = useMemo(() => {
    const units = new Set(analysis.modbus.transactions.map((t) => String(t.unitId)));
    return ["all", ...Array.from(units).sort()];
  }, [analysis.modbus.transactions]);

  const modbusFunctionOptions = useMemo(() => {
    const fns = new Set(analysis.modbus.transactions.map((t) => String(t.functionCode)));
    return ["all", ...Array.from(fns).sort()];
  }, [analysis.modbus.transactions]);

  const filteredModbusTransactions = useMemo(() => {
    return analysis.modbus.transactions.filter((t) => {
      if (modbusUnitFilter !== "all" && String(t.unitId) !== modbusUnitFilter) return false;
      if (modbusFunctionFilter !== "all" && String(t.functionCode) !== modbusFunctionFilter) return false;
      return true;
    });
  }, [analysis.modbus.transactions, modbusUnitFilter, modbusFunctionFilter]);

  return (
    <PageShell className="bg-[radial-gradient(circle_at_top,rgba(96,165,250,0.26),transparent_36%),linear-gradient(180deg,#f7fbff_0%,#f6f7ff_44%,#f8fafc_100%)]">
      <AnalysisHero
        icon={<Factory className="h-5 w-5" />}
        title="工控分析"
        subtitle="INDUSTRIAL PROTOCOLS"
        description="聚焦 Modbus 与其他工控协议的会话、功能码、异常响应和控制指令，用统一视图快速识别危险写操作。"
        tags={INDUSTRIAL_PROTOCOL_TAGS}
        tagsLabel="协议族"
        theme="blue"
        onRefresh={() => refreshAnalysis(true)}
      />

      {loading && <StatusHint tone="slate" className="mb-3">正在调用 tshark 生成工控分析结果...</StatusHint>}

      {!loading && error && <StatusHint tone="amber" className="mb-3">{error}</StatusHint>}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <StatCard title="工控相关包" value={analysis.totalIndustrialPackets.toLocaleString()} />
        <StatCard title="识别协议" value={String(analysis.protocols.length)} />
        <StatCard title="Modbus 帧" value={analysis.modbus.totalFrames.toLocaleString()} />
        <StatCard title="异常响应" value={analysis.modbus.exceptions.toLocaleString()} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="工控协议分布">
          <BucketChart data={analysis.protocols} barClassName="bg-blue-500" />
        </Panel>
        <Panel title="工控会话">
          <ConversationList
            items={analysis.conversations.map((item) => ({
              label: item.protocol ? `${item.protocol} · ${item.label}` : item.label,
              count: item.count,
            }))}
          />
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-4">
        <StatCard title="Modbus 请求" value={analysis.modbus.requests.toLocaleString()} />
        <StatCard title="Modbus 响应" value={analysis.modbus.responses.toLocaleString()} />
        <StatCard title="功能码种类" value={String(analysis.modbus.functionCodes.length)} />
        <StatCard title="目标 Unit 数" value={String(analysis.modbus.unitIds.length)} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="Modbus 功能码">
          <BucketChart data={analysis.modbus.functionCodes} barClassName="bg-indigo-500" />
        </Panel>
        <Panel title="Modbus Unit ID">
          <BucketChart data={analysis.modbus.unitIds} barClassName="bg-cyan-500" />
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="寄存器 / 线圈引用">
          <BucketChart data={analysis.modbus.referenceHits} barClassName="bg-emerald-500" />
        </Panel>
        <Panel title="异常码">
          <BucketChart data={analysis.modbus.exceptionCodes} barClassName="bg-rose-500" />
        </Panel>
      </div>

      <IndustrialRuleHitsPanel ruleHits={analysis.ruleHits ?? []} />

      <Panel title="分析提示" className="mt-4">
        <div className="space-y-2 text-sm">
          {analysis.notes.length === 0 ? (
            <div className="rounded border border-dashed border-border px-3 py-3 text-muted-foreground">当前抓包未识别到工控协议。</div>
          ) : (
            analysis.notes.map((note, index) => (
              <AnalysisCallout key={`${note}-${index}`} tone="blue" icon={<Workflow className="h-4 w-4" />}>
                {note}
              </AnalysisCallout>
            ))
          )}
        </div>
      </Panel>

      <IndustrialModbusPanels
        suspiciousWrites={analysis.suspiciousWrites ?? []}
        decodedInputs={analysis.modbus.decodedInputs ?? []}
        transactions={filteredModbusTransactions}
        unitOptions={modbusUnitOptions}
        functionOptions={modbusFunctionOptions}
        unitFilter={modbusUnitFilter}
        functionFilter={modbusFunctionFilter}
        onUnitFilterChange={setModbusUnitFilter}
        onFunctionFilterChange={setModbusFunctionFilter}
      />

      <IndustrialControlCommandsPanel commands={analysis.controlCommands ?? []} />
      <IndustrialProtocolDetailsPanel details={analysis.details} />
    </PageShell>
  );
}
