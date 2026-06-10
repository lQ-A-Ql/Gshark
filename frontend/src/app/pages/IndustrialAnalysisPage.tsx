import { Factory, Workflow } from "lucide-react";
import { useState } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { InvestigationReportPanel } from "../components/InvestigationReportPanel";
import { PageShell } from "../components/PageShell";
import { MetricCard, StatusHint } from "../components/DesignSystem";
import { AnalysisWorkbenchShell } from "../components/analysis/AnalysisWorkbenchShell";
import {
  AnalysisBucketChart as BucketChart,
  AnalysisCallout,
  AnalysisPanel as Panel,
  AnalysisList as ConversationList,
} from "../components/analysis/AnalysisPrimitives";
import type { AnalysisWorkbenchSection } from "../components/analysis/analysisWorkbenchTypes";
import { useBackend } from "../state/contexts/BackendContext";
import { useCapture } from "../state/contexts/CaptureContext";
import { usePacket } from "../state/contexts/PacketContext";
import { useIndustrialAnalysis } from "../features/industrial/useIndustrialAnalysis";
import { IndustrialModbusPanels } from "../features/industrial/IndustrialModbusPanels";
import {
  IndustrialControlCommandsPanel, IndustrialDnp3Panel, IndustrialProtocolDetailsPanel, IndustrialRuleHitsPanel,
} from "../features/industrial/IndustrialAuxiliaryPanels";
import { useIndustrialModbusFilters } from "./useIndustrialModbusFilters";
const INDUSTRIAL_PROTOCOL_TAGS = ["Modbus", "S7", "DNP3", "CIP", "BACnet", "IEC104", "OPC UA", "PROFINET"];

type IndustrialWorkbenchSection = "overview" | "modbus" | "alerts" | "dnp3" | "commands" | "details" | "report";

const INDUSTRIAL_WORKBENCH_SECTIONS: AnalysisWorkbenchSection[] = [
  { id: "overview", title: "总览", description: "工控指标、协议与会话", group: "Overview" },
  { id: "modbus", title: "Modbus", description: "功能码、事务与输入重组", group: "Protocols" },
  { id: "alerts", title: "告警", description: "规则命中与分析提示", group: "Signals" },
  { id: "dnp3", title: "DNP3", description: "DNP3 明细、命令与规则", group: "Protocols" },
  { id: "commands", title: "控制命令", description: "跨协议控制操作", group: "Signals" },
  { id: "details", title: "明细", description: "协议明细记录", group: "Workspace" },
  { id: "report", title: "报告", description: "工控调查报告", group: "Output" },
];

export default function IndustrialAnalysis() {
  const { backendConnected } = useBackend();
  const { isPreloadingCapture, fileMeta, captureRevision } = useCapture();
  const { totalPackets } = usePacket();
  const [activeSection, setActiveSection] = useState<IndustrialWorkbenchSection>("overview");
  const { analysis, loading, error, refreshAnalysis } = useIndustrialAnalysis({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
  });

  const modbusFilters = useIndustrialModbusFilters(analysis);

  return (
    <PageShell>
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

      {loading && (
        <StatusHint tone="slate" className="mb-3">
          正在调用 tshark 生成工控分析结果...
        </StatusHint>
      )}

      {!loading && error && (
        <StatusHint tone="amber" className="mb-3">
          {error}
        </StatusHint>
      )}

      <AnalysisWorkbenchShell
        sections={INDUSTRIAL_WORKBENCH_SECTIONS}
        selectedSection={activeSection}
        onSectionChange={setActiveSection}
      >
        {activeSection === "overview" && (
          <>
            <div className="grid grid-cols-1 lg:grid-cols-4">
              <MetricCard label="工控相关包" value={analysis.totalIndustrialPackets.toLocaleString()} />
              <MetricCard label="识别协议" value={String(analysis.protocols.length)} />
              <MetricCard label="Modbus 帧" value={analysis.modbus.totalFrames.toLocaleString()} />
              <MetricCard label="异常响应" value={analysis.modbus.exceptions.toLocaleString()} />
            </div>

            <div className="mt-0 grid grid-cols-1 xl:grid-cols-2">
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
          </>
        )}

        {activeSection === "modbus" && (
          <>
            <div className="mt-0 grid grid-cols-1 lg:grid-cols-4">
              <MetricCard label="Modbus 请求" value={analysis.modbus.requests.toLocaleString()} />
              <MetricCard label="Modbus 响应" value={analysis.modbus.responses.toLocaleString()} />
              <MetricCard label="功能码种类" value={String(analysis.modbus.functionCodes.length)} />
              <MetricCard label="目标 Unit 数" value={String(analysis.modbus.unitIds.length)} />
            </div>

            <div className="mt-0 grid grid-cols-1 xl:grid-cols-2">
              <Panel title="Modbus 功能码">
                <BucketChart data={analysis.modbus.functionCodes} barClassName="bg-indigo-500" />
              </Panel>
              <Panel title="Modbus Unit ID">
                <BucketChart data={analysis.modbus.unitIds} barClassName="bg-cyan-500" />
              </Panel>
            </div>

            <div className="mt-0 grid grid-cols-1 xl:grid-cols-2">
              <Panel title="寄存器 / 线圈引用">
                <BucketChart data={analysis.modbus.referenceHits} barClassName="bg-emerald-500" />
              </Panel>
              <Panel title="异常码">
                <BucketChart data={analysis.modbus.exceptionCodes} barClassName="bg-rose-500" />
              </Panel>
            </div>

            <IndustrialModbusPanels
              suspiciousWrites={analysis.suspiciousWrites ?? []}
              decodedInputs={analysis.modbus.decodedInputs ?? []}
              transactions={modbusFilters.filteredModbusTransactions}
              unitOptions={modbusFilters.modbusUnitOptions}
              functionOptions={modbusFilters.modbusFunctionOptions}
              unitFilter={modbusFilters.modbusUnitFilter}
              functionFilter={modbusFilters.modbusFunctionFilter}
              onUnitFilterChange={modbusFilters.setModbusUnitFilter}
              onFunctionFilterChange={modbusFilters.setModbusFunctionFilter}
            />
          </>
        )}

        {activeSection === "alerts" && (
          <>
            <IndustrialRuleHitsPanel ruleHits={analysis.ruleHits ?? []} />
            <Panel title="分析提示" className="mt-0">
              <div className="space-y-2 text-sm">
                {analysis.notes.length === 0 ? (
                  <div className="px-3 py-3 text-muted-foreground">
                    当前抓包未识别到工控协议。
                  </div>
                ) : (
                  analysis.notes.map((note, index) => (
                    <AnalysisCallout key={`${note}-${index}`} tone="blue" icon={<Workflow className="h-4 w-4" />}>
                      {note}
                    </AnalysisCallout>
                  ))
                )}
              </div>
            </Panel>
          </>
        )}

        {activeSection === "dnp3" && (
          <IndustrialDnp3Panel
            details={analysis.details}
            commands={analysis.controlCommands ?? []}
            ruleHits={analysis.ruleHits ?? []}
          />
        )}

        {activeSection === "commands" && <IndustrialControlCommandsPanel commands={analysis.controlCommands ?? []} />}

        {activeSection === "details" && <IndustrialProtocolDetailsPanel details={analysis.details} />}

        {activeSection === "report" && (
          <InvestigationReportPanel
            className="mt-0"
            preferredProtocol="TCP"
            report={analysis.report}
            title="工控调查报告"
          />
        )}
      </AnalysisWorkbenchShell>
    </PageShell>
  );
}
