import { Car } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { InvestigationReportPanel } from "../components/InvestigationReportPanel";
import { PageShell } from "../components/PageShell";
import { StatusHint } from "../components/DesignSystem";
import { AnalysisWorkbenchShell } from "../components/analysis/AnalysisWorkbenchShell";
import type { AnalysisWorkbenchSection } from "../components/analysis/analysisWorkbenchTypes";
import { VehicleDetailPanels } from "../features/vehicle/VehicleDetailPanels";
import { VehicleDbcPanel } from "../features/vehicle/VehicleDbcPanel";
import { VehicleOverviewPanel, VEHICLE_PROTOCOL_TAGS } from "../features/vehicle/VehicleOverviewPanel";
import { VehicleProtocolPanels } from "../features/vehicle/VehicleProtocolPanels";
import { VehicleUdsTransactionsPanel } from "../features/vehicle/VehicleUdsTransactionsPanel";
import { useVehicleAnalysis } from "../features/vehicle/useVehicleAnalysis";
import { useVehicleDbcProfiles } from "../features/vehicle/useVehicleDbcProfiles";
import { useBackend } from "../state/contexts/BackendContext";
import { useCapture } from "../state/contexts/CaptureContext";
import { usePacket } from "../state/contexts/PacketContext";

type VehicleWorkbenchSection = "setup" | "overview" | "protocols" | "details" | "uds" | "report";

const VEHICLE_WORKBENCH_SECTIONS: AnalysisWorkbenchSection[] = [
  { id: "setup", title: "Setup", description: "DBC profile 与分析输入", group: "Setup" },
  { id: "overview", title: "总览", description: "车机协议指标", group: "Analysis" },
  { id: "protocols", title: "协议", description: "CAN、J1939、DoIP、UDS", group: "Analysis" },
  { id: "details", title: "明细", description: "CAN ID、payload 与 signal", group: "Workspace" },
  { id: "uds", title: "UDS", description: "诊断事务与状态过滤", group: "Workspace" },
  { id: "report", title: "报告", description: "车机调查报告", group: "Output" },
];

export default function VehicleAnalysis() {
  const { backendConnected } = useBackend();
  const { isPreloadingCapture, fileMeta, captureRevision } = useCapture();
  const { totalPackets } = usePacket();
  const {
    profiles: dbcProfiles,
    pathInput: dbcPathInput,
    error: dbcError,
    setPathInput: setDBCPathInput,
    addPath: addDBC,
    removePath: removeDBC,
    importFile: importDBC,
  } = useVehicleDbcProfiles({ backendConnected });
  const {
    analysis,
    loading,
    error: analysisError,
    refreshAnalysis,
  } = useVehicleAnalysis({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
    dbcProfiles,
  });
  const error = analysisError || dbcError;
  const [activeSection, setActiveSection] = useState<VehicleWorkbenchSection>("setup");
  const [udsStatusFilter, setUdsStatusFilter] = useState("all");
  const filteredUdsTransactions = useMemo(() => {
    if (udsStatusFilter === "all") return analysis.uds.transactions;
    return analysis.uds.transactions.filter((t) => t.status === udsStatusFilter);
  }, [analysis.uds.transactions, udsStatusFilter]);

  useEffect(() => {
    if (isPreloadingCapture) return;
    return refreshAnalysis();
  }, [isPreloadingCapture, refreshAnalysis]);

  return (
    <PageShell>
      <AnalysisHero
        icon={<Car className="h-5 w-5" />}
        title="车机流量分析"
        subtitle="AUTOMOTIVE PROTOCOLS"
        description="统一查看 CAN、J1939、DoIP、UDS 等车载协议，并在同一页处理 DBC 映射、诊断事务和安全提示。"
        tags={VEHICLE_PROTOCOL_TAGS}
        tagsLabel="协议族"
        theme="emerald"
        onRefresh={() => refreshAnalysis(true)}
      />

      {loading && (
        <StatusHint tone="slate" className="mb-3">
          正在调用 tshark 生成车机分析结果...
        </StatusHint>
      )}

      {!loading && error && (
        <StatusHint tone="amber" className="mb-3">
          {error}
        </StatusHint>
      )}

      <AnalysisWorkbenchShell
        sections={VEHICLE_WORKBENCH_SECTIONS}
        selectedSection={activeSection}
        onSectionChange={setActiveSection}
      >
        {activeSection === "setup" && (
          <VehicleDbcPanel
            profiles={dbcProfiles}
            pathInput={dbcPathInput}
            onPathInputChange={setDBCPathInput}
            onImport={() => void importDBC().then((changed) => changed && refreshAnalysis(true))}
            onAddPath={() => void addDBC(dbcPathInput).then((changed) => changed && refreshAnalysis(true))}
            onRemove={(path) => void removeDBC(path).then((changed) => changed && refreshAnalysis(true))}
          />
        )}

        {activeSection === "overview" && <VehicleOverviewPanel analysis={analysis} />}

        {activeSection === "protocols" && <VehicleProtocolPanels analysis={analysis} />}

        {activeSection === "details" && <VehicleDetailPanels analysis={analysis} />}

        {activeSection === "uds" && (
          <VehicleUdsTransactionsPanel
            transactions={analysis.uds.transactions}
            filteredTransactions={filteredUdsTransactions}
            statusFilter={udsStatusFilter}
            onStatusFilterChange={setUdsStatusFilter}
          />
        )}

        {activeSection === "report" && (
          <InvestigationReportPanel
            className="mt-0"
            preferredProtocol="TCP"
            report={analysis.report}
            title="车机调查报告"
          />
        )}
      </AnalysisWorkbenchShell>
    </PageShell>
  );
}
