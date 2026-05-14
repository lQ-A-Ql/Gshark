import { Car } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { InvestigationReportPanel } from "../components/InvestigationReportPanel";
import { PageShell } from "../components/PageShell";
import { StatusHint } from "../components/DesignSystem";
import { VehicleDetailPanels } from "../features/vehicle/VehicleDetailPanels";
import { VehicleDbcPanel } from "../features/vehicle/VehicleDbcPanel";
import { VehicleOverviewPanel, VEHICLE_PROTOCOL_TAGS } from "../features/vehicle/VehicleOverviewPanel";
import { VehicleProtocolPanels } from "../features/vehicle/VehicleProtocolPanels";
import { VehicleUdsTransactionsPanel } from "../features/vehicle/VehicleUdsTransactionsPanel";
import { useVehicleAnalysis } from "../features/vehicle/useVehicleAnalysis";
import { useVehicleDbcProfiles } from "../features/vehicle/useVehicleDbcProfiles";
import { useSentinel } from "../state/SentinelContext";

export default function VehicleAnalysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision } = useSentinel();
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
    <PageShell className="bg-[radial-gradient(circle_at_top,rgba(52,211,153,0.24),transparent_36%),linear-gradient(180deg,#f4fffb_0%,#f6f7ff_44%,#f8fafc_100%)]">
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

      <VehicleDbcPanel
        profiles={dbcProfiles}
        pathInput={dbcPathInput}
        onPathInputChange={setDBCPathInput}
        onImport={() => void importDBC().then((changed) => changed && refreshAnalysis(true))}
        onAddPath={() => void addDBC(dbcPathInput).then((changed) => changed && refreshAnalysis(true))}
        onRemove={(path) => void removeDBC(path).then((changed) => changed && refreshAnalysis(true))}
      />

      <VehicleOverviewPanel analysis={analysis} />
      <InvestigationReportPanel
        className="mt-4"
        preferredProtocol="TCP"
        report={analysis.report}
        title="车机调查报告"
      />

      <VehicleProtocolPanels analysis={analysis} />
      <VehicleDetailPanels analysis={analysis} />

      <VehicleUdsTransactionsPanel
        transactions={analysis.uds.transactions}
        filteredTransactions={filteredUdsTransactions}
        statusFilter={udsStatusFilter}
        onStatusFilterChange={setUdsStatusFilter}
      />
    </PageShell>
  );
}
