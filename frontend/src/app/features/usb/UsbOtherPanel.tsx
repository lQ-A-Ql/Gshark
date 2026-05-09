import {
  AnalysisBucketChart as BucketChart,
  AnalysisPanel as Panel,
  AnalysisStatCard as StatCard,
} from "../../components/analysis/AnalysisPrimitives";
import type { USBOtherAnalysis, USBPacketRecord } from "../../core/types";
import { NotesList, SecondaryTabButton } from "./UsbAnalysisControls";
import { ControlRequestTable, USBRecordTable } from "./UsbTables";

export type OtherSubTab = "overview" | "control" | "raw";

export function UsbOtherPanel({
  analysis,
  records,
  controlRecords,
  notes,
  activeSubTab,
  onSubTabChange,
}: {
  analysis: USBOtherAnalysis;
  records: USBPacketRecord[];
  controlRecords: USBPacketRecord[];
  notes: string[];
  activeSubTab: OtherSubTab;
  onSubTabChange: (tab: OtherSubTab) => void;
}) {
  return (
    <div className="mt-4 space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <SecondaryTabButton active={activeSubTab === "overview"} onClick={() => onSubTabChange("overview")}>
          概览
        </SecondaryTabButton>
        <SecondaryTabButton active={activeSubTab === "control"} onClick={() => onSubTabChange("control")}>
          控制请求
        </SecondaryTabButton>
        <SecondaryTabButton active={activeSubTab === "raw"} onClick={() => onSubTabChange("raw")}>
          原始记录
        </SecondaryTabButton>
      </div>

      {activeSubTab === "overview" && (
        <>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
            <StatCard title="其他 USB 包" value={analysis.totalPackets.toLocaleString()} />
            <StatCard title="设备数" value={String(analysis.devices.length)} />
            <StatCard title="端点数" value={String(analysis.endpoints.length)} />
            <StatCard
              title="Setup 请求数"
              value={String(analysis.setupRequests.reduce((sum, item) => sum + item.count, 0))}
            />
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <Panel title="设备分布">
              <BucketChart data={analysis.devices} barClassName="bg-amber-500" />
            </Panel>
            <Panel title="端点分布">
              <BucketChart data={analysis.endpoints} barClassName="bg-slate-500" />
            </Panel>
            <Panel title="Setup 请求分布">
              <BucketChart data={analysis.setupRequests} barClassName="bg-rose-500" />
            </Panel>
          </div>

          <Panel title="其他域提示">
            <NotesList notes={notes} emptyLabel="暂无其他域提示" />
          </Panel>
        </>
      )}

      {activeSubTab === "control" && (
        <Panel title={`控制请求 (${controlRecords.length})`}>
          <ControlRequestTable rows={controlRecords} />
        </Panel>
      )}

      {activeSubTab === "raw" && (
        <Panel title={`原始记录 (${records.length})`}>
          <USBRecordTable rows={records} />
        </Panel>
      )}
    </div>
  );
}
