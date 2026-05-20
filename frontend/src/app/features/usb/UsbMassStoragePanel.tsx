import {
  AnalysisBucketChart as BucketChart,
  AnalysisPanel as Panel,
  AnalysisStatCard as StatCard,
} from "../../components/analysis/AnalysisPrimitives";
import type { USBMassStorageAnalysis, USBMassStorageOperation } from "../../core/types";
import { MassStorageFilters, MassStorageOperationTable } from "./UsbTables";
import { NotesList, SecondaryTabButton } from "./UsbAnalysisControls";

export type MassStorageSubTab = "overview" | "read" | "write";

export function UsbMassStoragePanel({
  analysis,
  notes,
  activeSubTab,
  devices,
  luns,
  activeDevice,
  activeLun,
  filteredReadOperations,
  filteredWriteOperations,
  onSubTabChange,
  onDeviceChange,
  onLunChange,
}: {
  analysis: USBMassStorageAnalysis;
  notes: string[];
  activeSubTab: MassStorageSubTab;
  devices: string[];
  luns: string[];
  activeDevice: string;
  activeLun: string;
  filteredReadOperations: USBMassStorageOperation[];
  filteredWriteOperations: USBMassStorageOperation[];
  onSubTabChange: (tab: MassStorageSubTab) => void;
  onDeviceChange: (value: string) => void;
  onLunChange: (value: string) => void;
}) {
  return (
    <div className="mt-0 space-y-0">
      <div className="flex flex-wrap items-center gap-px">
        <SecondaryTabButton active={activeSubTab === "overview"} onClick={() => onSubTabChange("overview")}>
          概览
        </SecondaryTabButton>
        <SecondaryTabButton active={activeSubTab === "read"} onClick={() => onSubTabChange("read")}>
          读请求
        </SecondaryTabButton>
        <SecondaryTabButton active={activeSubTab === "write"} onClick={() => onSubTabChange("write")}>
          写请求
        </SecondaryTabButton>
      </div>

      {activeSubTab === "overview" && (
        <>
          <div className="grid grid-cols-1 gap-0 lg:grid-cols-4">
            <StatCard title="总存储包" value={analysis.totalPackets.toLocaleString()} />
            <StatCard title="读请求数" value={analysis.readPackets.toLocaleString()} />
            <StatCard title="写请求数" value={analysis.writePackets.toLocaleString()} />
            <StatCard title="LUN 数" value={String(analysis.luns.length)} />
          </div>

          <div className="grid grid-cols-1 gap-0 xl:grid-cols-3">
            <Panel title="命令分布">
              <BucketChart data={analysis.commands} barClassName="bg-cyan-500" />
            </Panel>
            <Panel title="设备分布">
              <BucketChart data={analysis.devices} barClassName="bg-violet-500" />
            </Panel>
            <Panel title="分析提示">
              <NotesList notes={notes} emptyLabel="暂无存储域提示" />
            </Panel>
          </div>
        </>
      )}

      {(activeSubTab === "read" || activeSubTab === "write") && (
        <>
          <MassStorageFilters
            devices={devices}
            luns={luns}
            activeDevice={activeDevice}
            activeLun={activeLun}
            onDeviceChange={onDeviceChange}
            onLunChange={onLunChange}
          />
          <Panel
            title={
              activeSubTab === "read"
                ? `读请求 (${filteredReadOperations.length})`
                : `写请求 (${filteredWriteOperations.length})`
            }
          >
            <MassStorageOperationTable
              rows={activeSubTab === "read" ? filteredReadOperations : filteredWriteOperations}
            />
          </Panel>
        </>
      )}
    </div>
  );
}
