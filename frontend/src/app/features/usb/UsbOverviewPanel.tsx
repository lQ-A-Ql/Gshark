import { HardDrive, Keyboard, Usb } from "lucide-react";
import {
  AnalysisBucketChart as BucketChart,
  AnalysisPanel as Panel,
  AnalysisStatCard as StatCard,
} from "../../components/analysis/AnalysisPrimitives";
import type { USBAnalysis } from "../../core/types";
import { NotesList, PrimaryTabButton } from "./UsbAnalysisControls";

export type UsbPrimaryTab = "hid" | "mass-storage" | "other";

export const USB_PROTOCOL_TAGS = ["HID", "Mass Storage", "其他"];

export function UsbOverviewPanel({
  analysis,
  activePrimaryTab,
  onPrimaryTabChange,
}: {
  analysis: USBAnalysis;
  activePrimaryTab: UsbPrimaryTab;
  onPrimaryTabChange: (tab: UsbPrimaryTab) => void;
}) {
  return (
    <>
      <div className="grid grid-cols-1 gap-0 lg:grid-cols-4">
        <StatCard title="USB 包总数" value={analysis.totalUSBPackets.toLocaleString()} />
        <StatCard title="HID" value={String(analysis.hidPackets || analysis.keyboardPackets + analysis.mousePackets)} />
        <StatCard title="Mass Storage" value={String(analysis.massStoragePackets)} />
        <StatCard title="其他" value={analysis.otherUSBPackets.toLocaleString()} />
      </div>

      <div className="mt-0 grid grid-cols-1 gap-0 xl:grid-cols-3">
        <Panel title="协议分布">
          <BucketChart data={analysis.protocols} barClassName="bg-blue-500" />
        </Panel>
        <Panel title="传输类型">
          <BucketChart data={analysis.transferTypes} barClassName="bg-emerald-500" />
        </Panel>
        <Panel title="分析提示">
          <NotesList notes={analysis.notes} emptyLabel="当前抓包未识别到可展示的 USB 行为。" />
        </Panel>
      </div>

      <div className="mt-0 flex flex-wrap items-center gap-px">
        <PrimaryTabButton
          active={activePrimaryTab === "hid"}
          onClick={() => onPrimaryTabChange("hid")}
          icon={<Keyboard className="h-4 w-4" />}
        >
          HID
        </PrimaryTabButton>
        <PrimaryTabButton
          active={activePrimaryTab === "mass-storage"}
          onClick={() => onPrimaryTabChange("mass-storage")}
          icon={<HardDrive className="h-4 w-4" />}
        >
          Mass Storage
        </PrimaryTabButton>
        <PrimaryTabButton
          active={activePrimaryTab === "other"}
          onClick={() => onPrimaryTabChange("other")}
          icon={<Usb className="h-4 w-4" />}
        >
          其他
        </PrimaryTabButton>
      </div>
    </>
  );
}
