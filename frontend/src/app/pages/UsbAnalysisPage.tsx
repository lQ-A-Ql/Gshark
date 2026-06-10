import { Usb } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { InvestigationReportPanel } from "../components/InvestigationReportPanel";
import { PageShell } from "../components/PageShell";
import { StatusHint } from "../components/DesignSystem";
import { AnalysisWorkbenchShell } from "../components/analysis/AnalysisWorkbenchShell";
import type { AnalysisWorkbenchSection } from "../components/analysis/analysisWorkbenchTypes";
import type { USBAnalysis as USBAnalysisData, USBHIDSourceMode, USBMassStorageOperation } from "../core/types";
import { UsbHidPanel } from "../features/usb/UsbHidPanel";
import { UsbMassStoragePanel, type MassStorageSubTab } from "../features/usb/UsbMassStoragePanel";
import { UsbOtherPanel, type OtherSubTab } from "../features/usb/UsbOtherPanel";
import { UsbOverviewPanel, USB_PROTOCOL_TAGS, type UsbPrimaryTab } from "../features/usb/UsbOverviewPanel";
import { useUsbAnalysis } from "../features/usb/useUsbAnalysis";
import { useBackend } from "../state/contexts/BackendContext";
import { useCapture } from "../state/contexts/CaptureContext";
import { usePacket } from "../state/contexts/PacketContext";

type UsbWorkbenchSection = UsbPrimaryTab | "overview" | "report";

const USB_WORKBENCH_SECTIONS: AnalysisWorkbenchSection[] = [
  { id: "overview", title: "总览", description: "USB 指标与协议分布", group: "Overview" },
  { id: "hid", title: "HID", description: "键盘、鼠标与 HID 事件", group: "Domains" },
  { id: "mass-storage", title: "Mass Storage", description: "读写操作与设备过滤", group: "Domains" },
  { id: "other", title: "其他 USB", description: "控制请求与原始记录", group: "Domains" },
  { id: "report", title: "报告", description: "USB 调查报告", group: "Output" },
];

export default function UsbAnalysis() {
  const { backendConnected } = useBackend();
  const { isPreloadingCapture, fileMeta, captureRevision } = useCapture();
  const { totalPackets } = usePacket();
  const [hidSource, setHidSource] = useState<USBHIDSourceMode>("auto");
  const [hidEventLimit, setHidEventLimit] = useState(20000);
  const { analysis, loading, error, refreshAnalysis } = useUsbAnalysis({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
    hidSource,
    hidEventLimit,
  });

  const [activePrimaryTab, setActivePrimaryTab] = useState<UsbPrimaryTab>("hid");
  const [activeMassStorageSubTab, setActiveMassStorageSubTab] = useState<MassStorageSubTab>("overview");
  const [activeOtherSubTab, setActiveOtherSubTab] = useState<OtherSubTab>("overview");
  const [activeMassStorageDevice, setActiveMassStorageDevice] = useState("all");
  const [activeMassStorageLUN, setActiveMassStorageLUN] = useState("all");
  const [activeSection, setActiveSection] = useState<UsbWorkbenchSection>("hid");
  const autoEmptyOverviewRef = useRef(false);

  const otherRecords = useMemo(
    () => (analysis.other.records.length > 0 ? analysis.other.records : analysis.otherRecords),
    [analysis.other.records, analysis.otherRecords],
  );
  const controlRecords = analysis.other.controlRecords;
  const otherNotes = analysis.other.notes.length > 0 ? analysis.other.notes : analysis.notes;
  const readOperations = analysis.massStorage.readOperations;
  const writeOperations = analysis.massStorage.writeOperations;
  const massStorageNotes = analysis.massStorage.notes.length > 0 ? analysis.massStorage.notes : analysis.notes;
  const allMassStorageOperations = useMemo(() => [...readOperations, ...writeOperations], [readOperations, writeOperations]);

  useEffect(() => {
    const hasAnyDomainData = domainHasData(analysis, "hid") || domainHasData(analysis, "mass-storage") || domainHasData(analysis, "other");
    const defaultPrimaryTab = pickDefaultPrimaryTab(analysis);
    setActivePrimaryTab((prev) => (domainHasData(analysis, prev) ? prev : defaultPrimaryTab));
    setActiveSection((section) => {
      if (!hasAnyDomainData) {
        autoEmptyOverviewRef.current = true;
        return "overview";
      }
      if (autoEmptyOverviewRef.current && section === "overview") {
        autoEmptyOverviewRef.current = false;
        return defaultPrimaryTab;
      }
      autoEmptyOverviewRef.current = false;
      if (section === "hid" || section === "mass-storage" || section === "other") {
        return domainHasData(analysis, section) ? section : defaultPrimaryTab;
      }
      return section;
    });
  }, [analysis]);

  const massStorageDevices = useMemo(
    () => uniqueStrings(allMassStorageOperations.map((item) => item.device).filter(Boolean)),
    [allMassStorageOperations],
  );
  const massStorageLUNs = useMemo(
    () => uniqueStrings(allMassStorageOperations.map((item) => item.lun).filter(Boolean)),
    [allMassStorageOperations],
  );

  useEffect(() => {
    if (massStorageDevices.length === 0) {
      setActiveMassStorageDevice("all");
      return;
    }
    setActiveMassStorageDevice((prev) => (prev === "all" || massStorageDevices.includes(prev) ? prev : "all"));
  }, [massStorageDevices]);

  useEffect(() => {
    if (massStorageLUNs.length === 0) {
      setActiveMassStorageLUN("all");
      return;
    }
    setActiveMassStorageLUN((prev) => (prev === "all" || massStorageLUNs.includes(prev) ? prev : "all"));
  }, [massStorageLUNs]);

  const massStorageFilter = useCallback(
    (rows: USBMassStorageOperation[]) =>
      rows.filter((item) => {
        const deviceMatch = activeMassStorageDevice === "all" || item.device === activeMassStorageDevice;
        const lunMatch = activeMassStorageLUN === "all" || item.lun === activeMassStorageLUN;
        return deviceMatch && lunMatch;
      }),
    [activeMassStorageDevice, activeMassStorageLUN],
  );
  const filteredReadOperations = useMemo(() => massStorageFilter(readOperations), [massStorageFilter, readOperations]);
  const filteredWriteOperations = useMemo(() => massStorageFilter(writeOperations), [massStorageFilter, writeOperations]);

  return (
    <PageShell>
      <AnalysisHero
        icon={<Usb className="h-5 w-5" />}
        title="USB 行为分析"
        subtitle="USB BEHAVIOR ANALYTICS"
        description="按 HID、Mass Storage 与其他 USB 域统一编排页面，分别查看键入行为、鼠标按键行为、闪存读写与控制请求。"
        tags={USB_PROTOCOL_TAGS}
        tagsLabel="分析域"
        theme="cyan"
        onRefresh={() => refreshAnalysis(true)}
      />

      {loading && <StatusHint tone="slate">正在解析 USB / HID / Mass Storage 数据...</StatusHint>}
      {!loading && error && <StatusHint tone="amber">{error}</StatusHint>}

      <AnalysisWorkbenchShell
        sections={USB_WORKBENCH_SECTIONS}
        selectedSection={activeSection}
        onSectionChange={(section) => {
          autoEmptyOverviewRef.current = false;
          setActiveSection(section);
          if (section === "hid" || section === "mass-storage" || section === "other") {
            setActivePrimaryTab(section);
          }
        }}
      >
        {activeSection === "overview" && (
          <UsbOverviewPanel
            analysis={analysis}
            activePrimaryTab={activePrimaryTab}
            onPrimaryTabChange={(tab) => {
              autoEmptyOverviewRef.current = false;
              setActivePrimaryTab(tab);
              setActiveSection(tab);
            }}
          />
        )}

        {activeSection === "hid" && (
          <UsbHidPanel
            analysis={analysis}
            hidEventLimit={hidEventLimit}
            hidSource={hidSource}
            onHidEventLimitChange={setHidEventLimit}
            onHidSourceChange={setHidSource}
          />
        )}

        {activeSection === "mass-storage" && (
          <UsbMassStoragePanel
            analysis={analysis.massStorage}
            notes={massStorageNotes}
            activeSubTab={activeMassStorageSubTab}
            devices={massStorageDevices}
            luns={massStorageLUNs}
            activeDevice={activeMassStorageDevice}
            activeLun={activeMassStorageLUN}
            filteredReadOperations={filteredReadOperations}
            filteredWriteOperations={filteredWriteOperations}
            onSubTabChange={setActiveMassStorageSubTab}
            onDeviceChange={setActiveMassStorageDevice}
            onLunChange={setActiveMassStorageLUN}
          />
        )}

        {activeSection === "other" && (
          <UsbOtherPanel
            analysis={analysis.other}
            records={otherRecords}
            controlRecords={controlRecords}
            notes={otherNotes}
            activeSubTab={activeOtherSubTab}
            onSubTabChange={setActiveOtherSubTab}
          />
        )}

        {activeSection === "report" && (
          <InvestigationReportPanel
            className="mt-0"
            preferredProtocol="TCP"
            report={analysis.report}
            title="USB 调查报告"
          />
        )}
      </AnalysisWorkbenchShell>
    </PageShell>
  );
}

function domainHasData(analysis: USBAnalysisData, tab: UsbPrimaryTab) {
  switch (tab) {
    case "hid":
      return (
        analysis.hidPackets > 0 ||
        analysis.keyboardPackets > 0 ||
        analysis.mousePackets > 0 ||
        analysis.keyboardEvents.length > 0 ||
        analysis.mouseEvents.length > 0 ||
        analysis.hid.keyboardEvents.length > 0 ||
        analysis.hid.mouseEvents.length > 0 ||
        analysis.hid.devices.length > 0
      );
    case "mass-storage":
      return (
        analysis.massStoragePackets > 0 ||
        analysis.massStorage.totalPackets > 0 ||
        analysis.massStorage.readOperations.length > 0 ||
        analysis.massStorage.writeOperations.length > 0 ||
        analysis.massStorage.devices.length > 0 ||
        analysis.massStorage.commands.length > 0
      );
    case "other":
      return (
        analysis.otherUSBPackets > 0 ||
        analysis.other.totalPackets > 0 ||
        analysis.otherRecords.length > 0 ||
        analysis.other.records.length > 0 ||
        analysis.other.controlRecords.length > 0 ||
        analysis.other.setupRequests.length > 0
      );
    default:
      return false;
  }
}

function pickDefaultPrimaryTab(analysis: USBAnalysisData): UsbPrimaryTab {
  if (domainHasData(analysis, "hid")) return "hid";
  if (domainHasData(analysis, "mass-storage")) return "mass-storage";
  return "other";
}

function uniqueStrings(values: string[]) {
  return Array.from(new Set(values));
}
