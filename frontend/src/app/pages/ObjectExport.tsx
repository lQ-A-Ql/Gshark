import { useMemo, useState } from "react";
import { InvestigationReportPanel } from "../components/InvestigationReportPanel";
import { PageShell } from "../components/PageShell";
import { backendClients } from "../integrations/backendClients";
import { buildObjectInvestigationReport } from "../features/object/objectInvestigationReport";
import { useSentinel } from "../state/SentinelContext";
import {
  ObjectExportFooter,
  ObjectExportHero,
  ObjectExportToolbar,
  ObjectGroupChips,
  ObjectGroupGrid,
} from "../features/object/ObjectExportPanels";
import { filterObjects, groupObjectsByMagic, type ObjectKind } from "../features/object/objectExportRules";
import { useObjectExport } from "../features/object/useObjectExport";

const OBJECT_EXPORT_TAGS = ["HTTP", "FTP", "文件对象", "Magic 分类", "批量导出"];

export default function ObjectExport() {
  const { extractedObjects, backendConnected } = useSentinel();
  const { objects: sourceObjects } = useObjectExport({ backendConnected, extractedObjects });
  const [selected, setSelected] = useState<number[]>([]);
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<ObjectKind | "all">("all");
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({});

  const objects = useMemo(() => filterObjects(sourceObjects, query, typeFilter), [sourceObjects, query, typeFilter]);
  const selectedObjects = objects.filter((item) => selected.includes(item.id));
  const selectedBytes = selectedObjects.reduce((sum, item) => sum + item.sizeBytes, 0);
  const magicGroups = useMemo(() => groupObjectsByMagic(objects), [objects]);
  const report = useMemo(() => buildObjectInvestigationReport(objects), [objects]);

  const toggleSelect = (id: number) => {
    setSelected((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  };

  const downloadZip = async (ids: number[]) => {
    if (ids.length === 0) return;
    try {
      await backendClients.object.downloadObjectsZip(ids);
    } catch (err) {
      console.error("下载失败:", err);
    }
  };

  return (
    <PageShell
      className="bg-[radial-gradient(circle_at_top,rgba(251,191,36,0.26),transparent_36%),linear-gradient(180deg,#fffaf0_0%,#fbfbff_44%,#f8fafc_100%)]"
      innerClassName="mx-auto flex w-full max-w-[1200px] flex-col gap-6 px-4 py-8 sm:px-6 lg:px-8"
    >
      <section className="rounded-[28px] border border-white/70 bg-white/72 px-6 py-6 shadow-[0_30px_80px_rgba(251,191,36,0.16)] backdrop-blur-xl sm:px-8 lg:px-10">
        <ObjectExportHero tags={OBJECT_EXPORT_TAGS} />
        <ObjectExportToolbar
          count={objects.length}
          query={query}
          typeFilter={typeFilter}
          onQueryChange={setQuery}
          onTypeFilterChange={setTypeFilter}
        />
        <ObjectGroupChips groups={magicGroups} />
        <InvestigationReportPanel className="mt-6" report={report} title="对象调查报告" />
        <ObjectGroupGrid
          expandedGroups={expandedGroups}
          groups={magicGroups}
          selectedIds={selected}
          onExpandGroup={(label) => setExpandedGroups((prev) => ({ ...prev, [label]: true }))}
          onToggleSelect={toggleSelect}
        />
        <ObjectExportFooter
          objectCount={objects.length}
          selectedBytes={selectedBytes}
          selectedCount={selectedObjects.length}
          onDownloadAll={() => downloadZip(objects.map((item) => item.id))}
          onDownloadSelected={() => downloadZip(selectedObjects.map((item) => item.id))}
        />
      </section>
    </PageShell>
  );
}
