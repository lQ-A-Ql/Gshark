import { useMemo, useState } from "react";
import { FileDown } from "lucide-react";
import { AnalysisHero } from "../components/AnalysisHero";
import { InvestigationReportPanel } from "../components/InvestigationReportPanel";
import { AnalysisPanel } from "../components/analysis/AnalysisPrimitives";
import { PageShell } from "../components/PageShell";
import { buildObjectInvestigationReport } from "../features/object/objectInvestigationReport";
import { useSentinel } from "../state/SentinelContext";
import {
  ObjectExportFooter,
  ObjectExportToolbar,
  ObjectGroupChips,
  ObjectGroupGrid,
} from "../features/object/ObjectExportPanels";
import { filterObjects, groupObjectsByMagic, type ObjectKind } from "../features/object/objectExportRules";
import { useObjectExport } from "../features/object/useObjectExport";

const OBJECT_EXPORT_TAGS = ["HTTP", "FTP", "文件对象", "Magic 分类", "批量导出"];

export default function ObjectExport() {
  const { extractedObjects, backendConnected } = useSentinel();
  const { objects: sourceObjects, downloadZip } = useObjectExport({ backendConnected, extractedObjects });
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

  return (
    <PageShell>
      <AnalysisHero
        icon={<FileDown className="h-5 w-5" />}
        title="附件提取"
        subtitle="EXTRACTED OBJECTS"
        description="按文件类型（magic bytes）统一查看当前抓包里可导出的对象，快速筛选、分组并批量导出。"
        tags={OBJECT_EXPORT_TAGS}
        tagsLabel="对象域"
        theme="amber"
      />
      <AnalysisPanel title="对象筛选" tone="amber">
        <ObjectExportToolbar
          count={objects.length}
          query={query}
          typeFilter={typeFilter}
          onQueryChange={setQuery}
          onTypeFilterChange={setTypeFilter}
        />
        <ObjectGroupChips groups={magicGroups} />
      </AnalysisPanel>
      <InvestigationReportPanel report={report} title="对象调查报告" />
      <AnalysisPanel title={`对象分组 (${objects.length})`} tone="amber">
        <ObjectGroupGrid
          expandedGroups={expandedGroups}
          groups={magicGroups}
          selectedIds={selected}
          onExpandGroup={(label) => setExpandedGroups((prev) => ({ ...prev, [label]: true }))}
          onToggleSelect={toggleSelect}
        />
      </AnalysisPanel>
      <AnalysisPanel title="导出队列" tone="amber">
        <ObjectExportFooter
          objectCount={objects.length}
          selectedBytes={selectedBytes}
          selectedCount={selectedObjects.length}
          onDownloadAll={() => downloadZip(objects.map((item) => item.id))}
          onDownloadSelected={() => downloadZip(selectedObjects.map((item) => item.id))}
        />
      </AnalysisPanel>
    </PageShell>
  );
}
