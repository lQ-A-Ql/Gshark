import { AnalysisDataTable } from "../../components/analysis/AnalysisPrimitives";
import { cn } from "../../components/ui/utils";
import type { UnifiedEvidenceRecord } from "./evidenceSchema";
import { evidenceTableColumns } from "./EvidenceTableColumns";

interface EvidenceTableProps {
  loading: boolean;
  records: UnifiedEvidenceRecord[];
  selectedId: string | null;
  onSelect: (recordId: string) => void;
}

export function EvidenceTable({ loading, records, selectedId, onSelect }: EvidenceTableProps) {
  return (
    <AnalysisDataTable
      columns={evidenceTableColumns()}
      data={records}
      rowKey={(item) => item.id}
      onRowClick={(item) => onSelect(item.id)}
      rowClassName={(item) =>
        cn(
          "border-l-2 border-l-transparent",
          selectedId === item.id && "border-l-indigo-400 bg-[var(--meow-table-selected-bg)]",
        )
      }
      maxHeightClassName="max-h-[720px]"
      tableClassName="min-w-[760px]"
      emptyText={loading ? "正在加载..." : "当前抓包未产生证据记录"}
    />
  );
}
