import { Badge } from "../../components/ui/badge";
import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import type { MiscModuleTableResult } from "../../core/types";

type GenericMiscResultPanelProps = {
  moduleId: string;
  resultJSON: string;
  resultTable?: MiscModuleTableResult;
  resultText: string;
  resultTitle: string;
};

export function GenericMiscResultPanel({
  moduleId,
  resultJSON,
  resultTable,
  resultText,
  resultTitle,
}: GenericMiscResultPanelProps) {
  if (!resultText && !resultJSON && !resultTable) {
    return null;
  }

  return (
    <div className="gshark-soft-fill space-y-3 p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="text-sm font-semibold text-slate-800">{resultTitle}</div>
        <Badge
          variant="outline"
          className="gshark-diffuse-chip border-emerald-200/24 bg-emerald-50/16 text-[11px] text-emerald-700"
        >
          Result
        </Badge>
      </div>
      {resultTable && resultTable.columns.length > 0 ? (
        <DataTable<Record<string, string>>
          data={resultTable.rows}
          rowKey={(_, index) => `${moduleId}-row-${index}`}
          maxHeightClassName="max-h-72"
          tableClassName="min-w-full text-slate-700"
          wrapperClassName="gshark-tile-table border-slate-200/18"
          headerClassName="gshark-tile-header bg-white/12 text-slate-800"
          emptyText="暂无表格结果"
          rowClassName="last:border-b-0 hover:bg-cyan-50/20"
          columns={resultTable.columns.map((column) => ({
            key: column.key,
            header: column.label,
            headerClassName: "whitespace-nowrap border-b border-slate-200/18 py-2.5 font-semibold",
            cellClassName: "whitespace-pre-wrap py-2.5 align-top",
            render: (row) => row[column.key] ?? "",
          }))}
        />
      ) : null}
      {resultText ? (
        <pre className="gshark-soft-fill max-h-72 overflow-auto whitespace-pre-wrap break-words p-3.5 text-xs leading-relaxed text-slate-700">
          {resultText}
        </pre>
      ) : null}
      {resultJSON ? (
        <pre className="max-h-72 overflow-auto border border-slate-900/35 bg-slate-950/88 p-3.5 text-xs leading-relaxed text-cyan-50 shadow-[inset_0_1px_24px_rgba(34,211,238,0.08)]">
          {resultJSON}
        </pre>
      ) : null}
    </div>
  );
}
