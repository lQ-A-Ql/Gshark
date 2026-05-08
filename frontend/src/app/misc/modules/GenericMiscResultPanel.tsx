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
    <div className="space-y-3 rounded-2xl border border-slate-200 bg-gradient-to-br from-slate-50 to-white p-4 shadow-[0_14px_36px_rgba(15,23,42,0.06)]">
      <div className="flex items-center justify-between gap-3">
        <div className="text-sm font-semibold text-slate-800">{resultTitle}</div>
        <Badge variant="outline" className="rounded-full border-emerald-100 bg-emerald-50 text-[11px] text-emerald-700">
          Result
        </Badge>
      </div>
      {resultTable && resultTable.columns.length > 0 ? (
        <DataTable<Record<string, string>>
          data={resultTable.rows}
          rowKey={(_, index) => `${moduleId}-row-${index}`}
          maxHeightClassName="max-h-72"
          tableClassName="min-w-full text-slate-700"
          wrapperClassName="border-slate-200 bg-white shadow-sm"
          headerClassName="bg-gradient-to-r from-slate-100 to-cyan-50 text-slate-800"
          emptyText="暂无表格结果"
          rowClassName="last:border-b-0 hover:bg-cyan-50/40"
          columns={resultTable.columns.map((column) => ({
            key: column.key,
            header: column.label,
            headerClassName: "whitespace-nowrap border-b border-slate-200 py-2.5 font-semibold",
            cellClassName: "whitespace-pre-wrap py-2.5 align-top",
            render: (row) => row[column.key] ?? "",
          }))}
        />
      ) : null}
      {resultText ? (
        <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-xl border border-slate-200 bg-white p-3.5 text-xs leading-relaxed text-slate-700 shadow-inner">
          {resultText}
        </pre>
      ) : null}
      {resultJSON ? (
        <pre className="max-h-72 overflow-auto rounded-xl border border-slate-800 bg-[linear-gradient(135deg,#020617_0%,#0f172a_58%,#111827_100%)] p-3.5 text-xs leading-relaxed text-cyan-50 shadow-inner">
          {resultJSON}
        </pre>
      ) : null}
    </div>
  );
}
