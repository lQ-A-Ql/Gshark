import { Fragment, type ReactNode } from "react";
import { cn } from "../ui/utils";

export type AnalysisTone = "amber" | "blue" | "cyan" | "emerald" | "rose" | "slate" | "violet";
type AnalysisBucket = {
  label: string;
  count: number;
};

const toneShadow: Record<AnalysisTone, string> = {
  amber: "hover:shadow-[0_28px_72px_rgba(245,158,11,0.14)]",
  blue: "hover:shadow-[0_28px_72px_rgba(59,130,246,0.14)]",
  cyan: "hover:shadow-[0_28px_72px_rgba(6,182,212,0.14)]",
  emerald: "hover:shadow-[0_28px_72px_rgba(16,185,129,0.14)]",
  rose: "hover:shadow-[0_28px_72px_rgba(244,63,94,0.14)]",
  slate: "hover:shadow-[0_28px_72px_rgba(148,163,184,0.16)]",
  violet: "hover:shadow-[0_28px_72px_rgba(139,92,246,0.14)]",
};

const tonePanelShadow: Record<AnalysisTone, string> = {
  amber: "hover:shadow-[0_28px_72px_rgba(245,158,11,0.12)]",
  blue: "hover:shadow-[0_28px_72px_rgba(59,130,246,0.12)]",
  cyan: "hover:shadow-[0_28px_72px_rgba(6,182,212,0.12)]",
  emerald: "hover:shadow-[0_28px_72px_rgba(16,185,129,0.12)]",
  rose: "hover:shadow-[0_28px_72px_rgba(244,63,94,0.12)]",
  slate: "hover:shadow-[0_28px_72px_rgba(148,163,184,0.14)]",
  violet: "hover:shadow-[0_28px_72px_rgba(139,92,246,0.12)]",
};

const toneCallout: Record<AnalysisTone, string> = {
  amber: "border-amber-200 bg-amber-50/88 text-amber-700",
  blue: "border-blue-200 bg-blue-50/88 text-blue-700",
  cyan: "border-cyan-200 bg-cyan-50/88 text-cyan-700",
  emerald: "border-emerald-200 bg-emerald-50/88 text-emerald-700",
  rose: "border-rose-200 bg-rose-50/88 text-rose-700",
  slate: "border-slate-200 bg-slate-50/88 text-slate-600",
  violet: "border-violet-200 bg-violet-50/88 text-violet-700",
};

const toneMiniText: Record<AnalysisTone, string> = {
  amber: "text-amber-700",
  blue: "text-blue-700",
  cyan: "text-cyan-700",
  emerald: "text-emerald-700",
  rose: "text-rose-700",
  slate: "text-slate-800",
  violet: "text-violet-700",
};

const toneBadge: Record<AnalysisTone, string> = {
  amber: "border-amber-200 bg-amber-50 text-amber-700",
  blue: "border-blue-200 bg-blue-50 text-blue-700",
  cyan: "border-cyan-200 bg-cyan-50 text-cyan-700",
  emerald: "border-emerald-200 bg-emerald-50 text-emerald-700",
  rose: "border-rose-200 bg-rose-50 text-rose-700",
  slate: "border-slate-200 bg-slate-50 text-slate-600",
  violet: "border-violet-200 bg-violet-50 text-violet-700",
};

export function AnalysisStatCard({
  title,
  value,
  icon,
  tone = "slate",
  className,
}: {
  title: string;
  value: ReactNode;
  icon?: ReactNode;
  tone?: AnalysisTone;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "rounded-[24px] border border-white/80 bg-white/88 p-4 shadow-[0_22px_55px_rgba(148,163,184,0.16)] backdrop-blur-xl transition-all duration-300 hover:-translate-y-0.5",
        toneShadow[tone],
        className,
      )}
    >
      <div className="mb-2 flex items-center justify-between gap-3 text-xs font-semibold uppercase tracking-[0.16em] text-slate-400">
        <span>{title}</span>
        {icon ? <span className="rounded-2xl border border-slate-100 bg-slate-50 p-2 shadow-sm">{icon}</span> : null}
      </div>
      <div className="text-2xl font-semibold tracking-tight text-slate-950">{value}</div>
    </div>
  );
}

export function AnalysisPanel({
  title,
  children,
  tone = "slate",
  className,
  actions,
}: {
  title: ReactNode;
  children: ReactNode;
  tone?: AnalysisTone;
  className?: string;
  actions?: ReactNode;
}) {
  return (
    <div
      className={cn(
        "overflow-hidden rounded-[24px] border border-white/80 bg-white/88 p-5 shadow-[0_22px_55px_rgba(148,163,184,0.16)] backdrop-blur-xl transition-all duration-300",
        tonePanelShadow[tone],
        className,
      )}
    >
      <div className="mb-4 flex items-center justify-between gap-3 border-b border-slate-100 pb-3">
        <div className="text-sm font-semibold tracking-tight text-slate-900">{title}</div>
        {actions ? <div className="shrink-0">{actions}</div> : null}
      </div>
      {children}
    </div>
  );
}

export function AnalysisMiniStat({
  title,
  value,
  tone = "slate",
  className,
}: {
  title: string;
  value: ReactNode;
  tone?: AnalysisTone;
  className?: string;
}) {
  return (
    <div className={cn("rounded-2xl border border-slate-100 bg-slate-50/75 px-3 py-2 shadow-sm", className)}>
      <div className="text-[11px] font-medium text-slate-400">{title}</div>
      <div className={cn("text-sm font-semibold", toneMiniText[tone])}>{value}</div>
    </div>
  );
}

export function AnalysisBadge({
  children,
  tone = "slate",
  className,
}: {
  children: ReactNode;
  tone?: AnalysisTone;
  className?: string;
}) {
  return (
    <span className={cn("inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold", toneBadge[tone], className)}>
      {children}
    </span>
  );
}

export function AnalysisEmptyState({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn("rounded-2xl border border-dashed border-slate-200 bg-slate-50/70 px-3 py-8 text-center text-xs leading-6 text-slate-500", className)}>
      {children}
    </div>
  );
}

export function AnalysisCallout({
  children,
  icon,
  tone = "slate",
  className,
}: {
  children: ReactNode;
  icon?: ReactNode;
  tone?: AnalysisTone;
  className?: string;
}) {
  return (
    <div className={cn("flex items-start gap-2 rounded-2xl border px-3 py-2 text-xs shadow-sm", toneCallout[tone], className)}>
      {icon ? <span className="mt-0.5 shrink-0">{icon}</span> : null}
      <span>{children}</span>
    </div>
  );
}

export function AnalysisBucketChart({
  data,
  barClassName,
  emptyText = "暂无数据",
  maxHeightClassName = "max-h-[420px]",
  labelWidthClassName = "grid-cols-[220px_1fr_72px]",
  onSelect,
}: {
  data: AnalysisBucket[];
  barClassName: string;
  emptyText?: ReactNode;
  maxHeightClassName?: string;
  labelWidthClassName?: string;
  onSelect?: (row: AnalysisBucket) => void;
}) {
  const max = Math.max(1, ...data.map((item) => item.count));
  if (data.length === 0) {
    return <AnalysisEmptyState>{emptyText}</AnalysisEmptyState>;
  }
  return (
    <div className={cn("overflow-auto pr-1", maxHeightClassName)}>
      <div className="space-y-2">
        {data.map((row) => {
          const rowContent = (
            <>
              <div className="truncate font-medium text-slate-500" title={row.label}>{row.label}</div>
              <div className="h-2 rounded-full bg-slate-100">
                <div className={cn("h-2 rounded-full", barClassName)} style={{ width: `${Math.max(2, (row.count / max) * 100)}%` }} />
              </div>
              <div className="text-right font-mono font-semibold text-slate-700">{row.count.toLocaleString()}</div>
            </>
          );
          if (onSelect) {
            return (
              <button
                key={row.label}
                type="button"
                className={cn("grid w-full items-center gap-3 rounded-2xl px-2 py-2 text-left text-xs transition-colors hover:bg-slate-50/80", labelWidthClassName)}
                onClick={() => onSelect(row)}
              >
                {rowContent}
              </button>
            );
          }
          return (
            <div key={row.label} className={cn("grid items-center gap-3 rounded-2xl px-2 py-2 text-xs", labelWidthClassName)}>
              {rowContent}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function AnalysisList({
  items,
  emptyText = "暂无数据",
  maxHeightClassName = "max-h-[420px]",
}: {
  items: AnalysisBucket[];
  emptyText?: ReactNode;
  maxHeightClassName?: string;
}) {
  if (items.length === 0) {
    return <AnalysisEmptyState>{emptyText}</AnalysisEmptyState>;
  }
  return (
    <div className={cn("space-y-2 overflow-auto pr-1", maxHeightClassName)}>
      {items.map((item) => (
        <div key={`${item.label}-${item.count}`} className="flex items-center justify-between rounded-2xl border border-slate-100 bg-slate-50/70 px-3 py-2 text-xs shadow-sm">
          <span className="truncate font-medium text-slate-500" title={item.label}>{item.label}</span>
          <span className="ml-3 font-mono font-semibold text-slate-700">{item.count.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}

export type AnalysisTableColumn<T> = {
  key: string;
  header: ReactNode;
  render: (row: T, rowIndex: number) => ReactNode;
  className?: string;
  headerClassName?: string;
  cellClassName?: string | ((row: T, rowIndex: number) => string);
  widthClassName?: string;
};

export function AnalysisDataTable<T = ReactNode[]>({
  headers,
  rows,
  columns,
  data,
  rowKey,
  rowClassName,
  onRowClick,
  renderExpandedRow,
  expandedRowClassName,
  expandedCellClassName,
  maxHeightClassName = "max-h-[420px]",
  emptyText = "暂无数据",
  wrapperClassName,
  tableClassName,
  headerClassName,
  headerCellClassName,
  cellClassName,
}: {
  headers?: ReactNode[];
  rows?: ReactNode[][];
  columns?: AnalysisTableColumn<T>[];
  data?: T[];
  rowKey?: (row: T, rowIndex: number) => string | number;
  rowClassName?: string | ((row: T, rowIndex: number) => string);
  onRowClick?: (row: T, rowIndex: number) => void;
  renderExpandedRow?: (row: T, rowIndex: number) => ReactNode;
  expandedRowClassName?: string | ((row: T, rowIndex: number) => string);
  expandedCellClassName?: string | ((row: T, rowIndex: number) => string);
  maxHeightClassName?: string;
  emptyText?: ReactNode;
  wrapperClassName?: string;
  tableClassName?: string;
  headerClassName?: string;
  headerCellClassName?: string;
  cellClassName?: string;
}) {
  const effectiveHeaders = columns ? columns.map((column) => column.header) : (headers ?? []);
  const hasStructuredRows = Boolean(columns && data);

  return (
    <div className={cn("overflow-auto rounded-2xl border border-slate-100 bg-white/70", maxHeightClassName, wrapperClassName)}>
      <table className={cn("w-full table-fixed border-collapse text-left text-xs", tableClassName)}>
        <thead className={cn("sticky top-0 bg-slate-50/95 text-slate-500 shadow-[0_1px_0_0_rgba(226,232,240,0.9)]", headerClassName)}>
          <tr>
            {effectiveHeaders.map((header, index) => (
              <th
                key={columns?.[index]?.key ?? `${String(header)}-${index}`}
                className={cn("px-3 py-2 font-medium", columns?.[index]?.widthClassName, columns?.[index]?.headerClassName, headerCellClassName)}
              >
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {hasStructuredRows ? (
            (data ?? []).length === 0 ? (
              <tr>
                <td colSpan={effectiveHeaders.length} className="px-3 py-6 text-center text-slate-500">{emptyText}</td>
              </tr>
            ) : (
              (data ?? []).map((row, rowIndex) => {
                const resolvedRowClassName = typeof rowClassName === "function" ? rowClassName(row, rowIndex) : rowClassName;
                const resolvedExpandedRowClassName = typeof expandedRowClassName === "function" ? expandedRowClassName(row, rowIndex) : expandedRowClassName;
                const resolvedExpandedCellClassName = typeof expandedCellClassName === "function" ? expandedCellClassName(row, rowIndex) : expandedCellClassName;
                const resolvedRowKey = rowKey ? rowKey(row, rowIndex) : rowIndex;
                const expandedContent = renderExpandedRow?.(row, rowIndex);
                const hasExpandedContent = expandedContent !== undefined && expandedContent !== null && expandedContent !== false;
                return (
                  <Fragment key={resolvedRowKey}>
                    <tr
                      className={cn(
                        "border-b border-slate-100 align-top transition-colors hover:bg-slate-50/70",
                        onRowClick && "cursor-pointer",
                        resolvedRowClassName,
                      )}
                      onClick={() => onRowClick?.(row, rowIndex)}
                    >
                      {(columns ?? []).map((column) => {
                        const resolvedCellClassName = typeof column.cellClassName === "function" ? column.cellClassName(row, rowIndex) : column.cellClassName;
                        return (
                          <td key={column.key} className={cn("break-words px-3 py-2", column.className, resolvedCellClassName, cellClassName)}>
                            {column.render(row, rowIndex)}
                          </td>
                        );
                      })}
                    </tr>
                    {hasExpandedContent && (
                      <tr key={`${resolvedRowKey}-expanded`} className={cn("border-b border-slate-100 bg-slate-50/50", resolvedExpandedRowClassName)}>
                        <td colSpan={effectiveHeaders.length} className={cn("px-3 pb-4 pt-0", resolvedExpandedCellClassName)}>
                          {expandedContent}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })
            )
          ) : (rows ?? []).length === 0 ? (
            <tr>
              <td colSpan={effectiveHeaders.length} className="px-3 py-6 text-center text-slate-500">{emptyText}</td>
            </tr>
          ) : (
            (rows ?? []).map((row, rowIndex) => (
              <tr key={rowIndex} className="border-b border-slate-100 align-top transition-colors hover:bg-slate-50/70">
                {row.map((value, cellIndex) => (
                  <td key={`${rowIndex}-${cellIndex}`} className={cn("break-words px-3 py-2", cellClassName)}>{value}</td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
