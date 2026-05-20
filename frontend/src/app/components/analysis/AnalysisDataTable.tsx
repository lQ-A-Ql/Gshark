import { Fragment, type ReactNode } from "react";
import { cn } from "../ui/utils";

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
    <div className={cn("gshark-tile-table", maxHeightClassName, wrapperClassName)}>
      <table className={cn("w-full table-fixed border-collapse text-left text-xs", tableClassName)}>
        <thead
          className={cn("sticky top-0 bg-[var(--gshark-table-header-bg)] text-[11px] text-slate-500", headerClassName)}
        >
          <tr>
            {effectiveHeaders.map((header, index) => (
              <th
                key={columns?.[index]?.key ?? `${String(header)}-${index}`}
                className={cn(
                  "px-2.5 py-2 font-semibold",
                  columns?.[index]?.widthClassName,
                  columns?.[index]?.headerClassName,
                  headerCellClassName,
                )}
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
                <td colSpan={effectiveHeaders.length} className="px-3 py-5 text-center text-slate-500">
                  {emptyText}
                </td>
              </tr>
            ) : (
              (data ?? []).map((row, rowIndex) => {
                const resolvedRowClassName =
                  typeof rowClassName === "function" ? rowClassName(row, rowIndex) : rowClassName;
                const resolvedExpandedRowClassName =
                  typeof expandedRowClassName === "function"
                    ? expandedRowClassName(row, rowIndex)
                    : expandedRowClassName;
                const resolvedExpandedCellClassName =
                  typeof expandedCellClassName === "function"
                    ? expandedCellClassName(row, rowIndex)
                    : expandedCellClassName;
                const resolvedRowKey = rowKey ? rowKey(row, rowIndex) : rowIndex;
                const expandedContent = renderExpandedRow?.(row, rowIndex);
                const hasExpandedContent =
                  expandedContent !== undefined && expandedContent !== null && expandedContent !== false;
                return (
                  <Fragment key={resolvedRowKey}>
                    <tr
                      className={cn(
                        "border-b border-[var(--gshark-tile-divider)] align-top transition-colors hover:bg-slate-500/5",
                        onRowClick && "cursor-pointer",
                        resolvedRowClassName,
                      )}
                      onClick={() => onRowClick?.(row, rowIndex)}
                    >
                      {(columns ?? []).map((column) => {
                        const resolvedCellClassName =
                          typeof column.cellClassName === "function"
                            ? column.cellClassName(row, rowIndex)
                            : column.cellClassName;
                        return (
                          <td
                            key={column.key}
                            className={cn(
                              "break-words px-2.5 py-1.5",
                              column.className,
                              resolvedCellClassName,
                              cellClassName,
                            )}
                          >
                            {column.render(row, rowIndex)}
                          </td>
                        );
                      })}
                    </tr>
                    {hasExpandedContent && (
                      <tr
                        key={`${resolvedRowKey}-expanded`}
                        className={cn(
                          "border-b border-[var(--gshark-tile-divider)] bg-slate-500/5",
                          resolvedExpandedRowClassName,
                        )}
                      >
                        <td
                          colSpan={effectiveHeaders.length}
                          className={cn("px-2.5 pb-3 pt-0", resolvedExpandedCellClassName)}
                        >
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
              <td colSpan={effectiveHeaders.length} className="px-3 py-5 text-center text-slate-500">
                {emptyText}
              </td>
            </tr>
          ) : (
            (rows ?? []).map((row, rowIndex) => (
              <tr
                key={rowIndex}
                className="border-b border-[var(--gshark-tile-divider)] align-top transition-colors hover:bg-slate-500/5"
              >
                {row.map((value, cellIndex) => (
                  <td key={`${rowIndex}-${cellIndex}`} className={cn("break-words px-2.5 py-1.5", cellClassName)}>
                    {value}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
