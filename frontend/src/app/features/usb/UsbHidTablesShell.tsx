import { type ReactNode, useEffect, useMemo, useState } from "react";

const HID_TABLE_INITIAL_ROWS = 1000;
const HID_TABLE_ROW_INCREMENT = 1000;

export function HIDTableShell<T>({
  children,
  visibleState,
}: {
  children: ReactNode;
  visibleState: ReturnType<typeof useVisibleRows<T>>;
}) {
  return (
    <div className="space-y-2">
      {children}
      {visibleState.totalRows > HID_TABLE_INITIAL_ROWS ? (
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
          <span>
            已显示 {visibleState.visibleRows.length.toLocaleString()} / {visibleState.totalRows.toLocaleString()} 行
          </span>
          {visibleState.canShowMore ? (
            <button
              type="button"
              onClick={visibleState.showMore}
              className="border border-border bg-slate-50/70 px-3 py-1.5 font-medium text-slate-600 transition-colors hover:bg-accent hover:text-foreground"
            >
              显示更多
            </button>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

export function useVisibleRows<T>(rows: T[], resetKey: string) {
  const [visibleCount, setVisibleCount] = useState(HID_TABLE_INITIAL_ROWS);

  useEffect(() => {
    setVisibleCount(HID_TABLE_INITIAL_ROWS);
  }, [resetKey, rows]);

  const clampedVisibleCount = Math.min(visibleCount, rows.length);
  const visibleRows = useMemo(() => rows.slice(0, clampedVisibleCount), [clampedVisibleCount, rows]);

  return {
    canShowMore: visibleRows.length < rows.length,
    showMore: () => setVisibleCount((current) => Math.min(current + HID_TABLE_ROW_INCREMENT, rows.length)),
    totalRows: rows.length,
    visibleRows,
  };
}
