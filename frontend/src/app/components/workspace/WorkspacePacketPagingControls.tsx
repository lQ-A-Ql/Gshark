import { RefreshCw } from "lucide-react";

type PacketPagingControlsProps = {
  hasPrevPackets: boolean;
  hasMorePackets: boolean;
  isPreloadingCapture: boolean;
  isPageLoading: boolean;
  totalPackets: number;
  currentPage: number;
  totalPages: number;
  pageInput: string;
  pagerItems: number[];
  onPageInputChange: (value: string) => void;
  onLoadPrev: () => void;
  onLoadMore: () => void;
  onJumpToPage: (page: number) => void;
};

export function PacketPagingControls({
  hasPrevPackets,
  hasMorePackets,
  isPreloadingCapture,
  isPageLoading,
  totalPackets,
  currentPage,
  totalPages,
  pageInput,
  pagerItems,
  onPageInputChange,
  onLoadPrev,
  onLoadMore,
  onJumpToPage,
}: PacketPagingControlsProps) {
  const pagingDisabled = isPreloadingCapture || isPageLoading;
  const jumpPage = () => onJumpToPage(Number(pageInput || currentPage));

  return (
    <div className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-200 bg-slate-50/80 px-2 py-1">
      <button
        onClick={onLoadPrev}
        disabled={!hasPrevPackets || pagingDisabled}
        className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1 text-xs text-foreground shadow-sm transition-all hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
      >
        <RefreshCw className="h-3 w-3" /> {isPageLoading ? "翻页中" : "上一页"}
      </button>
      <button
        onClick={onLoadMore}
        disabled={!hasMorePackets || pagingDisabled}
        className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1 text-xs text-foreground shadow-sm transition-all hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
      >
        <RefreshCw className="h-3 w-3" />{" "}
        {isPreloadingCapture ? `预加载中 ${totalPackets.toLocaleString()}` : isPageLoading ? "翻页中" : hasMorePackets ? "下一页" : "已到末页"}
      </button>
      <div className="flex items-center gap-1 rounded-md border border-border bg-background px-2 py-1 text-xs">
        <input
          value={pageInput}
          onChange={(event) => onPageInputChange(event.target.value.replace(/[^0-9]/g, ""))}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              jumpPage();
            }
          }}
          className="w-14 border-none bg-transparent text-center font-mono text-foreground outline-none"
          placeholder="页"
          disabled={pagingDisabled}
        />
        <span className="text-muted-foreground">/ {totalPages.toLocaleString()}</span>
        <button
          onClick={jumpPage}
          disabled={pagingDisabled}
          className="rounded border border-border px-1.5 py-0.5 text-[11px] hover:bg-accent disabled:opacity-50"
        >
          跳转
        </button>
      </div>
      <div className="flex items-center gap-1 rounded-md border border-border bg-background px-1 py-1 text-xs">
        <button
          onClick={() => onJumpToPage(1)}
          disabled={pagingDisabled || currentPage <= 1}
          className="rounded border border-border px-1.5 py-0.5 hover:bg-accent disabled:opacity-50"
        >
          «
        </button>
        {pagerItems.map((page) => (
          <button
            key={page}
            onClick={() => onJumpToPage(page)}
            disabled={pagingDisabled}
            className={`rounded border px-1.5 py-0.5 font-mono ${page === currentPage ? "border-blue-600 bg-blue-600 text-white" : "border-border hover:bg-accent"}`}
          >
            {page}
          </button>
        ))}
        <button
          onClick={() => onJumpToPage(totalPages)}
          disabled={pagingDisabled || currentPage >= totalPages}
          className="rounded border border-border px-1.5 py-0.5 hover:bg-accent disabled:opacity-50"
        >
          »
        </button>
      </div>
    </div>
  );
}
