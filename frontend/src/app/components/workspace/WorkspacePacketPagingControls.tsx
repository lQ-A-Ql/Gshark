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
  return (
    <div className="gshark-tile-toolbar flex flex-wrap items-center gap-2 px-2 py-1">
      <button
        onClick={onLoadPrev}
        disabled={!hasPrevPackets || pagingDisabled}
        className="gshark-control flex items-center gap-1 px-3 py-1 text-xs text-foreground transition-all disabled:cursor-not-allowed disabled:opacity-50"
      >
        <RefreshCw className="h-3 w-3" /> {isPageLoading ? "翻页中" : "上一页"}
      </button>
      <button
        onClick={onLoadMore}
        disabled={!hasMorePackets || pagingDisabled}
        className="gshark-control flex items-center gap-1 px-3 py-1 text-xs text-foreground transition-all disabled:cursor-not-allowed disabled:opacity-50"
      >
        <RefreshCw className="h-3 w-3" />
        {isPreloadingCapture
          ? `预加载中 ${totalPackets.toLocaleString()}`
          : isPageLoading
            ? "翻页中"
            : hasMorePackets
              ? "下一页"
              : "已到末页"}
      </button>
      <div className="gshark-field flex items-center gap-1 px-2 py-1 text-xs">
        <input
          value={pageInput}
          onChange={(event) => onPageInputChange(event.target.value.replace(/[^0-9]/g, ""))}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              onJumpToPage(Number(pageInput || currentPage));
            }
          }}
          className="w-14 border-none bg-transparent text-center font-mono text-foreground outline-none"
          placeholder="页"
          disabled={pagingDisabled}
        />
        <span className="text-muted-foreground">/ {totalPages.toLocaleString()}</span>
        <button
          onClick={() => onJumpToPage(Number(pageInput || currentPage))}
          disabled={pagingDisabled}
          className="gshark-control-ghost px-1.5 py-0.5 text-[11px] disabled:opacity-50"
        >
          跳转
        </button>
      </div>
      <div className="gshark-field flex items-center gap-1 px-1 py-1 text-xs">
        <button
          onClick={() => onJumpToPage(1)}
          disabled={pagingDisabled || currentPage <= 1}
          className="gshark-control-ghost px-1.5 py-0.5 disabled:opacity-50"
        >
          «
        </button>
        {pagerItems.map((page) => (
          <button
            key={page}
            onClick={() => onJumpToPage(page)}
            disabled={pagingDisabled}
            className={`gshark-control px-1.5 py-0.5 font-mono ${page === currentPage ? "border-blue-300/30 bg-blue-500/64 text-white" : ""}`}
          >
            {page}
          </button>
        ))}
        <button
          onClick={() => onJumpToPage(totalPages)}
          disabled={pagingDisabled || currentPage >= totalPages}
          className="gshark-control-ghost px-1.5 py-0.5 disabled:opacity-50"
        >
          »
        </button>
      </div>
    </div>
  );
}
