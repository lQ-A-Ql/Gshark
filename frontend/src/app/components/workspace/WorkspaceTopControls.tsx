import { FolderOpen, RefreshCw, Square } from "lucide-react";

type CaptureFileControlsProps = {
  capturePath: string;
  onCapturePathChange: (value: string) => void;
  onChooseFile: () => void;
  onOpenPath: () => void;
  onStop: () => void;
  disabled: boolean;
  backendConnected: boolean;
};

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

type PacketLocatorControlsProps = {
  packetIdInput: string;
  onPacketIdInputChange: (value: string) => void;
  onLocatePacket: (packetId: number) => void;
  disabled: boolean;
};

export function CaptureFileControls({
  capturePath,
  onCapturePathChange,
  onChooseFile,
  onOpenPath,
  onStop,
  disabled,
  backendConnected,
}: CaptureFileControlsProps) {
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-2 rounded-lg border border-slate-200 bg-slate-50/80 px-2 py-1">
      <div className="flex w-[320px] min-w-[220px] items-center overflow-hidden rounded-md border border-border bg-background shadow-sm focus-within:border-blue-500">
        <FolderOpen className="ml-2 h-4 w-4 text-muted-foreground" />
        <input
          value={capturePath}
          onChange={(event) => onCapturePathChange(event.target.value)}
          name="capture-path-input"
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="none"
          spellCheck={false}
          className="w-full border-none bg-transparent px-2 py-1 text-xs font-mono text-foreground outline-none placeholder:text-muted-foreground"
          placeholder="输入 PCAP/PCAPNG 绝对路径"
        />
      </div>
      <button
        onClick={onChooseFile}
        disabled={disabled}
        className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1 text-xs text-foreground shadow-sm transition-all hover:bg-accent disabled:cursor-not-allowed disabled:opacity-60"
        title={backendConnected ? "选择并打开 PCAP/PCAPNG 文件" : "后端未连接"}
      >
        <FolderOpen className="h-3.5 w-3.5 text-blue-600" /> 选择文件
      </button>
      <button
        onClick={onOpenPath}
        disabled={disabled}
        className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1 text-xs text-foreground shadow-sm transition-all hover:bg-accent disabled:cursor-not-allowed disabled:opacity-60"
        title={backendConnected ? "按路径打开（适用于本机路径）" : "后端未连接"}
      >
        <FolderOpen className="h-3.5 w-3.5 text-indigo-600" /> 路径打开
      </button>
      <button
        onClick={onStop}
        disabled={!backendConnected}
        className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1 text-xs text-foreground shadow-sm transition-all hover:bg-accent disabled:cursor-not-allowed disabled:opacity-60"
        title={backendConnected ? "关闭当前抓包并清理临时数据库" : "后端未连接"}
      >
        <Square className="h-3.5 w-3.5 text-rose-600" /> 关闭抓包
      </button>
    </div>
  );
}

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
        <RefreshCw className="h-3 w-3" /> {isPreloadingCapture ? `预加载中 ${totalPackets.toLocaleString()}` : isPageLoading ? "翻页中" : hasMorePackets ? "下一页" : "已到末页"}
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

export function PacketLocatorControls({
  packetIdInput,
  onPacketIdInputChange,
  onLocatePacket,
  disabled,
}: PacketLocatorControlsProps) {
  const locate = () => {
    const packetId = Number(packetIdInput);
    if (packetId > 0) {
      onLocatePacket(packetId);
    }
  };

  return (
    <div className="flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50/80 px-2 py-1 text-xs">
      <input
        value={packetIdInput}
        onChange={(event) => onPacketIdInputChange(event.target.value.replace(/[^0-9]/g, ""))}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            locate();
          }
        }}
        className="w-20 border-none bg-transparent text-center font-mono text-foreground outline-none"
        placeholder="分组号"
        disabled={disabled}
      />
      <button
        onClick={locate}
        disabled={disabled}
        className="rounded border border-border bg-background px-1.5 py-0.5 text-[11px] hover:bg-accent disabled:opacity-50"
      >
        定位
      </button>
    </div>
  );
}
