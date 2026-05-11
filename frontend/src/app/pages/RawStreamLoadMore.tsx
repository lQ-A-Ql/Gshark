interface RawStreamLoadMoreProps {
  hasMore: boolean;
  loadedChunkCount: number;
  loadingMore: boolean;
  loadingText: string;
  totalChunks: number;
  onLoadMore: () => void;
}

export function RawStreamLoadMore({
  hasMore,
  loadedChunkCount,
  loadingMore,
  loadingText,
  totalChunks,
  onLoadMore,
}: RawStreamLoadMoreProps) {
  if (!loadingMore && !hasMore) return null;

  if (loadingText) {
    return (
      <div className="flex justify-center pt-2 text-xs text-muted-foreground">
        {loadingMore ? "正在加载更多流片段..." : loadingText}
      </div>
    );
  }

  return (
    <button
      className="mt-2 self-start rounded border border-border bg-background px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-60"
      onClick={onLoadMore}
      disabled={loadingMore}
    >
      {loadingMore ? "正在加载..." : `加载更多 (${loadedChunkCount}/${totalChunks || loadedChunkCount})`}
    </button>
  );
}
