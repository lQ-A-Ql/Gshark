import { useCallback, useEffect, useState, type Dispatch, type SetStateAction } from "react";
import type { BinaryStream } from "../core/types";
import type { RawStreamViewState } from "./RawStreamViewState";
import type { RawStreamProtocol } from "./useRawStreamRouteSelection";

export type FetchRawStreamPage = (
  protocol: RawStreamProtocol,
  streamId: number,
  cursor: number,
  limit: number,
) => Promise<BinaryStream>;

interface UseRawStreamPageLoaderOptions {
  fetchRawStreamPage: FetchRawStreamPage;
  pageSize: number;
  protocol: RawStreamProtocol;
  setStreamView: Dispatch<SetStateAction<RawStreamViewState>>;
  streamView: RawStreamViewState;
}

export function useRawStreamPageLoader({
  fetchRawStreamPage,
  pageSize,
  protocol,
  setStreamView,
  streamView,
}: UseRawStreamPageLoaderOptions) {
  const [loadError, setLoadError] = useState("");
  const [loadingMore, setLoadingMore] = useState(false);

  useEffect(() => {
    setLoadError("");
    setLoadingMore(false);
  }, [streamView.id]);

  const loadMore = useCallback(async () => {
    if (loadingMore || !streamView.hasMore) return;
    setLoadingMore(true);
    setLoadError("");
    try {
      const page = await fetchRawStreamPage(
        protocol,
        streamView.id,
        streamView.nextCursor ?? streamView.chunks.length,
        pageSize,
      );
      setStreamView((prev) => mergeRawStreamPage(prev, page));
    } catch (error) {
      setLoadError(error instanceof Error && error.message ? error.message : "加载更多流片段失败");
    } finally {
      setLoadingMore(false);
    }
  }, [
    fetchRawStreamPage,
    loadingMore,
    pageSize,
    protocol,
    setStreamView,
    streamView.chunks.length,
    streamView.hasMore,
    streamView.id,
    streamView.nextCursor,
  ]);

  return { loadError, loadingMore, loadMore };
}

function mergeRawStreamPage(prev: RawStreamViewState, page: BinaryStream): RawStreamViewState {
  if (prev.id !== page.id) return prev;
  return {
    ...prev,
    from: page.from,
    to: page.to,
    chunks: [...prev.chunks, ...page.chunks],
    loadMeta: page.loadMeta ?? prev.loadMeta,
    nextCursor: page.nextCursor ?? prev.chunks.length + page.chunks.length,
    totalChunks: page.totalChunks ?? prev.totalChunks,
    hasMore: page.hasMore ?? false,
  };
}
