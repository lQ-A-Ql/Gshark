import type { StreamLoadMeta } from "../core/types";
import type { RawChunk } from "./RawStreamUtils";
import type { RawStreamProtocol } from "./useRawStreamRouteSelection";

export interface RawStreamViewState {
  id: number;
  protocol: RawStreamProtocol;
  from: string;
  to: string;
  chunks: RawChunk[];
  loadMeta?: StreamLoadMeta;
  nextCursor: number;
  totalChunks: number;
  hasMore: boolean;
}

export function createEmptyRawStreamView(protocol: RawStreamProtocol): RawStreamViewState {
  return {
    id: -1,
    protocol,
    from: "",
    to: "",
    chunks: [],
    loadMeta: undefined,
    nextCursor: 0,
    totalChunks: 0,
    hasMore: false,
  };
}
