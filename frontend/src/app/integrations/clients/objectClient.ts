import type { ExtractedObject } from "../../core/types";
import { downloadBlob } from "../../utils/browserFile";
import { asObjectList } from "../mappers/objectMapper";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;
type BlobRequest = (path: string, init?: RequestInit) => Promise<Blob>;

export interface ObjectClient {
  listObjects(signal?: AbortSignal): Promise<ExtractedObject[]>;
  downloadObjectsZip(ids: number[]): Promise<void>;
}

export function createObjectClient(request: JsonRequest, requestBlob: BlobRequest): ObjectClient {
  return {
    async listObjects(signal?: AbortSignal) {
      const rows = await request<any[]>("/api/objects", { signal });
      return asObjectList(rows);
    },

    async downloadObjectsZip(ids: number[]) {
      const blob = await requestBlob("/api/objects/download", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ids }),
      });
      downloadBlob("exported_objects.zip", blob);
    },
  };
}
