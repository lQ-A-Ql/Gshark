import { describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  downloadBlob: vi.fn(),
}));

vi.mock("../../utils/browserFile", () => ({
  downloadBlob: mocks.downloadBlob,
}));

import { createObjectClient } from "./objectClient";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;
type BlobRequest = (path: string, init?: RequestInit) => Promise<Blob>;

describe("objectClient", () => {
  it("maps extracted objects from transport payloads", async () => {
    const request = vi.fn(async (path: string) => {
      expect(path).toBe("/api/objects");
      return [
        {
          id: 3,
          packet_id: 42,
          name: "invoice.txt",
          size_bytes: 128,
          mime: "text/plain",
          magic: "ASCII text",
          source: "FTP",
        },
      ];
    }) as unknown as JsonRequest;
    const requestBlob = vi.fn() as unknown as BlobRequest;

    const client = createObjectClient(request, requestBlob);
    const objects = await client.listObjects();

    expect(objects).toEqual([
      {
        id: 3,
        packetId: 42,
        name: "invoice.txt",
        sizeBytes: 128,
        mime: "text/plain",
        magic: "ASCII text",
        source: "FTP",
      },
    ]);
  });

  it("posts ids and downloads the returned blob as a zip", async () => {
    const request = vi.fn() as unknown as JsonRequest;
    const blob = new Blob(["zip"]);
    const requestBlob = vi.fn(async (path: string, init?: RequestInit) => {
      expect(path).toBe("/api/objects/download");
      expect(init?.method).toBe("POST");
      expect(init?.headers).toEqual({ "Content-Type": "application/json" });
      expect(init?.body).toBe(JSON.stringify({ ids: [1, 2, 3] }));
      return blob;
    }) as unknown as BlobRequest;

    const client = createObjectClient(request, requestBlob);
    await client.downloadObjectsZip([1, 2, 3]);

    expect(mocks.downloadBlob).toHaveBeenCalledWith("exported_objects.zip", blob);
  });
});
