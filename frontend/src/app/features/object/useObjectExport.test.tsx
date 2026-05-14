import { renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { ExtractedObject } from "../../core/types";
import { useObjectExport } from "./useObjectExport";

const extractedObject: ExtractedObject = {
  id: 1,
  packetId: 10,
  name: "payload.exe",
  sizeBytes: 128,
  mime: "application/octet-stream",
  magic: "PE32 executable",
  source: "HTTP",
};
const extractedObjects = [extractedObject];
const emptyObjects: ExtractedObject[] = [];

function createClient() {
  return {
    listObjects: vi.fn().mockResolvedValue(extractedObjects),
    downloadObjectsZip: vi.fn().mockResolvedValue(undefined),
  };
}

describe("useObjectExport", () => {
  it("uses sentinel extracted objects without fallback loading", () => {
    const objectClient = createClient();
    const { result } = renderHook(() =>
      useObjectExport({ backendConnected: true, extractedObjects, objectClient }),
    );

    expect(result.current.objects).toEqual(extractedObjects);
    expect(objectClient.listObjects).not.toHaveBeenCalled();
  });

  it("loads fallback objects when the current capture has no extracted object cache", async () => {
    const objectClient = createClient();
    const { result } = renderHook(() =>
      useObjectExport({ backendConnected: true, extractedObjects: emptyObjects, objectClient }),
    );

    await waitFor(() => expect(result.current.objects).toEqual(extractedObjects));

    expect(objectClient.listObjects).toHaveBeenCalledTimes(1);
  });

  it("downloads selected ids and ignores empty selections", async () => {
    const objectClient = createClient();
    const { result } = renderHook(() =>
      useObjectExport({ backendConnected: true, extractedObjects, objectClient }),
    );

    await expect(result.current.downloadZip([])).resolves.toBe(false);
    await expect(result.current.downloadZip([1, 2])).resolves.toBe(true);

    expect(objectClient.downloadObjectsZip).toHaveBeenCalledTimes(1);
    expect(objectClient.downloadObjectsZip).toHaveBeenCalledWith([1, 2]);
  });
});
