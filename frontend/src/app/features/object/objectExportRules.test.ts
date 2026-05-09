import { describe, expect, it } from "vitest";
import type { ExtractedObject } from "../../core/types";
import { classifyObject, filterObjects, groupObjectsByMagic, magicGroupLabel } from "./objectExportRules";

function object(overrides: Partial<ExtractedObject>): ExtractedObject {
  return {
    id: 1,
    packetId: 10,
    name: "sample.bin",
    sizeBytes: 42,
    mime: "",
    magic: "",
    source: "HTTP",
    ...overrides,
  };
}

describe("object export rules", () => {
  it("classifies objects by magic bytes before mime type", () => {
    expect(classifyObject(object({ magic: "PNG image data", mime: "application/octet-stream" })).kind).toBe("image");
    expect(classifyObject(object({ magic: "PE32 executable", mime: "text/plain" })).kind).toBe("executable");
    expect(classifyObject(object({ magic: "", mime: "application/pdf" })).kind).toBe("document");
  });

  it("filters by type and filename query", () => {
    const rows = [
      object({ id: 1, name: "report.pdf", magic: "PDF document" }),
      object({ id: 2, name: "payload.exe", magic: "PE32 executable" }),
      object({ id: 3, name: "notes.txt", mime: "text/plain" }),
    ];

    expect(filterObjects(rows, "PAYLOAD", "all").map((item) => item.id)).toEqual([2]);
    expect(filterObjects(rows, "", "document").map((item) => item.id)).toEqual([1]);
    expect(filterObjects(rows, "txt", "text").map((item) => item.id)).toEqual([3]);
  });

  it("groups by magic label and sorts larger groups first", () => {
    const rows = [
      object({ id: 1, name: "b.png", magic: "PNG image data" }),
      object({ id: 2, name: "a.png", magic: "PNG image data" }),
      object({ id: 3, name: "doc.pdf", magic: "PDF document" }),
    ];

    expect(magicGroupLabel(rows[0])).toBe("PNG 图片");
    expect(groupObjectsByMagic(rows)).toMatchObject([
      { label: "PNG 图片", items: [{ name: "a.png" }, { name: "b.png" }] },
      { label: "PDF", items: [{ name: "doc.pdf" }] },
    ]);
  });
});
