import { describe, expect, it, vi } from "vitest";

import { createAnalysisResourceCache } from "./analysisResourceCache";

describe("createAnalysisResourceCache", () => {
  it("deduplicates inflight requests for the same key", async () => {
    const cache = createAnalysisResourceCache<number>();
    const load = vi.fn(async () => 7);
    const signal = new AbortController().signal;

    const first = cache.request("capture::c2", { signal, load });
    const second = cache.request("capture::c2", { signal, load });

    await expect(Promise.all([first, second])).resolves.toEqual([7, 7]);
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("serves cached values unless force refresh is requested", async () => {
    const cache = createAnalysisResourceCache<number>();
    const signal = new AbortController().signal;
    const load = vi.fn().mockResolvedValueOnce(1).mockResolvedValueOnce(2);

    await expect(cache.request("capture::traffic", { signal, load })).resolves.toBe(1);
    await expect(cache.request("capture::traffic", { signal, load })).resolves.toBe(1);
    await expect(cache.request("capture::traffic", { signal, force: true, load })).resolves.toBe(2);

    expect(load).toHaveBeenCalledTimes(2);
  });

  it("evicts least recently used entries when capacity is set", async () => {
    const cache = createAnalysisResourceCache<string>({ capacity: 2 });
    const signal = new AbortController().signal;

    cache.set("a", "A");
    cache.set("b", "B");
    expect(cache.get("a")).toBe("A");
    cache.set("c", "C");

    expect(cache.get("a")).toBe("A");
    expect(cache.get("b")).toBeUndefined();
    expect(cache.get("c")).toBe("C");
    await expect(cache.request("b", { signal, load: async () => "B2" })).resolves.toBe("B2");
  });
});
