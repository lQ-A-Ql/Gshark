import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { useUpdateCenter } from "./useUpdateCenter";

describe("useUpdateCenter", () => {
  it("loads update status and exposes release notes", async () => {
    const runtimeClient = {
      checkAppUpdate: vi.fn().mockResolvedValue({
        currentVersion: "1.0.0",
        latestTag: "1.0.1",
        hasUpdate: true,
        releaseNotes: "security fixes",
      }),
      installAppUpdate: vi.fn(),
    };

    const { result } = renderHook(() => useUpdateCenter(runtimeClient));

    await waitFor(() => expect(result.current.loading).toBe(false));

    expect(runtimeClient.checkAppUpdate).toHaveBeenCalledTimes(1);
    expect(result.current.status?.latestTag).toBe("1.0.1");
    expect(result.current.notes).toBe("security fixes");
  });

  it("sets install progress to complete after successful install", async () => {
    const runtimeClient = {
      checkAppUpdate: vi.fn().mockResolvedValue({ currentVersion: "1.0.0", releaseNotes: "" }),
      installAppUpdate: vi.fn().mockResolvedValue(undefined),
    };

    const { result } = renderHook(() => useUpdateCenter(runtimeClient));
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      await result.current.installUpdate();
    });

    expect(runtimeClient.installAppUpdate).toHaveBeenCalledTimes(1);
    expect(result.current.installing).toBe(true);
    expect(result.current.installProgress).toBe(100);
    expect(result.current.notes).toBe("该版本没有附带 Release 说明。");
  });

  it("refreshes status and surfaces an error when install fails", async () => {
    const runtimeClient = {
      checkAppUpdate: vi.fn().mockResolvedValue({ currentVersion: "1.0.0", releaseNotes: "" }),
      installAppUpdate: vi.fn().mockRejectedValue(new Error("install denied")),
    };

    const { result } = renderHook(() => useUpdateCenter(runtimeClient));
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      await result.current.installUpdate();
    });

    expect(runtimeClient.installAppUpdate).toHaveBeenCalledTimes(1);
    expect(runtimeClient.checkAppUpdate).toHaveBeenCalledTimes(2);
    expect(result.current.installing).toBe(false);
    expect(result.current.installProgress).toBe(0);
    expect(result.current.error).toBe("");
  });
});
