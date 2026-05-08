import { describe, expect, it } from "vitest";
import {
  CAPTURE_PRELOAD_TIMEOUT_MS,
  getCaptureEmptyParseError,
  getCaptureOpenDisconnectedStatus,
  getCaptureOpenErrorMessage,
  getCapturePreloadDoneStatus,
  getCapturePreloadTimeoutError,
  getCapturePreloadWorkingStatus,
} from "./capturePreloadStatus";

describe("capturePreloadStatus helpers", () => {
  it("keeps the preload timeout constant explicit", () => {
    expect(CAPTURE_PRELOAD_TIMEOUT_MS).toBe(120000);
  });

  it("builds capture preload status messages", () => {
    expect(getCaptureOpenDisconnectedStatus()).toBe("桌面后端未连接，无法打开文件");
    expect(getCapturePreloadWorkingStatus("sample.pcapng")).toBe("正在预加载全部数据: sample.pcapng");
    expect(getCapturePreloadDoneStatus("sample.pcapng")).toBe("预加载完成，可浏览全部流量: sample.pcapng");
  });

  it("builds capture preload failure messages", () => {
    expect(getCaptureEmptyParseError("tshark failed")).toBe("tshark failed");
    expect(getCaptureEmptyParseError("")).toBe(
      "capture parsing finished without any packets; please verify tshark compatibility",
    );
    expect(getCapturePreloadTimeoutError()).toBe("capture parsing timed out before preloading finished");
  });

  it("preserves capture open error normalization", () => {
    expect(getCaptureOpenErrorMessage(new Error("open failed"))).toBe("open failed");
    expect(getCaptureOpenErrorMessage(new Error(""))).toBe("");
    expect(getCaptureOpenErrorMessage("failed")).toBe("打开文件失败");
  });
});
