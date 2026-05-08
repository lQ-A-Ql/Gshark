import { describe, expect, it } from "vitest";
import {
  getCaptureCloseErrorMessage,
  getCaptureStopDoneStatus,
  getCaptureStopRequestStatus,
} from "./captureStopStatus";

describe("captureStopStatus helpers", () => {
  it("builds stop request status based on backend connectivity", () => {
    expect(getCaptureStopRequestStatus(true)).toBe("当前抓包已从界面移除，正在请求后端清理线程");
    expect(getCaptureStopRequestStatus(false)).toBe("当前抓包已从界面移除；后端未连接");
  });

  it("normalizes close errors", () => {
    expect(getCaptureCloseErrorMessage(new Error("backend busy"))).toBe("backend busy");
    expect(getCaptureCloseErrorMessage(new Error(""))).toBe("关闭抓包失败");
    expect(getCaptureCloseErrorMessage("failed")).toBe("关闭抓包失败");
  });

  it("builds stop completion status", () => {
    expect(getCaptureStopDoneStatus("")).toBe("当前抓包已关闭，临时数据库已清理");
    expect(getCaptureStopDoneStatus("backend busy")).toBe("当前抓包已从界面移除；后端清理返回: backend busy");
  });
});
