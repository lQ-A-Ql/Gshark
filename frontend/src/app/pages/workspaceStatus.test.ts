import { describe, expect, it } from "vitest";

import { getWorkspaceFilterPanelState } from "./workspaceStatus";

describe("workspaceStatus", () => {
  it("builds filter panel title, detail, and error message", () => {
    expect(getWorkspaceFilterPanelState("正在应用过滤器 tcp", "tcp")).toMatchObject({
      loadingTitle: "正在应用过滤器 tcp",
      loadingDetail: "旧页已清空，首屏命中结果返回前会在这里显示实时进度。",
      errorMessage: "正在应用过滤器 tcp",
    });
    expect(getWorkspaceFilterPanelState("invalid display filter", "bad(").errorMessage).toBe("invalid display filter");
  });
});
