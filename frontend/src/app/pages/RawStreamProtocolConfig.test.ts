import { describe, expect, it } from "vitest";

import { getRawStreamProtocolConfig } from "./RawStreamProtocolConfig";

describe("getRawStreamProtocolConfig", () => {
  it("enables incremental scroll loading for TCP only", () => {
    expect(getRawStreamProtocolConfig("TCP")).toMatchObject({
      enableScrollLoad: true,
      loadingText: "继续下滚可加载更多",
    });
    expect(getRawStreamProtocolConfig("UDP")).toMatchObject({
      enableScrollLoad: false,
      loadingText: "",
    });
  });
});
