import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { StreamDecoderBatchPanel } from "./StreamDecoderBatchPanel";

describe("StreamDecoderBatchPanel", () => {
  it("renders clamped batch range and start item", () => {
    render(
      <StreamDecoderBatchPanel
        batchItems={[
          { index: 10, label: "frame 10", payload: "a" },
          { index: 11, label: "frame 11", payload: "b" },
        ]}
        batchCount={2}
        selectedBatchOrdinal={1}
        rangeStart="9"
        rangeEnd="2"
        batchProgress={null}
        batchFailureDetails={[]}
        onRangeStartChange={vi.fn()}
        onRangeEndChange={vi.fn()}
      />,
    );

    expect(screen.getByText("当前片段位于第 1 / 2 条")).toBeInTheDocument();
    expect(screen.getByText("将按当前列表顺序处理第 2 到 2 条。")).toBeInTheDocument();
    expect(screen.getByText("起点: frame 11")).toBeInTheDocument();
  });

  it("renders progress and failure details", () => {
    render(
      <StreamDecoderBatchPanel
        batchItems={[]}
        batchCount={3}
        selectedBatchOrdinal={2}
        rangeStart="1"
        rangeEnd="3"
        batchProgress={{ total: 3, done: 2, success: 1, failed: 1, currentLabel: "frame 2" }}
        batchFailureDetails={["[2] frame 2: 解码失败"]}
        onRangeStartChange={vi.fn()}
        onRangeEndChange={vi.fn()}
      />,
    );

    expect(screen.getByText("进度：2/3")).toBeInTheDocument();
    expect(screen.getByText("成功：1 · 失败：1")).toBeInTheDocument();
    expect(screen.getByText("当前：frame 2")).toBeInTheDocument();
    expect(screen.getByText("[2] frame 2: 解码失败")).toBeInTheDocument();
  });
});
