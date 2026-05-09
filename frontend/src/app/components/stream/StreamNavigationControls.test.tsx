import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { StreamNavigator, StreamSearchBar, ViewModeToggle } from "./StreamWorkbench";

describe("stream navigation controls", () => {
  it("normalizes stream input and submits on Enter", () => {
    const onStreamInputChange = vi.fn();
    const onSubmitStream = vi.fn();

    render(
      <StreamNavigator
        protocolLabel="TCP"
        ordinalLabel="2 / 4"
        streamId={7}
        streamTotal={4}
        streamInput="7"
        onStreamInputChange={onStreamInputChange}
        onSubmitStream={onSubmitStream}
        onPrev={vi.fn()}
        onNext={vi.fn()}
        hasPrev
        hasNext
      />,
    );

    const input = screen.getByPlaceholderText("stream");
    fireEvent.change(input, { target: { value: "abc42x" } });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(screen.getByText("第 2 / 4 条 / stream eq 7")).toBeInTheDocument();
    expect(onStreamInputChange).toHaveBeenCalledWith("42");
    expect(onSubmitStream).toHaveBeenCalledTimes(1);
  });

  it("renders active search summary and disables navigation when no results", () => {
    const { rerender } = render(
      <StreamSearchBar
        value="flag"
        onChange={vi.fn()}
        onPrev={vi.fn()}
        onNext={vi.fn()}
        matchCount={3}
        resultCount={5}
        currentIndex={1}
      />,
    );

    expect(screen.getByText("第 2 / 5 片段 · 3 匹配")).toBeInTheDocument();

    rerender(
      <StreamSearchBar
        value="flag"
        onChange={vi.fn()}
        onPrev={vi.fn()}
        onNext={vi.fn()}
        matchCount={0}
        resultCount={0}
      />,
    );

    expect(screen.getByText("0 片段 · 0 匹配")).toBeInTheDocument();
    expect(screen.getAllByRole("button")).toEqual(
      expect.arrayContaining([expect.objectContaining({ disabled: true })]),
    );
  });

  it("switches view mode", () => {
    const onChange = vi.fn();

    render(
      <ViewModeToggle
        value="ascii"
        options={[
          { value: "ascii", label: "ASCII" },
          { value: "hex", label: "Hex" },
        ]}
        onChange={onChange}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Hex" }));

    expect(onChange).toHaveBeenCalledWith("hex");
  });
});
