import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { StreamChunkCard, StreamCurrentChunkPanel, StreamPayloadDialog } from "./StreamWorkbench";

describe("stream payload panels", () => {
  it("highlights selected content and renders chips", () => {
    render(
      <StreamCurrentChunkPanel
        title="当前片段"
        chips={["client", "42B"]}
        content="hello hacked_by_fallsnow"
        highlight="hacked_by"
        showOpenButton
        onOpen={vi.fn()}
      />,
    );

    expect(screen.getByText("client")).toBeInTheDocument();
    expect(screen.getByText("42B")).toBeInTheDocument();
    expect(screen.getByText("hacked_by")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "查看完整 payload" })).toBeInTheDocument();
  });

  it("separates card selection from open action", () => {
    const onSelect = vi.fn();
    const onOpen = vi.fn();

    render(
      <StreamChunkCard
        directionLabel="C -> S"
        packetId={12}
        rendered="payload body"
        selected={false}
        tone="border-slate-200"
        onSelect={onSelect}
        onOpen={onOpen}
        truncated
      />,
    );

    fireEvent.click(screen.getByText("payload body"));
    fireEvent.click(screen.getByRole("button", { name: "查看完整 payload" }));

    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it("filters empty metadata in payload dialog", () => {
    render(
      <StreamPayloadDialog
        title="Payload"
        content="secret token"
        meta={[
          { label: "packet", value: 10 },
          { label: "empty", value: "" },
        ]}
        onClose={vi.fn()}
      />,
    );

    expect(screen.getByText("Payload")).toBeInTheDocument();
    expect(screen.getByText("packet")).toBeInTheDocument();
    expect(screen.queryByText("empty")).not.toBeInTheDocument();
    expect(screen.getByText("secret token")).toBeInTheDocument();
  });
});
