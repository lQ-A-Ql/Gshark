import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { MediaAnalysis, SpeechBatchTaskStatus } from "../../core/types";
import { MediaBatchActions, MediaNotesPanel, MediaOverviewStats } from "./MediaOverviewPanels";

const idleBatchStatus: SpeechBatchTaskStatus = {
  taskId: "",
  total: 0,
  queued: 0,
  running: 0,
  completed: 0,
  failed: 0,
  skipped: 0,
  done: false,
  cancelled: false,
  items: [],
};

function createAnalysis(): MediaAnalysis {
  return {
    totalMediaPackets: 42,
    protocols: [{ label: "RTP", count: 3 }],
    applications: [],
    sessions: [
      {
        id: "media-1",
        mediaType: "audio",
        family: "rtp",
        application: "RTP",
        source: "10.0.0.1",
        sourcePort: 4000,
        destination: "10.0.0.2",
        destinationPort: 5000,
        transport: "udp",
        packetCount: 12,
        gapCount: 0,
        tags: [],
        notes: [],
        artifact: {
          token: "audio-token",
          name: "audio.wav",
          sizeBytes: 128,
        },
      },
    ],
    notes: [],
  };
}

describe("MediaOverviewPanels", () => {
  it("renders overview stats from media analysis", () => {
    render(<MediaOverviewStats analysis={createAnalysis()} />);

    expect(screen.getByText("相关流量包")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("已导出媒体流")).toBeInTheDocument();
    expect(screen.getAllByText("1")).toHaveLength(3);
  });

  it("hides batch actions until audio artifacts exist", () => {
    render(
      <MediaBatchActions
        hasAudioArtifacts={false}
        batchStarting={false}
        batchStatus={idleBatchStatus}
        onStartBatchTranscription={vi.fn()}
        onCancelBatchTranscription={vi.fn()}
      />,
    );

    expect(screen.queryByText("批量转写音频")).not.toBeInTheDocument();
  });

  it("wires batch action callbacks", () => {
    const onStart = vi.fn();
    const onCancel = vi.fn();

    render(
      <MediaBatchActions
        hasAudioArtifacts
        batchStarting={false}
        batchStatus={{ ...idleBatchStatus, taskId: "task-1", done: false }}
        onStartBatchTranscription={onStart}
        onCancelBatchTranscription={onCancel}
      />,
    );

    fireEvent.click(screen.getByText("取消"));

    expect(screen.getByText("批量转写音频")).toBeDisabled();
    expect(onStart).not.toHaveBeenCalled();
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("renders notes or the empty state", () => {
    const { rerender } = render(<MediaNotesPanel notes={[]} />);
    expect(screen.getByText("当前抓包未识别到媒体流。")).toBeInTheDocument();

    rerender(<MediaNotesPanel notes={["识别到 RTP 音频流"]} />);
    expect(screen.getByText("识别到 RTP 音频流")).toBeInTheDocument();
  });
});
