import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { MediaSession, MediaTranscription, SpeechBatchTaskStatus } from "../../core/types";
import { ExportActionsCell, MediaTypeBadge, TranscriptionCell } from "./MediaSessionCells";

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

function createSession(overrides: Partial<MediaSession> = {}): MediaSession {
  return {
    id: "session-1",
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
      token: "token-1",
      name: "audio.raw",
      format: "opus",
      sizeBytes: 128,
    },
    ...overrides,
  };
}

function createTranscription(overrides: Partial<MediaTranscription> = {}): MediaTranscription {
  return {
    token: "token-1",
    sessionId: "session-1",
    title: "audio",
    text: "hello sentinel",
    language: "zh",
    engine: "vosk",
    status: "completed",
    cached: true,
    durationSeconds: 1,
    segments: [],
    ...overrides,
  };
}

describe("MediaSessionCells", () => {
  it("renders media type badges", () => {
    const { rerender } = render(<MediaTypeBadge session={createSession()} />);
    expect(screen.getByText("音频")).toBeInTheDocument();

    rerender(<MediaTypeBadge session={createSession({ mediaType: "video" })} />);
    expect(screen.getByText("视频")).toBeInTheDocument();
  });

  it("renders cached transcription text and copies it", () => {
    const onCopyText = vi.fn();

    render(
      <TranscriptionCell
        session={createSession()}
        batchStatus={idleBatchStatus}
        transcriptions={{ "token-1": createTranscription() }}
        transcriptionLoadingToken=""
        transcriptionStartedAt={null}
        batchTokenStartedAt={null}
        progressClock={0}
        onCopyText={onCopyText}
      />,
    );

    expect(screen.getByText("已完成")).toBeInTheDocument();
    expect(screen.getByText("缓存")).toBeInTheDocument();
    expect(screen.getByText("hello sentinel")).toBeInTheDocument();

    fireEvent.click(screen.getByText("复制"));

    expect(onCopyText).toHaveBeenCalledWith("hello sentinel");
  });

  it("wires artifact actions and running states", () => {
    const onDownloadArtifact = vi.fn();
    const onOpenPlayback = vi.fn();
    const onRunTranscription = vi.fn();

    render(
      <ExportActionsCell
        session={createSession()}
        batchStatus={{ ...idleBatchStatus, taskId: "task-1", currentToken: "token-1" }}
        transcriptionLoadingToken=""
        playbackLoadingToken="token-1"
        onDownloadArtifact={onDownloadArtifact}
        onOpenPlayback={onOpenPlayback}
        onRunTranscription={onRunTranscription}
      />,
    );

    fireEvent.click(screen.getByText("下载音频流"));
    fireEvent.click(screen.getByText("转写"));

    expect(screen.getByText("(128 B)")).toBeInTheDocument();
    expect(screen.getByText("播放")).toBeDisabled();
    expect(screen.getByText("转写")).toBeDisabled();
    expect(onDownloadArtifact).toHaveBeenCalledWith(expect.objectContaining({ id: "session-1" }));
    expect(onOpenPlayback).not.toHaveBeenCalled();
    expect(onRunTranscription).not.toHaveBeenCalled();
  });
});
