import { Clapperboard } from "lucide-react";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import {
  BatchTranscriptionStatusPanel,
  MediaAnalysisProgressPanel,
  MediaDependencyDialogs,
  MediaPlaybackDialog,
} from "../features/media/MediaDisplayPanels";
import {
  MediaBatchActions,
  MediaDistributionPanels,
  MediaLoadingNotice,
  MediaNotesPanel,
  MediaOverviewStats,
} from "../features/media/MediaOverviewPanels";
import { MediaSessionTable } from "../features/media/MediaSessionTable";
import { MediaTranscriptionSummaryPanel } from "../features/media/MediaTranscriptionSummaryPanel";
import { useMediaAnalysis } from "../features/media/useMediaAnalysis";
import { useMediaTranscriptionWorkflow } from "../features/media/useMediaTranscriptionWorkflow";
import { useSentinel } from "../state/SentinelContext";

const MEDIA_PROTOCOL_TAGS = ["RTP", "RTSP", "Moonlight", "GameStream"];

export default function MediaAnalysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets, mediaAnalysisProgress, captureRevision } =
    useSentinel();
  const {
    analysis,
    loading,
    error: analysisError,
    refreshAnalysis,
    batchStatus,
    setBatchStatus,
    transcriptions,
    setTranscriptions,
  } = useMediaAnalysis({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
  });
  const workflow = useMediaTranscriptionWorkflow({
    backendConnected,
    isPreloadingCapture,
    captureRevision,
    sessions: analysis.sessions,
    batchStatus,
    setBatchStatus,
    setTranscriptions,
  });
  const error = analysisError || workflow.error;

  return (
    <PageShell className="bg-[radial-gradient(circle_at_top,rgba(251,113,133,0.26),transparent_36%),linear-gradient(180deg,#fff7f8_0%,#fbfbff_44%,#f8fafc_100%)]">
      <AnalysisHero
        icon={<Clapperboard className="h-5 w-5" />}
        title="媒体流还原"
        subtitle="MEDIA STREAM RECONSTRUCTION"
        description="统一串起媒体流识别、播放、导出与语音转写，让 RTP、RTSP、Moonlight 和音频流分析保持同一套工作台结构。"
        tags={MEDIA_PROTOCOL_TAGS}
        tagsLabel="协议族"
        theme="rose"
        onRefresh={() => refreshAnalysis(true)}
      />

      <MediaBatchActions
        hasAudioArtifacts={workflow.hasAudioArtifacts}
        batchStarting={workflow.batchStarting}
        batchStatus={batchStatus}
        onStartBatchTranscription={(force) => void workflow.startBatchTranscription(force)}
        onCancelBatchTranscription={() => void workflow.cancelBatchTranscription()}
      />

      <MediaLoadingNotice loading={loading} />

      <MediaAnalysisProgressPanel progress={mediaAnalysisProgress} />

      {!loading && error && (
        <div className="mb-3 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-700">{error}</div>
      )}

      <BatchTranscriptionStatusPanel batchStatus={batchStatus} />

      <MediaOverviewStats analysis={analysis} />
      <MediaDistributionPanels analysis={analysis} />
      <MediaNotesPanel notes={analysis.notes} />

      <MediaSessionTable
        sessions={analysis.sessions}
        batchStatus={batchStatus}
        transcriptions={transcriptions}
        transcriptionLoadingToken={workflow.transcriptionLoadingToken}
        transcriptionStartedAt={workflow.transcriptionStartedAt}
        batchTokenStartedAt={workflow.batchTokenStartedAt}
        progressClock={workflow.progressClock}
        playbackLoadingToken={workflow.playbackLoadingToken}
        onCopyText={workflow.copyText}
        onDownloadArtifact={workflow.downloadArtifact}
        onOpenPlayback={workflow.openPlayback}
        onRunTranscription={workflow.runTranscription}
      />

      <MediaTranscriptionSummaryPanel
        batchStatus={batchStatus}
        transcriptions={transcriptions}
        onCopyText={workflow.copyText}
        onExportBatchTranscription={workflow.exportBatchTranscription}
      />

      <MediaPlaybackDialog
        playbackSession={workflow.playbackSession}
        playbackUrl={workflow.playbackUrl}
        onClose={workflow.closePlayback}
      />

      <MediaDependencyDialogs
        ffmpegDialogMessage={workflow.ffmpegDialogMessage}
        speechDialogMessage={workflow.speechDialogMessage}
        onFfmpegDialogMessageChange={workflow.setFfmpegDialogMessage}
        onSpeechDialogMessageChange={workflow.setSpeechDialogMessage}
      />
    </PageShell>
  );
}
