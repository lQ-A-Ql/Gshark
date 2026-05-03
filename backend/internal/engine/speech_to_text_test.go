package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestStartMediaBatchTranscriptionSkipsCachedAudioArtifacts(t *testing.T) {
	oldStatus := speechToTextStatusFn
	oldTranscribe := transcribeAudioArtifactFn
	t.Cleanup(func() {
		speechToTextStatusFn = oldStatus
		transcribeAudioArtifactFn = oldTranscribe
	})

	speechToTextStatusFn = func() model.SpeechToTextStatus {
		return model.SpeechToTextStatus{
			Available:       true,
			FFmpegAvailable: true,
			PythonAvailable: true,
			VoskAvailable:   true,
			ModelAvailable:  true,
			Engine:          speechEngineName,
			Language:        speechLanguageCode,
			Message:         "ok",
		}
	}
	transcribeAudioArtifactFn = func(context.Context, model.SpeechToTextStatus, string) (rawTranscriptionPayload, error) {
		t.Fatal("cached batch item should not invoke transcription")
		return rawTranscriptionPayload{}, nil
	}

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()

	svc.mediaAnalysis = &model.MediaAnalysis{
		Sessions: []model.MediaSession{
			{
				ID:          "audio-1",
				MediaType:   "audio",
				Application: "RTP",
				Source:      "10.0.0.1", SourcePort: 4000,
				Destination: "10.0.0.2", DestinationPort: 5000,
				Artifact: &model.MediaArtifact{Token: "tok-audio", Name: "audio.ulaw", Format: "ulaw"},
			},
			{
				ID:        "video-1",
				MediaType: "video",
				Artifact:  &model.MediaArtifact{Token: "tok-video", Name: "video.h264", Format: "h264"},
			},
		},
	}
	svc.mediaSpeech["tok-audio"] = model.MediaTranscription{
		Token: "tok-audio", SessionID: "audio-1", Title: "cached", Text: "cached text", Status: "completed", Cached: false,
	}

	status, err := svc.StartMediaBatchTranscription(false)
	if err != nil {
		t.Fatalf("StartMediaBatchTranscription() error = %v", err)
	}
	if status.Total != 1 {
		t.Fatalf("expected only audio session to be queued, got %+v", status)
	}
	if len(status.Items) != 1 || status.Items[0].Status != "skipped" || status.Items[0].Text != "cached text" {
		t.Fatalf("expected cached audio item to be skipped with text, got %+v", status.Items)
	}
}

func TestStartMediaBatchTranscriptionRunsSequentially(t *testing.T) {
	oldStatus := speechToTextStatusFn
	oldTranscribe := transcribeAudioArtifactFn
	t.Cleanup(func() {
		speechToTextStatusFn = oldStatus
		transcribeAudioArtifactFn = oldTranscribe
	})

	speechToTextStatusFn = func() model.SpeechToTextStatus {
		return model.SpeechToTextStatus{
			Available:       true,
			FFmpegAvailable: true,
			PythonAvailable: true,
			VoskAvailable:   true,
			ModelAvailable:  true,
			Engine:          speechEngineName,
			Language:        speechLanguageCode,
			Message:         "ok",
		}
	}

	callOrder := make([]string, 0, 2)
	transcribeAudioArtifactFn = func(ctx context.Context, _ model.SpeechToTextStatus, path string) (rawTranscriptionPayload, error) {
		callOrder = append(callOrder, filepath.Base(path))
		return rawTranscriptionPayload{Text: "hello", DurationSeconds: 1.2}, ctx.Err()
	}

	audioFile1 := filepath.Join(t.TempDir(), "first.ulaw")
	audioFile2 := filepath.Join(t.TempDir(), "second.ulaw")
	_ = os.WriteFile(audioFile1, []byte("a"), 0o644)
	_ = os.WriteFile(audioFile2, []byte("b"), 0o644)

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	svc.mediaAnalysis = &model.MediaAnalysis{
		Sessions: []model.MediaSession{
			{
				ID: "audio-1", MediaType: "audio", Application: "RTP",
				Source: "10.0.0.1", SourcePort: 4000, Destination: "10.0.0.2", DestinationPort: 5000,
				Artifact: &model.MediaArtifact{Token: "tok-1", Name: filepath.Base(audioFile1), Format: "ulaw"},
			},
			{
				ID: "audio-2", MediaType: "audio", Application: "RTP",
				Source: "10.0.0.3", SourcePort: 4001, Destination: "10.0.0.4", DestinationPort: 5001,
				Artifact: &model.MediaArtifact{Token: "tok-2", Name: filepath.Base(audioFile2), Format: "ulaw"},
			},
		},
	}
	svc.mediaArtifacts["tok-1"] = audioFile1
	svc.mediaArtifacts["tok-2"] = audioFile2

	if _, err := svc.StartMediaBatchTranscription(true); err != nil {
		t.Fatalf("StartMediaBatchTranscription() error = %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := svc.MediaBatchTranscriptionStatus()
		if status.Done {
			if status.Completed != 2 {
				t.Fatalf("expected both items to complete, got %+v", status)
			}
			if len(callOrder) != 2 || callOrder[0] != filepath.Base(audioFile1) || callOrder[1] != filepath.Base(audioFile2) {
				t.Fatalf("expected sequential transcription order, got %v", callOrder)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for batch transcription to complete")
}

func TestPrepareCaptureReplacementCancelsSpeechBatchTask(t *testing.T) {
	oldStatus := speechToTextStatusFn
	oldTranscribe := transcribeAudioArtifactFn
	t.Cleanup(func() {
		speechToTextStatusFn = oldStatus
		transcribeAudioArtifactFn = oldTranscribe
	})

	speechToTextStatusFn = func() model.SpeechToTextStatus {
		return model.SpeechToTextStatus{
			Available:       true,
			FFmpegAvailable: true,
			PythonAvailable: true,
			VoskAvailable:   true,
			ModelAvailable:  true,
			Engine:          speechEngineName,
			Language:        speechLanguageCode,
			Message:         "ok",
		}
	}

	started := make(chan struct{})
	var calls atomic.Int32
	transcribeAudioArtifactFn = func(ctx context.Context, _ model.SpeechToTextStatus, _ string) (rawTranscriptionPayload, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-ctx.Done()
		return rawTranscriptionPayload{}, ctx.Err()
	}

	audioDir := t.TempDir()
	audioFile1 := filepath.Join(audioDir, "first.ulaw")
	audioFile2 := filepath.Join(audioDir, "second.ulaw")
	_ = os.WriteFile(audioFile1, []byte("a"), 0o644)
	_ = os.WriteFile(audioFile2, []byte("b"), 0o644)

	svc := NewService(NopEmitter{}, nil)
	defer svc.packetStore.Close()
	svc.mediaAnalysis = &model.MediaAnalysis{
		Sessions: []model.MediaSession{
			{
				ID: "audio-1", MediaType: "audio", Application: "RTP",
				Source: "10.0.0.1", SourcePort: 4000, Destination: "10.0.0.2", DestinationPort: 5000,
				Artifact: &model.MediaArtifact{Token: "tok-1", Name: filepath.Base(audioFile1), Format: "ulaw"},
			},
			{
				ID: "audio-2", MediaType: "audio", Application: "RTP",
				Source: "10.0.0.3", SourcePort: 4001, Destination: "10.0.0.4", DestinationPort: 5001,
				Artifact: &model.MediaArtifact{Token: "tok-2", Name: filepath.Base(audioFile2), Format: "ulaw"},
			},
		},
	}
	svc.mediaArtifacts["tok-1"] = audioFile1
	svc.mediaArtifacts["tok-2"] = audioFile2

	if _, err := svc.StartMediaBatchTranscription(true); err != nil {
		t.Fatalf("StartMediaBatchTranscription() error = %v", err)
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for speech batch item to start")
	}
	if got := svc.ActiveCaptureTaskCount(); got == 0 {
		t.Fatal("expected speech batch to be registered as capture task")
	}

	svc.PrepareCaptureReplacement()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := svc.MediaBatchTranscriptionStatus()
		if status.Done {
			if !status.Cancelled {
				t.Fatalf("expected speech batch to be marked cancelled, got %+v", status)
			}
			if calls.Load() != 1 {
				t.Fatalf("expected replacement to stop before second item, got %d transcription calls", calls.Load())
			}
			if got := svc.ActiveCaptureTaskCount(); got != 0 {
				t.Fatalf("expected capture tasks to be cleared, got %d", got)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for speech batch cancellation")
}

func TestBuildSpeechModuleHintMissingVosk(t *testing.T) {
	message := buildSpeechModuleHint(
		[]string{`C:\Python311\python.exe`},
		errors.New(`Traceback (most recent call last): ModuleNotFoundError: No module named 'vosk'`),
	)
	if !strings.Contains(message, "没有安装 vosk 模块") {
		t.Fatalf("expected missing module hint, got %q", message)
	}
	if !strings.Contains(message, `C:\Python311\python.exe -m pip install vosk`) {
		t.Fatalf("expected install command in hint, got %q", message)
	}
}

func TestBuildSpeechModuleHintFallback(t *testing.T) {
	message := buildSpeechModuleHint([]string{"python"}, errors.New("permission denied"))
	if !strings.Contains(message, "无法导入 vosk 模块") {
		t.Fatalf("expected generic import hint, got %q", message)
	}
	if !strings.Contains(message, "permission denied") {
		t.Fatalf("expected raw error detail in hint, got %q", message)
	}
}

func TestBuildSpeechFFmpegArgsAddsVoiceEnhancement(t *testing.T) {
	args := buildSpeechFFmpegArgs("input.ulaw", "output.wav", transcriptionAudioProfile{
		inputFormat: "mulaw",
		inputArgs:   []string{"-ar", "8000", "-ac", "1"},
	})

	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-af "+speechEnhancementFilter) {
		t.Fatalf("expected speech enhancement filter in args, got %q", joined)
	}
	if !strings.Contains(joined, "-ac 1") || !strings.Contains(joined, "-ar 16000") {
		t.Fatalf("expected mono 16k output in args, got %q", joined)
	}
}
