package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestCancelMediaBatchTranscriptionMarksTaskAndInvokesCancel(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()

	cancelCalled := atomic.Bool{}
	svc.mediaCtl.speechCancel = func() { cancelCalled.Store(true) }
	svc.mediaCtl.speechBatch = &model.SpeechBatchTaskStatus{
		TaskID:       "speech-batch-test",
		CurrentToken: "tok-running",
		CurrentLabel: "running item",
		Items: []model.SpeechBatchTaskItem{
			{Token: "tok-queued", Status: "queued"},
			{Token: "tok-running", Status: "running"},
			{Token: "tok-done", Status: "completed", Text: "done"},
			{Token: "tok-failed", Status: "failed", Error: "boom"},
			{Token: "tok-skipped", Status: "skipped", Cached: true},
		},
	}

	status := svc.CancelMediaBatchTranscription()
	if !cancelCalled.Load() {
		t.Fatal("expected stored speech cancel function to be invoked")
	}
	if !status.Done || !status.Cancelled || status.CurrentToken != "" {
		t.Fatalf("batch not marked canceled/done: %+v", status)
	}
	if status.Total != 5 || status.Queued != 1 || status.Running != 1 || status.Completed != 1 || status.Failed != 1 || status.Skipped != 1 {
		t.Fatalf("batch counts not recomputed: %+v", status)
	}

	status.Items[0].Status = "mutated"
	if svc.mediaCtl.speechBatch.Items[0].Status == "mutated" {
		t.Fatal("CancelMediaBatchTranscription should return a cloned task snapshot")
	}
}

func TestCancelAndExportMediaBatchTranscriptionWithoutTask(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()

	status := svc.CancelMediaBatchTranscription()
	if status.TaskID != "" || len(status.Items) != 0 || status.Done || status.Cancelled {
		t.Fatalf("empty cancel status = %+v, want zero value", status)
	}

	export := svc.ExportMediaBatchTranscription()
	if export.Engine != speechEngineName || export.Language != speechLanguageCode || len(export.Items) != 0 {
		t.Fatalf("empty export = %+v", export)
	}
}

func TestExportMediaBatchTranscriptionFiltersBlankText(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()

	svc.mediaCtl.speechBatch = &model.SpeechBatchTaskStatus{
		TaskID: "speech-batch-export",
		Items: []model.SpeechBatchTaskItem{
			{Token: "tok-1", SessionID: "s1", Title: "first", Status: "completed", Text: "hello", Cached: true},
			{Token: "tok-blank", SessionID: "s2", Title: "blank", Status: "completed", Text: " \t "},
			{Token: "tok-2", SessionID: "s3", Title: "second", Status: "failed", Text: "partial"},
		},
	}

	export := svc.ExportMediaBatchTranscription()
	if export.TaskID != "speech-batch-export" || export.Engine != speechEngineName || export.Language != speechLanguageCode {
		t.Fatalf("unexpected export header: %+v", export)
	}
	if len(export.Items) != 2 {
		t.Fatalf("expected two non-empty transcript items, got %+v", export.Items)
	}
	if export.Items[0].Token != "tok-1" || !export.Items[0].Cached || export.Items[1].Token != "tok-2" {
		t.Fatalf("unexpected export items: %+v", export.Items)
	}
}

func TestTranscribeMediaArtifactWithContextCachesAndHonorsForce(t *testing.T) {
	oldStatus := speechToTextStatusFn
	oldTranscribe := transcribeAudioArtifactFn
	t.Cleanup(func() {
		speechToTextStatusFn = oldStatus
		transcribeAudioArtifactFn = oldTranscribe
	})
	fakeFFmpeg := writeFakeExecutableFile(t, "ffmpeg")
	t.Setenv(ffmpegEnvVar, fakeFFmpeg)

	speechToTextStatusFn = func() model.SpeechToTextStatus {
		return model.SpeechToTextStatus{
			Available:       true,
			Engine:          speechEngineName,
			Language:        speechLanguageCode,
			PythonAvailable: true,
			FFmpegAvailable: true,
			VoskAvailable:   true,
			ModelAvailable:  true,
			ModelPath:       t.TempDir(),
			Message:         "ok",
		}
	}

	var calls atomic.Int32
	transcribeAudioArtifactFn = func(ctx context.Context, _ model.SpeechToTextStatus, inputPath string) (rawTranscriptionPayload, error) {
		if err := ctx.Err(); err != nil {
			return rawTranscriptionPayload{}, err
		}
		calls.Add(1)
		if filepath.Base(inputPath) != "audio.ulaw" {
			t.Fatalf("unexpected transcription input path: %s", inputPath)
		}
		return rawTranscriptionPayload{
			Text:            " transcript ",
			DurationSeconds: 2.5,
			Segments: []model.MediaTranscriptionSegment{
				{StartSeconds: 0, EndSeconds: 1.2, Text: "transcript"},
			},
		}, nil
	}

	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()
	audioPath := filepath.Join(t.TempDir(), "audio.ulaw")
	if err := os.WriteFile(audioPath, []byte("audio"), 0o644); err != nil {
		t.Fatal(err)
	}
	svc.mediaCtl.mediaArtifacts["tok-audio"] = audioPath
	svc.analysisCtl.mediaAnalysis = &model.MediaAnalysis{Sessions: []model.MediaSession{{
		ID: "audio-1", MediaType: "audio", Application: "RTP", Codec: "PCMU",
		Source: "10.1.1.1", SourcePort: 4000, Destination: "10.1.1.2", DestinationPort: 5000,
		Artifact: &model.MediaArtifact{Token: "tok-audio", Name: "friendly.ulaw"},
	}}}

	first, err := svc.TranscribeMediaArtifactWithContext(context.Background(), " tok-audio ", false)
	if err != nil {
		t.Fatalf("TranscribeMediaArtifactWithContext() error = %v", err)
	}
	if first.Text != "transcript" || first.Status != "completed" || first.Cached || first.Language != speechLanguageCode || first.Engine != speechEngineName {
		t.Fatalf("unexpected first transcription: %+v", first)
	}
	if first.SessionID != "audio-1" || !strings.Contains(first.Title, "PCMU") || len(first.Segments) != 1 {
		t.Fatalf("transcription metadata missing: %+v", first)
	}

	cached, err := svc.TranscribeMediaArtifactWithContext(context.Background(), "tok-audio", false)
	if err != nil {
		t.Fatalf("cached TranscribeMediaArtifactWithContext() error = %v", err)
	}
	if !cached.Cached || cached.Status != "completed" || calls.Load() != 1 {
		t.Fatalf("expected cached result without extra call, got %+v calls=%d", cached, calls.Load())
	}

	forced, err := svc.TranscribeMediaArtifactWithContext(context.Background(), "tok-audio", true)
	if err != nil {
		t.Fatalf("forced TranscribeMediaArtifactWithContext() error = %v", err)
	}
	if forced.Cached || calls.Load() != 2 {
		t.Fatalf("expected force=true to transcribe again, got %+v calls=%d", forced, calls.Load())
	}
}

func TestTranscribeMediaArtifactWithContextRejectsBadInputs(t *testing.T) {
	oldStatus := speechToTextStatusFn
	t.Cleanup(func() { speechToTextStatusFn = oldStatus })
	fakeFFmpeg := writeFakeExecutableFile(t, "ffmpeg")
	t.Setenv(ffmpegEnvVar, fakeFFmpeg)
	speechToTextStatusFn = func() model.SpeechToTextStatus {
		return model.SpeechToTextStatus{
			Available:       true,
			PythonAvailable: true,
			FFmpegAvailable: true,
			VoskAvailable:   true,
			ModelAvailable:  true,
			Message:         "ok",
		}
	}

	svc := NewService(NopEmitter{})
	defer svc.captureCtl.packetStore.Close()
	if _, err := svc.TranscribeMediaArtifactWithContext(context.Background(), " ", false); err == nil || !strings.Contains(err.Error(), "missing media artifact token") {
		t.Fatalf("expected missing token error, got %v", err)
	}
	if _, err := svc.TranscribeMediaArtifactWithContext(context.Background(), "tok-missing", false); err == nil || !strings.Contains(err.Error(), "media analysis is not ready") {
		t.Fatalf("expected media analysis not ready error, got %v", err)
	}

	svc.analysisCtl.mediaAnalysis = &model.MediaAnalysis{Sessions: []model.MediaSession{{
		ID: "video-1", MediaType: "video", Artifact: &model.MediaArtifact{Token: "tok-video", Name: "video.h264"},
	}}}
	svc.mediaCtl.mediaArtifacts["tok-video"] = filepath.Join(t.TempDir(), "video.h264")
	if _, err := svc.TranscribeMediaArtifactWithContext(context.Background(), "tok-video", false); err == nil || !strings.Contains(err.Error(), "not an audio session") {
		t.Fatalf("expected non-audio error, got %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.TranscribeMediaArtifactWithContext(ctx, "tok-video", false); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled context, got %v", err)
	}
}

func TestSpeechBatchHelpersCloneAndNormalize(t *testing.T) {
	task := &model.SpeechBatchTaskStatus{
		Items: []model.SpeechBatchTaskItem{
			{Status: "queued"},
			{Status: "running"},
			{Status: "completed"},
			{Status: "failed"},
			{Status: "skipped"},
			{Status: "unknown"},
		},
	}
	recomputeSpeechBatchCounts(task)
	if task.Total != 6 || task.Queued != 1 || task.Running != 1 || task.Completed != 1 || task.Failed != 1 || task.Skipped != 1 {
		t.Fatalf("unexpected recomputed counts: %+v", task)
	}

	cloned := cloneSpeechBatchTask(task)
	cloned.Items[0].Status = "mutated"
	if task.Items[0].Status == "mutated" {
		t.Fatal("cloneSpeechBatchTask should copy item slice")
	}
	if !reflect.DeepEqual(cloneSpeechBatchTask(nil), model.SpeechBatchTaskStatus{}) {
		t.Fatal("cloneSpeechBatchTask(nil) should return zero value")
	}
	if got := normalizeSpeechBatchError(context.Canceled); got != "cancelled" {
		t.Fatalf("normalizeSpeechBatchError(context.Canceled) = %q", got)
	}
	if got := normalizeSpeechBatchError(errors.New("  detail  ")); got != "detail" {
		t.Fatalf("normalizeSpeechBatchError(trim) = %q", got)
	}
	if got := normalizeSpeechBatchError(nil); got != "" {
		t.Fatalf("normalizeSpeechBatchError(nil) = %q", got)
	}
}

func TestSpeechProfileAndRuntimeProbeHelpers(t *testing.T) {
	profiles := map[string]string{
		"sample.ulaw": "mulaw",
		"sample.alaw": "alaw",
		"sample.g722": "g722",
		"sample.l16":  "s16be",
		"sample.aac":  "aac",
		"sample.opus": "opus",
		"sample.mpa":  "mp3",
		"sample.mp3":  "mp3",
	}
	for path, want := range profiles {
		profile, err := detectTranscriptionAudioProfile(path)
		if err != nil {
			t.Fatalf("detectTranscriptionAudioProfile(%q) error = %v", path, err)
		}
		if profile.inputFormat != want {
			t.Fatalf("detectTranscriptionAudioProfile(%q).inputFormat = %q, want %q", path, profile.inputFormat, want)
		}
	}
	if _, err := detectTranscriptionAudioProfile("sample.wav"); err == nil || !strings.Contains(err.Error(), "unsupported speech transcription format") {
		t.Fatalf("expected unsupported speech format error, got %v", err)
	}

	name := buildTranscriptionTempName(filepath.Join("dir", "capture.ulaw"))
	if !strings.HasPrefix(name, "capture_") || !strings.HasSuffix(name, ".transcribe.wav") {
		t.Fatalf("unexpected transcription temp name: %q", name)
	}

	dir := t.TempDir()
	candidates := pythonPathCandidates(dir)
	want := [][]string{{filepath.Join(dir, "python.exe")}, {filepath.Join(dir, "python")}}
	if !reflect.DeepEqual(candidates, want) {
		t.Fatalf("pythonPathCandidates(dir) = %v, want %v", candidates, want)
	}
	if got := pythonPathCandidates("python3"); !reflect.DeepEqual(got, [][]string{{"python3"}}) {
		t.Fatalf("pythonPathCandidates(file) = %v", got)
	}
	if pythonCommandExists(nil) || pythonCommandExists([]string{""}) {
		t.Fatal("empty python command candidates should not exist")
	}
}

func TestSpeechProbeCachesCopySuccessAndError(t *testing.T) {
	clearSpeechRuntimeProbeCache()
	t.Cleanup(clearSpeechRuntimeProbeCache)

	key := "cache-key"
	cmd := []string{"python", "-3"}
	storeSpeechPythonCache(key, cmd, nil)
	cmd[0] = "mutated"

	got, err, ok := getSpeechPythonCache(key)
	if !ok || err != nil || !reflect.DeepEqual(got, []string{"python", "-3"}) {
		t.Fatalf("getSpeechPythonCache(success) = %v err=%v ok=%t", got, err, ok)
	}
	got[0] = "changed"
	gotAgain, _, _ := getSpeechPythonCache(key)
	if gotAgain[0] != "python" {
		t.Fatalf("cache should return copied command slices, got %v", gotAgain)
	}

	storeSpeechPythonCache("error-key", nil, errors.New("boom"))
	if got, err, ok := getSpeechPythonCache("error-key"); !ok || err == nil || err.Error() != "boom" || got != nil {
		t.Fatalf("getSpeechPythonCache(error) = %v err=%v ok=%t", got, err, ok)
	}
	if _, _, ok := getSpeechPythonCache("missing"); ok {
		t.Fatal("unexpected cache hit for missing key")
	}
}

func TestCheckPythonVoskAvailabilityCachedStoresResult(t *testing.T) {
	oldCheck := checkPythonVoskAvailabilityFn
	t.Cleanup(func() {
		checkPythonVoskAvailabilityFn = oldCheck
		clearSpeechRuntimeProbeCache()
	})
	clearSpeechRuntimeProbeCache()

	var calls atomic.Int32
	checkPythonVoskAvailabilityFn = func(context.Context, []string) error {
		calls.Add(1)
		return errors.New("No module named 'vosk'")
	}

	cmd := []string{"python"}
	err := checkPythonVoskAvailabilityCached(context.Background(), cmd)
	if err == nil || !strings.Contains(err.Error(), "vosk") {
		t.Fatalf("expected cached vosk error, got %v", err)
	}
	err = checkPythonVoskAvailabilityCached(context.Background(), cmd)
	if err == nil || calls.Load() != 1 {
		t.Fatalf("expected second vosk check to use cache, err=%v calls=%d", err, calls.Load())
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = checkPythonVoskAvailabilityCached(ctx, []string{"python-other"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled cache probe, got %v", err)
	}
}

func TestResolveSpeechToTextStatusWithResolverFastAndReady(t *testing.T) {
	modelDir := t.TempDir()
	status := resolveSpeechToTextStatusWithResolver(context.Background(), SpeechStatusOptions{Fast: true}, func(context.Context, bool) ([]string, error) {
		return []string{"python"}, nil
	})
	if !status.PythonAvailable || status.VoskAvailable || status.Available {
		t.Fatalf("fast status should only prove Python and model state, got %+v", status)
	}

	t.Setenv(voskModelEnvVar, modelDir)
	oldCheck := checkPythonVoskAvailabilityFn
	t.Cleanup(func() {
		checkPythonVoskAvailabilityFn = oldCheck
		clearSpeechRuntimeProbeCache()
	})
	clearSpeechRuntimeProbeCache()
	checkPythonVoskAvailabilityFn = func(context.Context, []string) error { return nil }

	status = resolveSpeechToTextStatusWithResolver(context.Background(), SpeechStatusOptions{}, func(context.Context, bool) ([]string, error) {
		return []string{"python"}, nil
	})
	if !status.PythonAvailable || !status.VoskAvailable || !status.ModelAvailable || status.Message != "ok" {
		t.Fatalf("expected ready Python/Vosk/model status, got %+v", status)
	}
}

func writeFakeExecutableFile(t *testing.T, base string) string {
	t.Helper()

	name := base
	if !strings.HasSuffix(strings.ToLower(name), ".exe") {
		name += ".exe"
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("fake"), 0o755); err != nil {
		t.Fatalf("write fake executable %s: %v", path, err)
	}
	return path
}

func TestSpeechCacheTTLCanExpire(t *testing.T) {
	oldTTL := speechProbeCacheTTL
	t.Cleanup(func() {
		speechProbeCacheTTL = oldTTL
		clearSpeechRuntimeProbeCache()
	})
	clearSpeechRuntimeProbeCache()
	speechProbeCacheTTL = time.Nanosecond

	storeSpeechPythonCache("short", []string{"python"}, nil)
	time.Sleep(time.Millisecond)
	if _, _, ok := getSpeechPythonCache("short"); ok {
		t.Fatal("expected short-lived speech cache entry to expire")
	}
}
