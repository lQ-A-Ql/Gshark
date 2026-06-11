package engine

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestBuildPlaybackNameNormalizesInputAndExtension(t *testing.T) {
	cases := []struct {
		input string
		ext   string
		want  string
	}{
		{input: "call.ulaw", ext: "m4a", want: "call.m4a"},
		{input: " camera.h264 ", ext: ".mp4", want: "camera.mp4"},
		{input: ".hidden", ext: "", want: "media.mp4"},
		{input: "   ", ext: "", want: "media.mp4"},
		{input: filepath.Join("nested", "clip.hevc"), ext: "mp4", want: "clip.mp4"},
	}

	for _, tc := range cases {
		if got := buildPlaybackName(tc.input, tc.ext); got != tc.want {
			t.Fatalf("buildPlaybackName(%q, %q) = %q, want %q", tc.input, tc.ext, got, tc.want)
		}
	}
}

func TestDetectPlaybackProfileAliasesAndUnsupportedFormat(t *testing.T) {
	aliases := map[string]string{
		"sample.264":  "h264",
		"sample.hevc": "hevc",
		"sample.mpa":  "mp3",
		"sample.mp3":  "mp3",
	}
	for path, wantFormat := range aliases {
		profile, err := detectPlaybackProfile(path)
		if err != nil {
			t.Fatalf("detectPlaybackProfile(%q) error = %v", path, err)
		}
		if profile.inputFormat != wantFormat {
			t.Fatalf("detectPlaybackProfile(%q).inputFormat = %q, want %q", path, profile.inputFormat, wantFormat)
		}
	}

	if _, err := detectPlaybackProfile("sample.wav"); err == nil || !strings.Contains(err.Error(), "unsupported playback input format") {
		t.Fatalf("expected unsupported format error, got %v", err)
	}
}

func TestPlaybackProfilesCarryExpectedTranscodeArgs(t *testing.T) {
	raw := rawAudioPlaybackProfile("mulaw", 8000)
	if raw.inputFormat != "mulaw" || raw.outputExt != ".m4a" || raw.contentType != "audio/mp4" {
		t.Fatalf("unexpected raw audio profile: %+v", raw)
	}
	if !containsSequence(raw.inputArgs, "-ar", "8000") || !containsSequence(raw.inputArgs, "-ac", "1") {
		t.Fatalf("raw audio input args missing sample layout: %+v", raw.inputArgs)
	}
	if !containsSequence(raw.outputArgs, "-c:a", "aac") || !containsSequence(raw.outputArgs, "-b:a", "160k") {
		t.Fatalf("raw audio output args missing AAC transcode settings: %+v", raw.outputArgs)
	}

	compressed := compressedAudioPlaybackProfile("opus")
	if compressed.inputFormat != "opus" || len(compressed.inputArgs) != 0 || compressed.outputExt != ".m4a" {
		t.Fatalf("unexpected compressed profile: %+v", compressed)
	}
	if !containsSequence(compressed.outputArgs, "-movflags", "+faststart") {
		t.Fatalf("compressed profile missing faststart flag: %+v", compressed.outputArgs)
	}
}

func TestFFmpegBinaryCandidatesForCustomFileAndDirectory(t *testing.T) {
	customFile := filepath.Join(t.TempDir(), "ffmpeg-custom")
	if got := ffmpegBinaryCandidates("  " + customFile + "  "); len(got) != 1 || got[0] != customFile {
		t.Fatalf("custom file candidates = %v, want [%q]", got, customFile)
	}

	customDir := t.TempDir()
	got := ffmpegBinaryCandidates(customDir)
	want := []string{customDir, filepath.Join(customDir, "ffmpeg.exe"), filepath.Join(customDir, "ffmpeg")}
	if len(got) != len(want) {
		t.Fatalf("custom dir candidates = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate[%d] = %q, want %q (all=%v)", i, got[i], want[i], got)
		}
	}
}

func TestResolveFFmpegBinaryFindsCustomFilePath(t *testing.T) {
	fake := filepath.Join(t.TempDir(), "ffmpeg-test")
	if runtime.GOOS == "windows" {
		fake += ".exe"
	}
	if err := os.WriteFile(fake, []byte("fake"), 0o755); err != nil {
		t.Fatalf("write fake ffmpeg: %v", err)
	}

	got, err := resolveFFmpegBinary(fake)
	if err != nil {
		t.Fatalf("resolveFFmpegBinary(custom file) error = %v", err)
	}
	if got != fake {
		t.Fatalf("resolveFFmpegBinary(custom file) = %q, want %q", got, fake)
	}
}

func TestGeneratePlaybackAssetWithFakeFFmpeg(t *testing.T) {
	ffmpegPath := buildFakeFFmpegBinary(t)
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "audio.ulaw")
	outputPath := filepath.Join(dir, "audio.m4a")
	if err := os.WriteFile(inputPath, []byte("raw audio"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	if err := os.WriteFile(outputPath, []byte("stale"), 0o644); err != nil {
		t.Fatalf("write stale output: %v", err)
	}

	if err := generatePlaybackAsset(context.Background(), ffmpegPath, inputPath, outputPath, rawAudioPlaybackProfile("mulaw", 8000)); err != nil {
		t.Fatalf("generatePlaybackAsset() error = %v", err)
	}
	payload, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read generated output: %v", err)
	}
	if string(payload) != "fake playback asset" {
		t.Fatalf("unexpected generated payload %q", string(payload))
	}
}

func TestGeneratePlaybackAssetReportsFakeFFmpegFailureAndEmptyOutput(t *testing.T) {
	ffmpegPath := buildFakeFFmpegBinary(t)
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "audio.ulaw")
	if err := os.WriteFile(inputPath, []byte("raw audio"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	t.Setenv("MEOW_TRAFFIC_FAKE_FFMPEG_MODE", "fail")
	err := generatePlaybackAsset(context.Background(), ffmpegPath, inputPath, filepath.Join(dir, "fail.m4a"), rawAudioPlaybackProfile("mulaw", 8000))
	if err == nil || !strings.Contains(err.Error(), "fake ffmpeg failure") {
		t.Fatalf("expected fake ffmpeg failure detail, got %v", err)
	}

	t.Setenv("MEOW_TRAFFIC_FAKE_FFMPEG_MODE", "empty")
	err = generatePlaybackAsset(context.Background(), ffmpegPath, inputPath, filepath.Join(dir, "empty.m4a"), rawAudioPlaybackProfile("mulaw", 8000))
	if err == nil || !strings.Contains(err.Error(), "ffmpeg output is empty") {
		t.Fatalf("expected empty output error, got %v", err)
	}
}

func TestGeneratePlaybackAssetHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := generatePlaybackAsset(ctx, filepath.Join(t.TempDir(), "missing-ffmpeg"), "input.ulaw", filepath.Join(t.TempDir(), "out.m4a"), rawAudioPlaybackProfile("mulaw", 8000))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestMediaPlaybackWithContextGeneratesAndCachesAsset(t *testing.T) {
	ffmpegPath := buildFakeFFmpegBinary(t)
	t.Setenv(ffmpegEnvVar, ffmpegPath)

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "capture.ulaw")
	if err := os.WriteFile(inputPath, []byte("raw audio"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	svc := NewService(NopEmitter{})
	defer svc.packetStore.Close()
	svc.mediaArtifacts["tok-audio"] = inputPath
	svc.mediaAnalysis = &model.MediaAnalysis{Sessions: []model.MediaSession{{
		ID: "audio-session", MediaType: "audio", Application: "RTP", Codec: "PCMU",
		Source: "10.0.0.1", SourcePort: 4000, Destination: "10.0.0.2", DestinationPort: 5000,
		Artifact: &model.MediaArtifact{Token: "tok-audio", Name: "friendly-name.ulaw", Format: "ulaw"},
	}}}

	path, name, err := svc.MediaPlaybackWithContext(context.Background(), "tok-audio")
	if err != nil {
		t.Fatalf("MediaPlaybackWithContext() error = %v", err)
	}
	if name != "friendly-name.m4a" {
		t.Fatalf("output name = %q, want friendly-name.m4a", name)
	}
	if filepath.Base(path) != name {
		t.Fatalf("output path %q does not use output name %q", path, name)
	}
	if payload, err := os.ReadFile(path); err != nil || string(payload) != "fake playback asset" {
		t.Fatalf("generated playback payload = %q err=%v", string(payload), err)
	}

	if got := svc.mediaPlayback["tok-audio"]; got != path {
		t.Fatalf("media playback cache = %q, want %q", got, path)
	}
	secondPath, secondName, err := svc.MediaPlaybackWithContext(context.Background(), "tok-audio")
	if err != nil {
		t.Fatalf("second MediaPlaybackWithContext() error = %v", err)
	}
	if secondPath != path || secondName != name {
		t.Fatalf("expected cached playback path/name, got %q/%q want %q/%q", secondPath, secondName, path, name)
	}
}

func containsSequence(items []string, first, second string) bool {
	for i := 0; i+1 < len(items); i++ {
		if items[i] == first && items[i+1] == second {
			return true
		}
	}
	return false
}

func buildFakeFFmpegBinary(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	src := filepath.Join(dir, "fake_ffmpeg.go")
	exe := filepath.Join(dir, "fake_ffmpeg")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	source := `package main

import (
	"fmt"
	"os"
)

func main() {
	mode := os.Getenv("MEOW_TRAFFIC_FAKE_FFMPEG_MODE")
	if mode == "fail" {
		fmt.Fprintln(os.Stderr, "fake ffmpeg failure")
		os.Exit(2)
	}
	if len(os.Args) == 0 {
		os.Exit(3)
	}
	outputPath := os.Args[len(os.Args)-1]
	if mode == "empty" {
		file, err := os.Create(outputPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(4)
		}
		_ = file.Close()
		return
	}
	if err := os.WriteFile(outputPath, []byte("fake playback asset"), 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(5)
	}
}
`
	if err := os.WriteFile(src, []byte(source), 0o644); err != nil {
		t.Fatalf("write fake ffmpeg source: %v", err)
	}
	cmd := exec.Command("go", "build", "-o", exe, src)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build fake ffmpeg: %v\n%s", err, strings.TrimSpace(string(output)))
	}
	return exe
}
