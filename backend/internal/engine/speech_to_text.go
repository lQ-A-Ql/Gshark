package engine

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

const (
	speechEngineName   = "vosk"
	speechLanguageCode = "zh-CN"
)

var (
	resolveSpeechPythonCommandFn = resolveSpeechPythonCommand
	speechToTextStatusFn         = resolveSpeechToTextStatus
	runSpeechToTextFn            = transcribeAudioFileWithPython
	transcribeAudioArtifactFn    = transcribeAudioArtifact
)

type transcriptionAudioProfile struct {
	inputFormat string
	inputArgs   []string
}

type rawTranscriptionPayload struct {
	Text            string                            `json:"text"`
	DurationSeconds float64                           `json:"duration_seconds"`
	Segments        []model.MediaTranscriptionSegment `json:"segments"`
}

const speechEnhancementFilter = "highpass=f=120,lowpass=f=3800,acompressor=threshold=-28dB:ratio=3:attack=5:release=80:makeup=8dB,alimiter=limit=0.92"

func (s *Service) SpeechToTextStatus() model.SpeechToTextStatus {
	status := speechToTextStatusFn()
	status.FFmpegAvailable = s.FFmpegStatus().Available
	if !status.FFmpegAvailable && strings.TrimSpace(status.Message) == "" {
		status.Message = "未检测到 ffmpeg，请先安装 ffmpeg 或在设置中配置其路径。"
	}
	status.Available = status.PythonAvailable && status.VoskAvailable && status.ModelAvailable && status.FFmpegAvailable
	return status
}

func (s *Service) TranscribeMediaArtifact(token string, force bool) (model.MediaTranscription, error) {
	return s.transcribeMediaArtifactWithContext(context.Background(), token, force)
}

func (s *Service) transcribeMediaArtifactWithContext(ctx context.Context, token string, force bool) (model.MediaTranscription, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return model.MediaTranscription{}, errors.New("missing media artifact token")
	}

	status := s.SpeechToTextStatus()
	if !status.Available {
		return model.MediaTranscription{}, errors.New(status.Message)
	}

	s.mu.RLock()
	cached, ok := s.mediaSpeech[token]
	s.mu.RUnlock()
	if ok && !force {
		cached.Cached = true
		cached.Status = "completed"
		return cached, nil
	}

	session, err := s.mediaSessionForArtifact(token)
	if err != nil {
		return model.MediaTranscription{}, err
	}
	if !strings.EqualFold(session.MediaType, "audio") {
		return model.MediaTranscription{}, errors.New("media artifact is not an audio session")
	}

	inputPath, _, err := s.MediaArtifact(token)
	if err != nil {
		return model.MediaTranscription{}, err
	}

	result, err := transcribeAudioArtifactFn(ctx, status, inputPath)
	if err != nil {
		return model.MediaTranscription{}, err
	}

	transcription := model.MediaTranscription{
		Token:           token,
		SessionID:       session.ID,
		Title:           buildMediaSessionLabel(session),
		Text:            strings.TrimSpace(result.Text),
		Language:        speechLanguageCode,
		Engine:          speechEngineName,
		Status:          "completed",
		Cached:          false,
		DurationSeconds: result.DurationSeconds,
		Segments:        result.Segments,
	}

	s.mu.Lock()
	if s.mediaSpeech == nil {
		s.mediaSpeech = map[string]model.MediaTranscription{}
	}
	s.mediaSpeech[token] = transcription
	s.mu.Unlock()
	return transcription, nil
}

func (s *Service) StartMediaBatchTranscription(force bool) (model.SpeechBatchTaskStatus, error) {
	status := s.SpeechToTextStatus()
	if !status.Available {
		return model.SpeechBatchTaskStatus{}, errors.New(status.Message)
	}

	analysis, err := s.MediaAnalysis()
	if err != nil {
		return model.SpeechBatchTaskStatus{}, err
	}

	items := make([]model.SpeechBatchTaskItem, 0, len(analysis.Sessions))
	s.mu.RLock()
	for _, session := range analysis.Sessions {
		if !strings.EqualFold(session.MediaType, "audio") || session.Artifact == nil {
			continue
		}
		item := model.SpeechBatchTaskItem{
			Token:      session.Artifact.Token,
			SessionID:  session.ID,
			MediaLabel: buildMediaSessionLabel(session),
			Title:      buildMediaSessionLabel(session),
			Status:     "queued",
		}
		if cached, ok := s.mediaSpeech[session.Artifact.Token]; ok && !force {
			item.Status = "skipped"
			item.Cached = true
			item.Text = cached.Text
		}
		items = append(items, item)
	}
	s.mu.RUnlock()

	if len(items) == 0 {
		return model.SpeechBatchTaskStatus{}, errors.New("当前抓包没有可转写的音频会话")
	}

	s.mu.Lock()
	if s.speechBatch != nil && !s.speechBatch.Done && !s.speechBatch.Cancelled {
		defer s.mu.Unlock()
		return model.SpeechBatchTaskStatus{}, errors.New("已有批量转写任务正在运行")
	}
	s.cancelSpeechBatchLocked()
	ctx, cancel := context.WithCancel(context.Background())
	taskSeed := sha1.Sum([]byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), len(items))))
	task := &model.SpeechBatchTaskStatus{
		TaskID: fmt.Sprintf("speech-batch-%x", taskSeed[:6]),
		Items:  items,
	}
	recomputeSpeechBatchCounts(task)
	s.speechBatch = task
	s.speechCancel = cancel
	out := cloneSpeechBatchTask(task)
	s.mu.Unlock()

	go s.runSpeechBatchTask(ctx, task.TaskID, force)
	return out, nil
}

func (s *Service) MediaBatchTranscriptionStatus() model.SpeechBatchTaskStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.speechBatch == nil {
		return model.SpeechBatchTaskStatus{}
	}
	return cloneSpeechBatchTask(s.speechBatch)
}

func (s *Service) CancelMediaBatchTranscription() model.SpeechBatchTaskStatus {
	s.mu.Lock()
	s.cancelSpeechBatchLocked()
	if s.speechBatch != nil {
		s.speechBatch.Cancelled = true
		s.speechBatch.Done = true
		s.speechBatch.CurrentLabel = "批量转写已取消"
		s.speechBatch.CurrentToken = ""
		recomputeSpeechBatchCounts(s.speechBatch)
	}
	out := cloneSpeechBatchTask(s.speechBatch)
	s.mu.Unlock()
	return out
}

func (s *Service) ExportMediaBatchTranscription() model.MediaTranscriptionBatchExport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	export := model.MediaTranscriptionBatchExport{
		Engine:   speechEngineName,
		Language: speechLanguageCode,
	}
	if s.speechBatch == nil {
		return export
	}
	export.TaskID = s.speechBatch.TaskID
	for _, item := range s.speechBatch.Items {
		if strings.TrimSpace(item.Text) == "" {
			continue
		}
		export.Items = append(export.Items, model.MediaTranscriptionBatchItem{
			Token:     item.Token,
			SessionID: item.SessionID,
			Title:     item.Title,
			Text:      item.Text,
			Status:    item.Status,
			Cached:    item.Cached,
		})
	}
	return export
}

func (s *Service) runSpeechBatchTask(ctx context.Context, taskID string, force bool) {
	s.mu.Lock()
	task := s.speechBatch
	if task == nil || task.TaskID != taskID {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	for idx := range task.Items {
		s.mu.Lock()
		task = s.speechBatch
		if task == nil || task.TaskID != taskID {
			s.mu.Unlock()
			return
		}
		if task.Cancelled {
			task.Done = true
			task.CurrentToken = ""
			task.CurrentLabel = "批量转写已取消"
			recomputeSpeechBatchCounts(task)
			s.mu.Unlock()
			return
		}
		item := &task.Items[idx]
		if item.Status == "skipped" {
			recomputeSpeechBatchCounts(task)
			s.mu.Unlock()
			continue
		}
		item.Status = "running"
		item.Error = ""
		task.CurrentToken = item.Token
		task.CurrentLabel = item.Title
		recomputeSpeechBatchCounts(task)
		s.mu.Unlock()

		result, err := s.transcribeMediaArtifactWithContext(ctx, item.Token, force)

		s.mu.Lock()
		task = s.speechBatch
		if task == nil || task.TaskID != taskID {
			s.mu.Unlock()
			return
		}
		item = &task.Items[idx]
		if err != nil {
			item.Status = "failed"
			item.Error = normalizeSpeechBatchError(err)
			item.Text = ""
			if errors.Is(ctx.Err(), context.Canceled) {
				task.Cancelled = true
			}
		} else {
			item.Status = "completed"
			item.Cached = result.Cached
			item.Text = result.Text
			item.Error = ""
		}
		task.CurrentToken = ""
		task.CurrentLabel = ""
		recomputeSpeechBatchCounts(task)
		s.mu.Unlock()

		if errors.Is(ctx.Err(), context.Canceled) {
			break
		}
	}

	s.mu.Lock()
	task = s.speechBatch
	if task != nil && task.TaskID == taskID {
		task.Done = true
		if task.Cancelled && strings.TrimSpace(task.CurrentLabel) == "" {
			task.CurrentLabel = "批量转写已取消"
		}
		s.speechCancel = nil
		recomputeSpeechBatchCounts(task)
	}
	s.mu.Unlock()
}

func (s *Service) mediaSessionForArtifact(token string) (model.MediaSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.mediaAnalysis == nil {
		return model.MediaSession{}, errors.New("media analysis is not ready")
	}
	for _, session := range s.mediaAnalysis.Sessions {
		if session.Artifact != nil && session.Artifact.Token == token {
			return session, nil
		}
	}
	return model.MediaSession{}, errors.New("media artifact metadata not found")
}

func buildMediaSessionLabel(session model.MediaSession) string {
	codec := strings.TrimSpace(session.Codec)
	if codec == "" {
		codec = "unknown"
	}
	return fmt.Sprintf(
		"%s / %s / %s:%d -> %s:%d",
		tshark.FirstNonEmpty(session.Application, "RTP"),
		codec,
		tshark.FirstNonEmpty(session.Source, "src"),
		session.SourcePort,
		tshark.FirstNonEmpty(session.Destination, "dst"),
		session.DestinationPort,
	)
}

func recomputeSpeechBatchCounts(task *model.SpeechBatchTaskStatus) {
	if task == nil {
		return
	}
	task.Total = len(task.Items)
	task.Queued = 0
	task.Running = 0
	task.Completed = 0
	task.Failed = 0
	task.Skipped = 0
	for _, item := range task.Items {
		switch item.Status {
		case "queued":
			task.Queued++
		case "running":
			task.Running++
		case "completed":
			task.Completed++
		case "failed":
			task.Failed++
		case "skipped":
			task.Skipped++
		}
	}
}

func cloneSpeechBatchTask(task *model.SpeechBatchTaskStatus) model.SpeechBatchTaskStatus {
	if task == nil {
		return model.SpeechBatchTaskStatus{}
	}
	out := *task
	out.Items = append([]model.SpeechBatchTaskItem(nil), task.Items...)
	return out
}

func normalizeSpeechBatchError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	return strings.TrimSpace(err.Error())
}

func resolveSpeechToTextStatus() model.SpeechToTextStatus {
	status := model.SpeechToTextStatus{
		Engine:    speechEngineName,
		Language:  speechLanguageCode,
		ModelPath: defaultSpeechModelPath(),
	}

	pythonCmd, err := resolveSpeechPythonCommandFn()
	if err == nil {
		status.PythonAvailable = true
		status.PythonCommand = strings.Join(pythonCmd, " ")
	} else {
		status.Message = "未找到 Python 解释器，请先安装 Python 3 或在设置中配置其路径。"
		return status
	}

	if _, err := os.Stat(status.ModelPath); err == nil {
		status.ModelAvailable = true
	} else {
		status.Message = "未检测到 Vosk 中文模型，请在设置中配置模型目录或放置到默认模型目录。"
	}

	if status.PythonAvailable {
		checkCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := checkPythonVoskAvailability(checkCtx, pythonCmd); err == nil {
			status.VoskAvailable = true
		} else if status.Message == "" {
			status.Message = buildSpeechModuleHint(pythonCmd, err)
		}
	}

	if status.Message == "" {
		status.Message = "ok"
	}
	return status
}

func resolveSpeechPythonCommand() ([]string, error) {
	if raw := strings.TrimSpace(os.Getenv("GSHARK_PYTHON")); raw != "" {
		if _, err := os.Stat(raw); err == nil {
			return []string{raw}, nil
		}
	}

	candidates := [][]string{
		{"python3"},
		{"python"},
		{"py", "-3"},
	}
	if runtime.GOOS == "windows" {
		candidates = [][]string{
			{`C:\Users\QAQ\AppData\Local\Programs\Python\Python311\python.exe`},
			{"py", "-3"},
			{"python"},
			{"python3"},
		}
	}
	for _, candidate := range candidates {
		if filepath.IsAbs(candidate[0]) {
			if _, err := os.Stat(candidate[0]); err == nil {
				return candidate, nil
			}
			continue
		}
		if _, err := exec.LookPath(candidate[0]); err == nil {
			return candidate, nil
		}
	}
	return nil, errors.New("python executable not found")
}

func defaultSpeechModelPath() string {
	if raw := strings.TrimSpace(os.Getenv("GSHARK_VOSK_MODEL")); raw != "" {
		return filepath.Clean(raw)
	}
	if raw := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); raw != "" {
		return filepath.Join(raw, "gshark-sentinel", "models", "vosk", "zh-CN")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".gshark-sentinel", "models", "vosk", "zh-CN")
	}
	return filepath.Join(".", "models", "vosk", "zh-CN")
}

func checkPythonVoskAvailability(ctx context.Context, pythonCmd []string) error {
	args := append(append([]string{}, pythonCmd[1:]...), "-c", "import vosk")
	cmd := exec.CommandContext(ctx, pythonCmd[0], args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			return err
		}
		return errors.New(msg)
	}
	return nil
}

func buildSpeechModuleHint(pythonCmd []string, importErr error) string {
	raw := strings.TrimSpace(importErr.Error())
	command := strings.TrimSpace(strings.Join(pythonCmd, " "))
	if command == "" {
		command = "python"
	}

	if strings.Contains(raw, "No module named 'vosk'") || strings.Contains(raw, `No module named "vosk"`) {
		return fmt.Sprintf(
			"当前选择的 Python 解释器里没有安装 vosk 模块。模型目录只提供语音识别模型，不会附带 Python 包。请对这个解释器执行：%s -m pip install vosk",
			command,
		)
	}

	if raw == "" {
		return fmt.Sprintf("当前选择的 Python 解释器无法导入 vosk 模块，请检查该解释器的依赖环境：%s", command)
	}

	return fmt.Sprintf("当前选择的 Python 解释器无法导入 vosk 模块：%s", raw)
}

func transcribeAudioArtifact(ctx context.Context, status model.SpeechToTextStatus, inputPath string) (rawTranscriptionPayload, error) {
	audioProfile, err := detectTranscriptionAudioProfile(inputPath)
	if err != nil {
		return rawTranscriptionPayload{}, err
	}
	wavPath := filepath.Join(filepath.Dir(inputPath), buildTranscriptionTempName(inputPath))
	if err := convertArtifactToSpeechWav(ctx, inputPath, wavPath, audioProfile); err != nil {
		return rawTranscriptionPayload{}, err
	}
	defer os.Remove(wavPath)

	pythonCmd, err := resolveSpeechPythonCommandFn()
	if err != nil {
		return rawTranscriptionPayload{}, err
	}
	return runSpeechToTextFn(ctx, pythonCmd, status.ModelPath, wavPath)
}

func detectTranscriptionAudioProfile(path string) (transcriptionAudioProfile, error) {
	switch strings.ToLower(strings.TrimPrefix(filepath.Ext(path), ".")) {
	case "ulaw":
		return transcriptionAudioProfile{inputFormat: "mulaw", inputArgs: []string{"-ar", "8000", "-ac", "1"}}, nil
	case "alaw":
		return transcriptionAudioProfile{inputFormat: "alaw", inputArgs: []string{"-ar", "8000", "-ac", "1"}}, nil
	case "g722":
		return transcriptionAudioProfile{inputFormat: "g722", inputArgs: []string{"-ar", "8000", "-ac", "1"}}, nil
	case "l16":
		return transcriptionAudioProfile{inputFormat: "s16be", inputArgs: []string{"-ar", "44100", "-ac", "1"}}, nil
	case "aac":
		return transcriptionAudioProfile{inputFormat: "aac"}, nil
	case "opus":
		return transcriptionAudioProfile{inputFormat: "opus"}, nil
	case "mpa", "mp3":
		return transcriptionAudioProfile{inputFormat: "mp3"}, nil
	default:
		return transcriptionAudioProfile{}, fmt.Errorf("unsupported speech transcription format: %s", filepath.Ext(path))
	}
}

func buildTranscriptionTempName(inputPath string) string {
	base := strings.TrimSuffix(filepath.Base(inputPath), filepath.Ext(inputPath))
	sum := sha1.Sum([]byte(inputPath))
	return fmt.Sprintf("%s_%x.transcribe.wav", base, sum[:4])
}

func convertArtifactToSpeechWav(ctx context.Context, inputPath, outputPath string, profile transcriptionAudioProfile) error {
	ffmpegPath, err := resolveFFmpegBinary(strings.TrimSpace(os.Getenv(ffmpegEnvVar)))
	if err != nil {
		return errors.New("未检测到 ffmpeg，请先安装 ffmpeg 或在设置中配置其路径。")
	}
	if err := os.RemoveAll(outputPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cleanup transcription temp wav: %w", err)
	}
	args := buildSpeechFFmpegArgs(inputPath, outputPath, profile)
	cmd := exec.CommandContext(ctx, ffmpegPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return ctx.Err()
		}
		return fmt.Errorf("ffmpeg convert failed: %s", msg)
	}
	return nil
}

func buildSpeechFFmpegArgs(inputPath, outputPath string, profile transcriptionAudioProfile) []string {
	args := []string{"-hide_banner", "-loglevel", "error", "-y"}
	if profile.inputFormat != "" {
		args = append(args, "-f", profile.inputFormat)
	}
	args = append(args, profile.inputArgs...)
	args = append(
		args,
		"-i", inputPath,
		"-af", speechEnhancementFilter,
		"-ac", "1",
		"-ar", "16000",
		"-c:a", "pcm_s16le",
		outputPath,
	)
	return args
}

func transcribeAudioFileWithPython(ctx context.Context, pythonCmd []string, modelPath, wavPath string) (rawTranscriptionPayload, error) {
	args := append(append([]string{}, pythonCmd[1:]...), "-c", speechPythonScript, modelPath, wavPath)
	cmd := exec.CommandContext(ctx, pythonCmd[0], args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return rawTranscriptionPayload{}, ctx.Err()
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if msg == "" {
			msg = err.Error()
		}
		return rawTranscriptionPayload{}, fmt.Errorf("vosk transcribe failed: %s", msg)
	}
	var payload rawTranscriptionPayload
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		return rawTranscriptionPayload{}, fmt.Errorf("decode vosk transcription result: %w", err)
	}
	return payload, nil
}

const speechPythonScript = `
import json
import sys
import wave
from vosk import Model, KaldiRecognizer

model_path = sys.argv[1]
wav_path = sys.argv[2]
wf = wave.open(wav_path, "rb")
if wf.getnchannels() != 1 or wf.getsampwidth() != 2:
    raise RuntimeError("wav must be mono 16-bit PCM")
model = Model(model_path)
rec = KaldiRecognizer(model, wf.getframerate())
rec.SetWords(True)

chunks = []
while True:
    data = wf.readframes(4000)
    if len(data) == 0:
        break
    if rec.AcceptWaveform(data):
        chunks.append(json.loads(rec.Result()))
chunks.append(json.loads(rec.FinalResult()))

segments = []
texts = []
for chunk in chunks:
    text = (chunk.get("text") or "").strip()
    words = chunk.get("result") or []
    if text:
        texts.append(text)
    if text or words:
        start = 0.0
        end = 0.0
        if words:
            start = float(words[0].get("start", 0.0))
            end = float(words[-1].get("end", 0.0))
        segments.append({
            "start_seconds": start,
            "end_seconds": end,
            "text": text,
        })

duration = 0.0
if wf.getframerate() > 0:
    duration = float(wf.getnframes()) / float(wf.getframerate())

print(json.dumps({
    "text": " ".join(texts).strip(),
    "duration_seconds": duration,
    "segments": segments,
}, ensure_ascii=False))
`
