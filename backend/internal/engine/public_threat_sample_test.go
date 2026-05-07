package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

type publicThreatSampleManifest struct {
	SchemaVersion int                          `json:"schemaVersion"`
	UpdatedAt     string                       `json:"updatedAt"`
	Policy        publicThreatSamplePolicy     `json:"policy"`
	Samples       []publicThreatSampleManifestItem `json:"samples"`
}

type publicThreatSamplePolicy struct {
	Purpose          string   `json:"purpose"`
	MaxBytes         int64    `json:"maxBytes"`
	AllowedExtensions []string `json:"allowedExtensions"`
	ArchivePolicy    string   `json:"archivePolicy"`
	ExecutionPolicy   string   `json:"executionPolicy"`
}

type publicThreatSampleManifestItem struct {
	ID            string                 `json:"id"`
	Family        string                 `json:"family"`
	SourceName    string                 `json:"sourceName"`
	SourceURL     string                 `json:"sourceUrl"`
	LocalPath     string                 `json:"localPath"`
	SHA256        string                 `json:"sha256"`
	Bytes         int64                  `json:"bytes"`
	Status        string                 `json:"status"`
	SkippedReason string                 `json:"skippedReason"`
	LicenseNote   string                 `json:"licenseNote"`
	ArchivePassword string               `json:"archivePassword"`
	KnownKeys     map[string]string      `json:"knownKeys"`
	Expected      map[string]any         `json:"expected"`
	DownloadedAt  string                 `json:"downloadedAt"`
}

func TestThreatSampleManifestAndCSDetection(t *testing.T) {
	manifest, manifestPath := loadPublicThreatManifest(t)
	cs := findThreatSampleByFamily(manifest.Samples, "cs")
	if cs == nil {
		t.Skipf("no CS sample in manifest %s", manifestPath)
	}
	if cs.Status != "downloaded" {
		t.Skipf("CS sample not downloaded yet: status=%s reason=%s", cs.Status, cs.SkippedReason)
	}
	if cs.LocalPath == "" {
		t.Fatalf("CS manifest entry missing localPath: %+v", cs)
	}

	svc := loadThreatSampleService(t, cs.LocalPath)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	analysis, err := svc.C2SampleAnalysis(ctx)
	if err != nil {
		t.Fatalf("C2SampleAnalysis() error = %v", err)
	}
	if analysis.CS.CandidateCount == 0 && len(analysis.CS.Candidates) == 0 && len(analysis.CS.HostURIAggregates) == 0 && len(analysis.CS.DNSAggregates) == 0 {
		t.Fatalf("expected public CS sample to produce candidates or aggregates, got %+v", analysis.CS)
	}
	evidence, err := svc.GatherEvidence(ctx, model.EvidenceFilter{Modules: []string{"c2"}})
	if err != nil {
		t.Fatalf("GatherEvidence(c2) error = %v", err)
	}
	if !hasRealSampleEvidenceText(evidence.Records, "cs", "cobalt") {
		t.Fatalf("expected CS-related evidence, got %+v", evidence.Records)
	}
	for _, record := range evidence.Records {
		if record.Module != "c2" {
			t.Fatalf("expected only c2 records, got %+v", record)
		}
		if record.PacketID == 0 || record.Summary == "" || record.Severity == "" {
			t.Fatalf("expected populated C2 evidence fields, got %+v", record)
		}
	}
}

func TestThreatSampleCSDecryptWhenRawKeyPresent(t *testing.T) {
	manifest, _ := loadPublicThreatManifest(t)
	cs := findThreatSampleByFamily(manifest.Samples, "cs")
	if cs == nil || cs.Status != "downloaded" {
		t.Skip("public CS sample unavailable")
	}
	rawKey := strings.TrimSpace(cs.KnownKeys["aes_rand"])
	if rawKey == "" {
		rawKey = strings.TrimSpace(os.Getenv("GSHARK_SAMPLE_CS_AES_RAND"))
	}
	if rawKey == "" {
		t.Skip("no raw key available for public CS sample")
	}

	svc := loadThreatSampleService(t, cs.LocalPath)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := svc.C2Decrypt(ctx, model.C2DecryptRequest{
		Family: "cs",
		Scope:  model.C2DecryptScope{UseCandidates: true, UseAggregates: true},
		CS:     model.C2CSDecryptOptions{KeyMode: "aes_rand", AESRand: rawKey, TransformMode: "auto"},
	})
	if err != nil {
		t.Fatalf("C2Decrypt(cs) error = %v", err)
	}
	if result.DecryptedCount == 0 {
		t.Fatalf("expected CS decrypted records with raw key, got status=%s candidates=%d notes=%v", result.Status, result.TotalCandidates, result.Notes)
	}
	if !hasRecordWithKeyStatus(result.Records, c2DecryptKeyStatusOK) {
		t.Fatalf("expected HMAC verified CS records, got %+v", result.Records)
	}
}

func TestThreatSampleVShellPendingSkipped(t *testing.T) {
	manifest, _ := loadPublicThreatManifest(t)
	vshell := findThreatSampleByFamily(manifest.Samples, "vshell")
	if vshell == nil {
		t.Skip("no VShell entry in manifest")
	}
	if vshell.Status == "downloaded" && strings.TrimSpace(vshell.LocalPath) != "" {
		svc := loadThreatSampleService(t, vshell.LocalPath)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		result, err := svc.C2Decrypt(ctx, model.C2DecryptRequest{
			Family: "vshell",
			Scope:  model.C2DecryptScope{UseCandidates: true, UseAggregates: true},
			VShell: model.C2VShellDecryptOptions{Salt: "paperplane", VKey: "fallsnow", Mode: "auto"},
		})
		if err != nil {
			t.Fatalf("C2Decrypt(vshell public) error = %v", err)
		}
		if result.DecryptedCount == 0 {
			t.Fatalf("expected public VShell decrypt if sample exists, got %+v", result)
		}
		if !hasDecryptedRecord(result, "hacked_by", "") {
			t.Fatalf("expected public VShell plaintext to include hacked_by marker, got %+v", result.Records)
		}
		return
	}

	t.Skip("public VShell PCAP not available; authorized local VShell regression remains covered elsewhere")
}

func loadThreatSampleService(t *testing.T, relPath string) *Service {
	t.Helper()
	path := relPath
	if !filepath.IsAbs(path) {
		path = filepath.Join(repoRootForTest(t), filepath.FromSlash(relPath))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("sample unavailable at %q: %v", path, err)
	}
	if info.IsDir() {
		t.Fatalf("sample path is directory, want file: %q", path)
	}
	svc := NewService(NopEmitter{}, nil)
	t.Cleanup(func() {
		_ = svc.packetStore.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := svc.LoadPCAP(ctx, model.ParseOptions{FilePath: path, FastList: true}); err != nil {
		t.Fatalf("LoadPCAP(%s) error = %v", path, err)
	}
	return svc
}

func loadPublicThreatManifest(t *testing.T) (*publicThreatSampleManifest, string) {
	t.Helper()
	path := filepath.Join(repoRootForTest(t), "samples", "threat-pcaps", "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest %s: %v", path, err)
	}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	var manifest publicThreatSampleManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse manifest %s: %v", path, err)
	}
	return &manifest, path
}

func findThreatSampleByFamily(samples []publicThreatSampleManifestItem, family string) *publicThreatSampleManifestItem {
	for i := range samples {
		if strings.EqualFold(samples[i].Family, family) {
			return &samples[i]
		}
	}
	return nil
}

func repoRootForTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(dir, "..", "..", ".."))
}
