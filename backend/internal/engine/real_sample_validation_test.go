package engine

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gshark/sentinel/backend/internal/model"
)

const (
	realSampleCS                  = `C:\Users\QAQ\Downloads\cs流量分析.pcapng`
	realSampleVShell              = `C:\Users\QAQ\Desktop\贺春\hard_pcap\attch.pcapng`
	realSampleWebShellBehinder    = `C:\Users\QAQ\Desktop\gshark\bx3base.pcap`
	realSampleWebShellGodzilla    = `C:\Users\QAQ\Desktop\gshark\gsl4.0.pcap`
	realSampleWebShellAntSword    = `C:\Users\QAQ\Desktop\gshark\Antsword.pcap`
	realSampleIndustrialModbus    = `C:\users\qaq\Downloads\70893dcf-7a32-4103-a1af-d059ca0dccfa\modbus.pcapng`
	realSampleVehicleCAN          = `C:\Users\QAQ\Desktop\gshark\CAN.pcapng`
	realSampleVShellTargetPreview = "hacked_by_fallsnow&paperplane(QAQ)"
	realSampleCSRawKey            = "a4553adf7a841e1dcf708afc912275ee"
)

func TestRealSampleCSBuildsC2Evidence(t *testing.T) {
	svc := loadRealSample(t, "GSHARK_SAMPLE_CS", realSampleCS)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	analysis, err := svc.C2SampleAnalysis(ctx)
	if err != nil {
		t.Fatalf("C2SampleAnalysis() error = %v", err)
	}
	if analysis.CS.CandidateCount == 0 &&
		len(analysis.CS.Candidates) == 0 &&
		len(analysis.CS.HostURIAggregates) == 0 &&
		len(analysis.CS.DNSAggregates) == 0 {
		t.Fatalf("expected CS candidates or aggregates, got %+v", analysis.CS)
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

func TestRealSampleCSDecryptsWithKnownRawKey(t *testing.T) {
	svc := loadRealSample(t, "GSHARK_SAMPLE_CS", realSampleCS)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	rawKey := strings.TrimSpace(os.Getenv("GSHARK_SAMPLE_CS_AES_RAND"))
	if rawKey == "" {
		rawKey = realSampleCSRawKey
	}
	result, err := svc.C2Decrypt(ctx, model.C2DecryptRequest{
		Family: "cs",
		Scope:  model.C2DecryptScope{UseCandidates: true, UseAggregates: true},
		CS:     model.C2CSDecryptOptions{KeyMode: "aes_rand", AESRand: rawKey, TransformMode: "auto"},
	})
	if err != nil {
		t.Fatalf("C2Decrypt(cs) error = %v", err)
	}
	if result.DecryptedCount == 0 {
		t.Fatalf("expected CS decrypted records with known Raw key, got status=%s candidates=%d notes=%v", result.Status, result.TotalCandidates, result.Notes)
	}
	if !hasRecordWithKeyStatus(result.Records, c2DecryptKeyStatusOK) {
		t.Fatalf("expected HMAC verified CS records, got %+v", result.Records)
	}
	if !noteContains(result.Notes, "SHA256(Raw key/AES rand)") || !noteContains(result.Notes, "Raw key 获取路径") {
		t.Fatalf("expected Raw key explanatory notes, got %+v", result.Notes)
	}
}

func TestRealSampleCSExplainsMetadataWithoutRawKey(t *testing.T) {
	svc := loadRealSample(t, "GSHARK_SAMPLE_CS", realSampleCS)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	result, err := svc.C2Decrypt(ctx, model.C2DecryptRequest{
		Family: "cs",
		Scope:  model.C2DecryptScope{UseCandidates: true, UseAggregates: true},
		CS:     model.C2CSDecryptOptions{KeyMode: "aes_hmac"},
	})
	if err != nil {
		t.Fatalf("C2Decrypt(cs no key) error = %v", err)
	}
	if result.DecryptedCount != 0 {
		t.Fatalf("CS decrypt without key should not produce plaintext, got %+v", result)
	}
	if !noteContains(result.Notes, "metadata 密文候选") || !noteContains(result.Notes, "无法直接算出 Raw key") {
		t.Fatalf("expected metadata/raw-key explanation, got %+v", result.Notes)
	}
}

func TestRealSampleVShellDecryptsTargetPlaintext(t *testing.T) {
	svc := loadRealSample(t, "GSHARK_SAMPLE_VSHELL", realSampleVShell)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	result, err := svc.C2Decrypt(ctx, model.C2DecryptRequest{
		Family: "vshell",
		Scope:  model.C2DecryptScope{UseCandidates: true, UseAggregates: true},
		VShell: model.C2VShellDecryptOptions{Salt: "paperplane", VKey: "fallsnow", Mode: "auto"},
	})
	if err != nil {
		t.Fatalf("C2Decrypt(vshell) error = %v", err)
	}
	if result.DecryptedCount == 0 {
		t.Fatalf("expected VShell decrypted records, got status=%s candidates=%d notes=%v", result.Status, result.TotalCandidates, result.Notes)
	}
	if !hasDecryptedRecord(result, realSampleVShellTargetPreview, "") {
		for _, record := range result.Records {
			if record.KeyStatus == c2DecryptKeyStatusOK {
				t.Logf("record: stream=%d packet=%d direction=%s len=%d tags=%v preview=%q", record.StreamID, record.PacketID, record.Direction, record.DecryptedLength, record.Tags, record.PlaintextPreview)
			}
		}
		t.Fatalf("expected decrypted plaintext %q to survive real-sample result cap", realSampleVShellTargetPreview)
	}
}

func TestRealSampleWebShellSourceHints(t *testing.T) {
	tests := []struct {
		name           string
		env            string
		fallback       string
		familyNeedles  []string
		decoderNeedles []string
	}{
		{
			name:           "behinder",
			env:            "GSHARK_SAMPLE_WEBSHELL_BEHINDER",
			fallback:       realSampleWebShellBehinder,
			familyNeedles:  []string{"aes_webshell_like", "behinder"},
			decoderNeedles: []string{"behinder"},
		},
		{
			name:           "godzilla",
			env:            "GSHARK_SAMPLE_WEBSHELL_GODZILLA",
			fallback:       realSampleWebShellGodzilla,
			familyNeedles:  []string{"godzilla_like"},
			decoderNeedles: []string{"godzilla"},
		},
		{
			name:           "antsword",
			env:            "GSHARK_SAMPLE_WEBSHELL_ANTSWORD",
			fallback:       realSampleWebShellAntSword,
			familyNeedles:  []string{"antsword_like"},
			decoderNeedles: []string{"antsword"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := loadRealSample(t, tt.env, tt.fallback)
			sources, err := svc.ListStreamPayloadSources(200)
			if err != nil {
				t.Fatalf("ListStreamPayloadSources() error = %v", err)
			}
			if len(sources) == 0 {
				t.Fatalf("expected WebShell payload sources")
			}
			if !hasPayloadSourceHint(sources, tt.familyNeedles, tt.decoderNeedles) {
				t.Fatalf("expected %s decoder/family hint, got %+v", tt.name, summarizePayloadSourcesForTest(sources))
			}
			if tt.name == "godzilla" && hasGodzillaHint(sources) && topPayloadDecoder(sources) == "behinder" {
				t.Fatalf("godzilla random-param hint was outranked by behinder: %+v", summarizePayloadSourcesForTest(sources))
			}
		})
	}
}

func TestRealSampleModbusIndustrialEvidence(t *testing.T) {
	svc := loadRealSample(t, "GSHARK_SAMPLE_INDUSTRIAL_MODBUS", realSampleIndustrialModbus)

	analysis, err := svc.IndustrialAnalysis()
	if err != nil {
		t.Fatalf("IndustrialAnalysis() error = %v", err)
	}
	if analysis.Modbus.TotalFrames == 0 && analysis.TotalIndustrialPackets == 0 {
		t.Fatalf("expected Modbus/industrial parsing result, got %+v", analysis)
	}
	if len(analysis.Modbus.DecodedInputs) == 0 {
		t.Fatalf("expected Modbus decoded ASCII/UTF-8 inputs, got none")
	}
	for _, input := range analysis.Modbus.DecodedInputs {
		if strings.TrimSpace(input.Text) == "" || input.StartPacketID == 0 || input.EndPacketID == 0 {
			t.Fatalf("expected populated Modbus decoded input, got %+v", input)
		}
		t.Logf("decoded Modbus input: packets=%d-%d encoding=%s text=%q raw=%q", input.StartPacketID, input.EndPacketID, input.Encoding, input.Text, input.RawText)
	}

	evidence, err := svc.GatherEvidence(context.Background(), model.EvidenceFilter{Modules: []string{"industrial"}})
	if err != nil {
		t.Fatalf("GatherEvidence(industrial) error = %v", err)
	}
	if len(evidence.Records) > 0 {
		high := countEvidenceSeverities(evidence.Records, "high", "critical")
		if high == len(evidence.Records) && len(analysis.RuleHits) == 0 {
			t.Fatalf("ordinary Modbus traffic should not all be high/critical without rule hits: %+v", evidence.Records)
		}
		for _, record := range evidence.Records {
			if record.Module != "industrial" || record.Summary == "" || record.Severity == "" {
				t.Fatalf("expected populated industrial evidence fields, got %+v", record)
			}
		}
	}
}

func TestRealSampleCANVehicleBaselineDoesNotEmitFalseHighUDS(t *testing.T) {
	svc := loadRealSample(t, "GSHARK_SAMPLE_VEHICLE_CAN", realSampleVehicleCAN)

	analysis, err := svc.VehicleAnalysis()
	if err != nil {
		t.Fatalf("VehicleAnalysis() error = %v", err)
	}
	if analysis.TotalVehiclePackets == 0 && analysis.CAN.TotalFrames == 0 {
		t.Fatalf("expected CAN/vehicle parser to run on baseline sample, got %+v", analysis)
	}

	evidence, err := svc.GatherEvidence(context.Background(), model.EvidenceFilter{Modules: []string{"vehicle"}})
	if err != nil {
		t.Fatalf("GatherEvidence(vehicle) error = %v", err)
	}
	for _, record := range evidence.Records {
		if record.Module != "vehicle" {
			t.Fatalf("expected only vehicle evidence, got %+v", record)
		}
		if isHighOrCritical(record.Severity) && analysis.UDS.TotalMessages == 0 && realSampleRecordMentions(record, "uds") {
			t.Fatalf("CAN baseline should not emit high/critical UDS evidence without UDS messages: %+v", record)
		}
	}
}

func realSamplePath(t *testing.T, envName, fallback string) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv(envName))
	if path == "" {
		path = fallback
	}
	if path == "" {
		t.Skipf("%s not configured", envName)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Skipf("%s sample unavailable at %q: %v", envName, path, err)
	}
	if info.IsDir() {
		t.Skipf("%s points to a directory, want a PCAP file: %q", envName, path)
	}
	return path
}

func loadRealSample(t *testing.T, envName, fallback string) *Service {
	t.Helper()
	path := realSamplePath(t, envName, fallback)
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

func hasRealSampleEvidenceText(records []model.EvidenceRecord, needles ...string) bool {
	for _, record := range records {
		text := strings.ToLower(strings.Join([]string{
			record.Family,
			record.SourceType,
			record.Summary,
			record.Value,
			strings.Join(record.Tags, " "),
		}, " "))
		for _, needle := range needles {
			if strings.Contains(text, strings.ToLower(needle)) {
				return true
			}
		}
	}
	return false
}

func hasPayloadSourceHint(sources []model.StreamPayloadSource, familyNeedles, decoderNeedles []string) bool {
	for _, source := range sources {
		if containsAnyFold(source.FamilyHint, familyNeedles...) {
			return true
		}
		if containsAnyFold(strings.Join(source.DecoderHints, " "), decoderNeedles...) {
			return true
		}
		if containsAnyFold(decoderFromOptions(source.DecoderOptionsHint), decoderNeedles...) {
			return true
		}
	}
	return false
}

func hasGodzillaHint(sources []model.StreamPayloadSource) bool {
	return hasPayloadSourceHint(sources, []string{"godzilla_like"}, []string{"godzilla"})
}

func hasRecordWithKeyStatus(records []model.C2DecryptedRecord, keyStatus string) bool {
	for _, record := range records {
		if record.KeyStatus == keyStatus && record.Error == "" {
			return true
		}
	}
	return false
}

func topPayloadDecoder(sources []model.StreamPayloadSource) string {
	if len(sources) == 0 {
		return ""
	}
	return decoderFromOptions(sources[0].DecoderOptionsHint)
}

func decoderFromOptions(options map[string]any) string {
	if options == nil {
		return ""
	}
	if decoder, ok := options["decoder"].(string); ok {
		return decoder
	}
	return ""
}

func summarizePayloadSourcesForTest(sources []model.StreamPayloadSource) []model.StreamPayloadSource {
	if len(sources) <= 8 {
		return sources
	}
	return sources[:8]
}

func countEvidenceSeverities(records []model.EvidenceRecord, severities ...string) int {
	count := 0
	for _, record := range records {
		if containsAnyFold(record.Severity, severities...) {
			count++
		}
	}
	return count
}

func isHighOrCritical(severity string) bool {
	return containsAnyFold(severity, "high", "critical")
}

func realSampleRecordMentions(record model.EvidenceRecord, needle string) bool {
	text := strings.Join([]string{
		record.SourceType,
		record.Summary,
		record.Value,
		strings.Join(record.Tags, " "),
	}, " ")
	return containsAnyFold(text, needle)
}

func containsAnyFold(text string, needles ...string) bool {
	text = strings.ToLower(text)
	for _, needle := range needles {
		if needle != "" && strings.Contains(text, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}
