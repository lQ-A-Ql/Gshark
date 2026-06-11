package engine

import (
	"slices"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestAPTThreatHitAndObjectClassificationHelpers(t *testing.T) {
	threatCases := []struct {
		name string
		hit  model.ThreatHit
		want string
	}{
		{name: "yara", hit: model.ThreatHit{Category: "YARA scan"}, want: "yara-hit"},
		{name: "webshell", hit: model.ThreatHit{Category: "web shell command"}, want: "command-detection"},
		{name: "base64", hit: model.ThreatHit{Category: "base64 payload"}, want: "encoding-detection"},
		{name: "404", hit: model.ThreatHit{Category: "Burst 404"}, want: "anomaly-detection"},
		{name: "default", hit: model.ThreatHit{Category: "network"}, want: "rule-match"},
	}
	for _, tt := range threatCases {
		t.Run("threat "+tt.name, func(t *testing.T) {
			if got := classifyThreatHitEvidenceType(tt.hit); got != tt.want {
				t.Fatalf("classifyThreatHitEvidenceType() = %q, want %q", got, tt.want)
			}
		})
	}

	confidenceCases := []struct {
		level string
		want  int
	}{
		{level: "critical", want: 90},
		{level: "high", want: 75},
		{level: "medium", want: 55},
		{level: "low", want: 35},
		{level: "unknown", want: 25},
	}
	for _, tt := range confidenceCases {
		t.Run("confidence "+tt.level, func(t *testing.T) {
			if got := threatHitLevelToConfidence(tt.level); got != tt.want {
				t.Fatalf("threatHitLevelToConfidence() = %d, want %d", got, tt.want)
			}
		})
	}

	objectCases := []struct {
		name           string
		wantType       string
		wantConfidence int
	}{
		{name: "loader.exe", wantType: "executable", wantConfidence: 70},
		{name: "library.dll", wantType: "executable", wantConfidence: 70},
		{name: "stage.ps1", wantType: "script", wantConfidence: 65},
		{name: "dropper.vbs", wantType: "script", wantConfidence: 60},
		{name: "invoice.docx", wantType: "document", wantConfidence: 40},
		{name: "bundle.zip", wantType: "archive", wantConfidence: 40},
		{name: "readme.txt", wantType: "file", wantConfidence: 40},
	}
	for _, tt := range objectCases {
		t.Run("object "+tt.name, func(t *testing.T) {
			obj := model.ObjectFile{Name: tt.name}
			if got := classifyObjectFileEvidenceType(obj); got != tt.wantType {
				t.Fatalf("classifyObjectFileEvidenceType() = %q, want %q", got, tt.wantType)
			}
			if got := objectFileConfidence(obj); got != tt.wantConfidence {
				t.Fatalf("objectFileConfidence() = %d, want %d", got, tt.wantConfidence)
			}
		})
	}
}

func TestBuildAPTAnalysisFromThreatHitsAppliesSilverFoxHints(t *testing.T) {
	analysis := buildAPTAnalysisFromThreatHits([]model.ThreatHit{
		{
			PacketID: 42,
			Category: "YARA scan",
			Rule:     "Silver Fox ValleyRAT HFS Rejetto beacon",
			Level:    "critical",
		},
		{
			PacketID: 43,
			Category: "web shell command",
			Rule:     "command execution over callback",
			Level:    "medium",
		},
		{
			PacketID: 44,
			Category: "ignored",
			Level:    "high",
		},
	}, emptyAPTAnalysis())

	if analysis.TotalEvidence != 2 || len(analysis.Evidence) != 2 {
		t.Fatalf("evidence count = total %d len %d, want 2", analysis.TotalEvidence, len(analysis.Evidence))
	}

	first := analysis.Evidence[0]
	if first.PacketID != 42 || first.SourceModule != "threat-hunting" || first.EvidenceType != "yara-hit" || first.Confidence != 90 {
		t.Fatalf("unexpected first evidence: %+v", first)
	}
	if first.ActorID != "silver-fox" || first.SampleFamily != "ValleyRAT" || first.CampaignStage != "delivery" {
		t.Fatalf("Silver Fox hints were not applied: %+v", first)
	}
	if !aptTestHasFactor(first.ScoreFactors, "yara-hit") || !aptTestHasFactor(first.ScoreFactors, "hfs-download-chain") || !aptTestHasFactor(first.ScoreFactors, "valleyrat-family-hint") {
		t.Fatalf("expected threat score factors, got %+v", first.ScoreFactors)
	}

	second := analysis.Evidence[1]
	if second.EvidenceType != "command-detection" || second.Confidence != 55 {
		t.Fatalf("unexpected second evidence: %+v", second)
	}
}

func TestBuildAPTAnalysisFromObjectsAppliesTypesConfidenceAndHints(t *testing.T) {
	analysis := buildAPTAnalysisFromObjects([]model.ObjectFile{
		{
			ID:       1,
			PacketID: 11,
			Name:     "ValleyRAT-loader.exe",
			MIME:     "application/x-msdownload",
			Source:   "http-object",
		},
		{
			ID:     2,
			Name:   "",
			MIME:   "application/octet-stream",
			Source: "ignored",
		},
		{
			ID:       3,
			PacketID: 12,
			Name:     "installer.zip",
			MIME:     "application/zip",
			Source:   "http-object",
		},
	}, emptyAPTAnalysis())

	if analysis.TotalEvidence != 2 || len(analysis.Evidence) != 2 {
		t.Fatalf("evidence count = total %d len %d, want 2", analysis.TotalEvidence, len(analysis.Evidence))
	}

	exe := analysis.Evidence[0]
	if exe.PacketID != 11 || exe.SourceModule != "object-export" || exe.EvidenceType != "executable" || exe.Confidence != 70 {
		t.Fatalf("unexpected executable evidence: %+v", exe)
	}
	if exe.ActorID != "silver-fox" || exe.SampleFamily != "ValleyRAT" {
		t.Fatalf("expected ValleyRAT object to be linked to Silver Fox, got %+v", exe)
	}
	if !aptTestHasFactor(exe.ScoreFactors, "object-executable") || !aptTestHasFactor(exe.ScoreFactors, "valleyrat-family-hint") {
		t.Fatalf("expected object score factors, got %+v", exe.ScoreFactors)
	}

	archive := analysis.Evidence[1]
	if archive.EvidenceType != "archive" || archive.Confidence != 40 || archive.PacketID != 12 {
		t.Fatalf("unexpected archive evidence: %+v", archive)
	}
}

func TestFinalizeAPTAnalysisAggregatesProfilesBucketsAndFactors(t *testing.T) {
	analysis := finalizeAPTAnalysis(model.APTAnalysis{
		Profiles: []model.APTActorProfile{
			{
				ID:                  "custom-actor",
				Name:                "Custom Actor",
				SampleFamilies:      []model.TrafficBucket{},
				CampaignStages:      []model.TrafficBucket{},
				TransportTraits:     []model.TrafficBucket{},
				InfrastructureHints: []model.TrafficBucket{},
				RelatedC2Families:   []model.TrafficBucket{},
				TTPTags:             []model.TrafficBucket{},
			},
		},
		Evidence: []model.APTEvidenceRecord{
			{
				ActorID:             "silver-fox",
				ActorName:           "Silver Fox / legacy",
				SourceModule:        "threat-hunting",
				EvidenceType:        "yara-hit",
				EvidenceValue:       "ValleyRAT HFS hit",
				Confidence:          80,
				SampleFamily:        "ValleyRAT",
				CampaignStage:       "delivery",
				TransportTraits:     []string{"https-c2", ""},
				InfrastructureHints: []string{"hfs-download-chain", "hfs-download-chain"},
				TTPTags:             []string{"encrypted-c2"},
			},
			{
				ActorID:       "custom-actor",
				ActorName:     "Custom Actor",
				SourceModule:  "object-export",
				EvidenceType:  "script",
				EvidenceValue: "stage.ps1",
				Confidence:    65,
			},
			{
				SourceModule:        "c2-analysis",
				EvidenceType:        "indicator",
				EvidenceValue:       "callback",
				Family:              "Cobalt Strike",
				TransportTraits:     []string{"periodic-callback"},
				InfrastructureHints: []string{"fallback-c2"},
			},
		},
	})

	if analysis.TotalEvidence != 3 {
		t.Fatalf("TotalEvidence = %d, want 3", analysis.TotalEvidence)
	}
	if len(analysis.Profiles) < 2 {
		t.Fatalf("expected silver fox and custom profiles, got %+v", analysis.Profiles)
	}
	if !aptTestHasBucket(analysis.Actors, emptySilverFoxProfile().Name, 1) || !aptTestHasBucket(analysis.Actors, "Custom Actor", 1) {
		t.Fatalf("actors were not aggregated: %+v", analysis.Actors)
	}
	if !aptTestHasBucket(analysis.SampleFamilies, "ValleyRAT", 1) ||
		!aptTestHasBucket(analysis.CampaignStages, "delivery", 1) ||
		!aptTestHasBucket(analysis.TransportTraits, "https-c2", 1) ||
		!aptTestHasBucket(analysis.InfrastructureHints, "hfs-download-chain", 1) ||
		!aptTestHasBucket(analysis.RelatedC2Families, "Cobalt Strike", 1) {
		t.Fatalf("global buckets were not aggregated: %+v", analysis)
	}

	silver := aptTestProfileByID(t, analysis.Profiles, "silver-fox")
	if silver.EvidenceCount != 1 || silver.Confidence != 80 {
		t.Fatalf("silver profile counts/confidence = %+v", silver)
	}
	if !aptTestHasBucket(silver.SampleFamilies, "ValleyRAT", 1) || !aptTestHasFactor(silver.ScoreFactors, "yara-hit") {
		t.Fatalf("silver profile buckets/factors = %+v", silver)
	}

	custom := aptTestProfileByID(t, analysis.Profiles, "custom-actor")
	if custom.EvidenceCount != 1 || custom.Confidence != 65 || !aptTestHasFactor(custom.ScoreFactors, "object-script") {
		t.Fatalf("custom profile was not populated: %+v", custom)
	}
}

func TestAPTMissingScoreFactorsAndFactorNames(t *testing.T) {
	weakOnly := model.APTEvidenceRecord{
		ScoreFactors: []model.APTScoreFactor{
			{Name: "silverfox-case-port-weak", Direction: "positive", SourceModule: "c2-analysis"},
		},
	}
	missing := aptMissingScoreFactors(emptySilverFoxProfile(), []model.APTEvidenceRecord{weakOnly})
	for _, name := range []string{
		"missing-sample-family",
		"missing-delivery-chain",
		"missing-c2-evidence",
		"missing-threat-hunting-evidence",
		"missing-object-evidence",
		"port-only-weak-observation",
	} {
		if !aptTestHasFactor(missing, name) {
			t.Fatalf("missing factor %q in %+v", name, missing)
		}
	}

	complete := []model.APTEvidenceRecord{
		{SampleFamily: "Winos 4.0", CampaignStage: "delivery", SourceModule: "c2-analysis", ScoreFactors: []model.APTScoreFactor{{Name: "winos-family-hint"}}},
		{SourceModule: "threat-hunting", ScoreFactors: []model.APTScoreFactor{{Name: "yara-hit"}}},
		{SourceModule: "object-export", ScoreFactors: []model.APTScoreFactor{{Name: "object-executable"}}},
	}
	missing = aptMissingScoreFactors(emptySilverFoxProfile(), complete)
	if len(missing) != 0 {
		t.Fatalf("complete evidence produced missing factors: %+v", missing)
	}

	names := aptScoreFactorNames(complete[0])
	if !slices.Equal(names, []string{"winos-family-hint"}) {
		t.Fatalf("aptScoreFactorNames() = %+v", names)
	}
}

func aptTestHasFactor(items []model.APTScoreFactor, name string) bool {
	for _, item := range items {
		if item.Name == name {
			return true
		}
	}
	return false
}

func aptTestHasBucket(items []model.TrafficBucket, label string, count int) bool {
	for _, item := range items {
		if item.Label == label && item.Count == count {
			return true
		}
	}
	return false
}

func aptTestProfileByID(t *testing.T, items []model.APTActorProfile, id string) model.APTActorProfile {
	t.Helper()
	for _, item := range items {
		if item.ID == id {
			return item
		}
	}
	t.Fatalf("profile %q not found in %+v", id, items)
	return model.APTActorProfile{}
}
