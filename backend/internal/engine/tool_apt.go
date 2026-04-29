package engine

import (
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func buildAPTAnalysisFromThreatHits(hits []model.ThreatHit, existing model.APTAnalysis) model.APTAnalysis {
	analysis := existing
	for _, hit := range hits {
		if hit.Rule == "" {
			continue
		}
		record := model.APTEvidenceRecord{
			SourceModule:  "threat-hunting",
			EvidenceType:  classifyThreatHitEvidenceType(hit),
			EvidenceValue: hit.Rule,
			Confidence:    threatHitLevelToConfidence(hit.Level),
			Summary:       hit.Rule + " (" + hit.Category + ")",
			Tags:          []string{hit.Category, hit.Level},
		}
		if hit.PacketID > 0 {
			record.PacketID = hit.PacketID
		}
		applySilverFoxEvidenceHints(&record)
		record.ScoreFactors = aptScoreFactorsForRecord(record)
		analysis.Evidence = append(analysis.Evidence, record)
		analysis.TotalEvidence++
	}
	return analysis
}

func buildAPTAnalysisFromObjects(objects []model.ObjectFile, existing model.APTAnalysis) model.APTAnalysis {
	analysis := existing
	for _, obj := range objects {
		if obj.Name == "" {
			continue
		}
		record := model.APTEvidenceRecord{
			SourceModule:  "object-export",
			EvidenceType:  classifyObjectFileEvidenceType(obj),
			EvidenceValue: obj.Name,
			Confidence:    objectFileConfidence(obj),
			Summary:       obj.Name + " (" + obj.MIME + ")",
			Tags:          []string{obj.Source},
		}
		if obj.PacketID > 0 {
			record.PacketID = obj.PacketID
		}
		applySilverFoxEvidenceHints(&record)
		record.ScoreFactors = aptScoreFactorsForRecord(record)
		analysis.Evidence = append(analysis.Evidence, record)
		analysis.TotalEvidence++
	}
	return analysis
}

func classifyThreatHitEvidenceType(hit model.ThreatHit) string {
	lower := strings.ToLower(hit.Category)
	switch {
	case strings.Contains(lower, "yara"):
		return "yara-hit"
	case strings.Contains(lower, "shell") || strings.Contains(lower, "cmd"):
		return "command-detection"
	case strings.Contains(lower, "base64"):
		return "encoding-detection"
	case strings.Contains(lower, "404"):
		return "anomaly-detection"
	default:
		return "rule-match"
	}
}

func threatHitLevelToConfidence(level string) int {
	switch strings.ToLower(level) {
	case "critical":
		return 90
	case "high":
		return 75
	case "medium":
		return 55
	case "low":
		return 35
	default:
		return 25
	}
}

func classifyObjectFileEvidenceType(obj model.ObjectFile) string {
	lower := strings.ToLower(obj.Name)
	switch {
	case strings.HasSuffix(lower, ".exe") || strings.HasSuffix(lower, ".dll"):
		return "executable"
	case strings.HasSuffix(lower, ".ps1") || strings.HasSuffix(lower, ".bat") || strings.HasSuffix(lower, ".cmd"):
		return "script"
	case strings.HasSuffix(lower, ".hta") || strings.HasSuffix(lower, ".vbs"):
		return "script"
	case strings.HasSuffix(lower, ".doc") || strings.HasSuffix(lower, ".docx") || strings.HasSuffix(lower, ".xls") || strings.HasSuffix(lower, ".xlsx"):
		return "document"
	case strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".rar") || strings.HasSuffix(lower, ".7z"):
		return "archive"
	default:
		return "file"
	}
}

func objectFileConfidence(obj model.ObjectFile) int {
	lower := strings.ToLower(obj.Name)
	switch {
	case strings.HasSuffix(lower, ".exe") || strings.HasSuffix(lower, ".dll"):
		return 70
	case strings.HasSuffix(lower, ".ps1") || strings.HasSuffix(lower, ".bat"):
		return 65
	case strings.HasSuffix(lower, ".hta") || strings.HasSuffix(lower, ".vbs"):
		return 60
	default:
		return 40
	}
}

func finalizeAPTAnalysis(analysis model.APTAnalysis) model.APTAnalysis {
	profileTemplates := map[string]model.APTActorProfile{
		"silver-fox": emptySilverFoxProfile(),
	}
	for _, profile := range analysis.Profiles {
		if profile.ID == "" {
			continue
		}
		if _, ok := profileTemplates[profile.ID]; !ok {
			profile.EvidenceCount = 0
			profile.Confidence = 0
			profile.SampleFamilies = []model.TrafficBucket{}
			profile.CampaignStages = []model.TrafficBucket{}
			profile.TransportTraits = []model.TrafficBucket{}
			profile.InfrastructureHints = []model.TrafficBucket{}
			profile.RelatedC2Families = []model.TrafficBucket{}
			profile.TTPTags = []model.TrafficBucket{}
			profile.ScoreFactors = nil
			profileTemplates[profile.ID] = profile
		}
	}

	type bucketSet struct {
		sampleFamilies      map[string]int
		campaignStages      map[string]int
		transportTraits     map[string]int
		infrastructureHints map[string]int
		relatedC2Families   map[string]int
		ttpTags             map[string]int
	}
	newBucketSet := func() *bucketSet {
		return &bucketSet{
			sampleFamilies:      map[string]int{},
			campaignStages:      map[string]int{},
			transportTraits:     map[string]int{},
			infrastructureHints: map[string]int{},
			relatedC2Families:   map[string]int{},
			ttpTags:             map[string]int{},
		}
	}

	profiles := map[string]*model.APTActorProfile{}
	profileBuckets := map[string]*bucketSet{}
	profileEvidence := map[string][]model.APTEvidenceRecord{}
	actorCounts := map[string]int{}
	global := newBucketSet()

	for id, profile := range profileTemplates {
		profile.EvidenceCount = 0
		profile.Confidence = 0
		profile.ScoreFactors = nil
		profiles[id] = cloneAPTActorProfile(profile)
		profileBuckets[id] = newBucketSet()
	}

	for idx := range analysis.Evidence {
		record := analysis.Evidence[idx]
		applySilverFoxEvidenceHints(&record)
		if len(record.ScoreFactors) == 0 {
			record.ScoreFactors = aptScoreFactorsForRecord(record)
		}
		analysis.Evidence[idx] = record

		if record.SampleFamily != "" {
			global.sampleFamilies[record.SampleFamily]++
		}
		if record.CampaignStage != "" {
			global.campaignStages[record.CampaignStage]++
		}
		for _, value := range record.TransportTraits {
			if strings.TrimSpace(value) != "" {
				global.transportTraits[value]++
			}
		}
		for _, value := range record.InfrastructureHints {
			if strings.TrimSpace(value) != "" {
				global.infrastructureHints[value]++
			}
		}
		if record.Family != "" {
			global.relatedC2Families[record.Family]++
		}
		for _, value := range record.TTPTags {
			if strings.TrimSpace(value) != "" {
				global.ttpTags[value]++
			}
		}

		if record.ActorID == "" {
			continue
		}
		profile := profiles[record.ActorID]
		if profile == nil {
			profile = &model.APTActorProfile{
				ID:                  record.ActorID,
				Name:                c2FirstNonEmpty(record.ActorName, record.ActorID),
				Summary:             "由跨模块证据临时聚合出的 APT 候选画像，仍需人工复核。",
				SampleFamilies:      []model.TrafficBucket{},
				CampaignStages:      []model.TrafficBucket{},
				TransportTraits:     []model.TrafficBucket{},
				InfrastructureHints: []model.TrafficBucket{},
				RelatedC2Families:   []model.TrafficBucket{},
				TTPTags:             []model.TrafficBucket{},
				Notes:               []string{"临时 actor hint：尚未接入正式组织画像基线。"},
			}
			profiles[record.ActorID] = profile
			profileBuckets[record.ActorID] = newBucketSet()
		}
		actorCounts[profile.Name]++
		profile.EvidenceCount++
		if record.Confidence > profile.Confidence {
			profile.Confidence = record.Confidence
		}
		bs := profileBuckets[record.ActorID]
		if bs == nil {
			bs = newBucketSet()
			profileBuckets[record.ActorID] = bs
		}
		if record.SampleFamily != "" {
			bs.sampleFamilies[record.SampleFamily]++
		}
		if record.CampaignStage != "" {
			bs.campaignStages[record.CampaignStage]++
		}
		for _, value := range record.TransportTraits {
			if strings.TrimSpace(value) != "" {
				bs.transportTraits[value]++
			}
		}
		for _, value := range record.InfrastructureHints {
			if strings.TrimSpace(value) != "" {
				bs.infrastructureHints[value]++
			}
		}
		if record.Family != "" {
			bs.relatedC2Families[record.Family]++
		}
		for _, value := range record.TTPTags {
			if strings.TrimSpace(value) != "" {
				bs.ttpTags[value]++
			}
		}
		profileEvidence[record.ActorID] = append(profileEvidence[record.ActorID], record)
	}

	profilesOut := make([]model.APTActorProfile, 0, len(profiles))
	for id, profile := range profiles {
		bs := profileBuckets[id]
		if bs != nil {
			profile.SampleFamilies = mergeAPTProfileBuckets(profile.SampleFamilies, bs.sampleFamilies)
			profile.CampaignStages = mergeAPTProfileBuckets(profile.CampaignStages, bs.campaignStages)
			profile.TransportTraits = mergeAPTProfileBuckets(profile.TransportTraits, bs.transportTraits)
			profile.InfrastructureHints = mergeAPTProfileBuckets(profile.InfrastructureHints, bs.infrastructureHints)
			profile.RelatedC2Families = mergeAPTProfileBuckets(profile.RelatedC2Families, bs.relatedC2Families)
			profile.TTPTags = mergeAPTProfileBuckets(profile.TTPTags, bs.ttpTags)
		}
		profile.ScoreFactors = buildAPTProfileScoreFactors(*profile, profileEvidence[id])
		profilesOut = append(profilesOut, *profile)
	}
	sort.SliceStable(profilesOut, func(i, j int) bool {
		if profilesOut[i].EvidenceCount == profilesOut[j].EvidenceCount {
			return profilesOut[i].Name < profilesOut[j].Name
		}
		return profilesOut[i].EvidenceCount > profilesOut[j].EvidenceCount
	})

	analysis.TotalEvidence = len(analysis.Evidence)
	analysis.Actors = bucketsFromMap(actorCounts, 16)
	analysis.SampleFamilies = bucketsFromMap(global.sampleFamilies, 24)
	analysis.CampaignStages = bucketsFromMap(global.campaignStages, 24)
	analysis.TransportTraits = bucketsFromMap(global.transportTraits, 24)
	analysis.InfrastructureHints = bucketsFromMap(global.infrastructureHints, 24)
	analysis.RelatedC2Families = bucketsFromMap(global.relatedC2Families, 12)
	analysis.Profiles = profilesOut
	return analysis
}

func applySilverFoxEvidenceHints(record *model.APTEvidenceRecord) {
	if record == nil {
		return
	}
	text := strings.ToLower(strings.Join([]string{
		record.ActorName,
		record.Family,
		record.EvidenceType,
		record.EvidenceValue,
		record.Host,
		record.URI,
		record.SampleFamily,
		record.CampaignStage,
		strings.Join(record.Tags, " "),
		strings.Join(record.TransportTraits, " "),
		strings.Join(record.InfrastructureHints, " "),
		strings.Join(record.TTPTags, " "),
		record.Summary,
		record.Evidence,
	}, " "))
	isSilverFox := strings.Contains(text, "silver fox") || strings.Contains(text, "银狐") || strings.Contains(text, "swimming snake") || strings.Contains(text, "valleyrat") || strings.Contains(text, "winos") || strings.Contains(text, "gh0st") || strings.Contains(text, "rejetto") || strings.Contains(text, "hfs")
	if isSilverFox && record.ActorID == "" {
		record.ActorID = "silver-fox"
		record.ActorName = "Silver Fox / 银狐"
	}
	if record.SampleFamily == "" {
		switch {
		case strings.Contains(text, "valleyrat"):
			record.SampleFamily = "ValleyRAT"
		case strings.Contains(text, "winos"):
			record.SampleFamily = "Winos 4.0"
		case strings.Contains(text, "gh0st"):
			record.SampleFamily = "Gh0st variant"
		}
	}
	if strings.Contains(text, "hfs") || strings.Contains(text, "rejetto") {
		record.InfrastructureHints = append(record.InfrastructureHints, "hfs-download-chain")
		if record.CampaignStage == "" {
			record.CampaignStage = "delivery"
		}
	}
	record.InfrastructureHints = uniqueStrings(record.InfrastructureHints)
}

func aptScoreFactorsForRecord(record model.APTEvidenceRecord) []model.APTScoreFactor {
	add := func(values map[string]model.APTScoreFactor, name string, weight int, direction, sourceModule, summary string) {
		if name == "" {
			return
		}
		key := sourceModule + ":" + direction + ":" + name
		if existing, ok := values[key]; ok {
			existing.Weight += weight
			if existing.Summary == "" {
				existing.Summary = summary
			}
			values[key] = existing
			return
		}
		values[key] = model.APTScoreFactor{Name: name, Weight: weight, Direction: direction, SourceModule: sourceModule, Summary: summary}
	}
	factors := map[string]model.APTScoreFactor{}
	source := c2FirstNonEmpty(record.SourceModule, "unknown")
	joined := strings.ToLower(strings.Join(append(append(append([]string{record.SampleFamily, record.CampaignStage, record.Family, record.EvidenceType, record.EvidenceValue, record.Host, record.URI, record.Summary}, record.Tags...), record.TransportTraits...), append(record.InfrastructureHints, record.TTPTags...)...), " "))

	if strings.Contains(joined, "hfs-download-chain") || strings.Contains(joined, "rejetto") || strings.Contains(joined, "http file server") {
		add(factors, "hfs-download-chain", 8, "positive", source, "HFS / Rejetto 下载链是 Silver Fox 公开活动中的重要投递线索")
	}
	if strings.Contains(joined, "valleyrat") {
		add(factors, "valleyrat-family-hint", 7, "positive", source, "命中 ValleyRAT 样本家族线索")
	}
	if strings.Contains(joined, "winos") {
		add(factors, "winos-family-hint", 7, "positive", source, "命中 Winos 4.0 样本家族线索")
	}
	if strings.Contains(joined, "gh0st") {
		add(factors, "gh0st-family-hint", 6, "positive", source, "命中 Gh0st 系样本家族线索")
	}
	if strings.Contains(joined, "https-c2") || strings.Contains(joined, "encrypted-c2") || strings.Contains(joined, "https") || strings.Contains(joined, ":443") {
		add(factors, "https-c2", 3, "positive", source, "HTTPS / 加密 C2 仅作为中弱传输模式线索")
	}
	if strings.Contains(joined, "periodic-callback") || strings.Contains(joined, "periodic") || strings.Contains(joined, "callback") {
		add(factors, "periodic-callback", 4, "positive", source, "周期回连模式可辅助识别 RAT/C2 通信")
	}
	if strings.Contains(joined, "18856") || strings.Contains(joined, "9899") || strings.Contains(joined, "silverfox-case-port-weak") {
		add(factors, "silverfox-case-port-weak", 2, "positive", source, "weak observation: 端口仅来自公开个案观察，不能单独强归因")
	}

	if source == "threat-hunting" {
		switch record.EvidenceType {
		case "yara-hit":
			add(factors, "yara-hit", 8, "positive", source, "YARA 命中提供样本/内容侧强证据")
		case "anomaly-detection":
			add(factors, "anomaly", 3, "positive", source, "异常规则命中仅作为辅助证据")
		default:
			add(factors, "rule-match", 5, "positive", source, "威胁狩猎规则命中提供行为侧辅助证据")
		}
	}
	if source == "object-export" {
		switch record.EvidenceType {
		case "executable":
			add(factors, "object-executable", 5, "positive", source, "导出可执行对象，适合作为样本侧复核入口")
		case "script":
			add(factors, "object-script", 4, "positive", source, "导出脚本对象，可能对应投递或执行阶段")
		case "archive":
			add(factors, "object-archive", 3, "positive", source, "导出压缩包对象，可能对应投递载体")
		case "document":
			add(factors, "object-suspicious-document", 3, "positive", source, "导出文档对象，可能对应钓鱼/投递载体")
		}
	}

	out := make([]model.APTScoreFactor, 0, len(factors))
	for _, factor := range factors {
		out = append(out, factor)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Weight == out[j].Weight {
			return out[i].Name < out[j].Name
		}
		return out[i].Weight > out[j].Weight
	})
	return out
}

func buildAPTProfileScoreFactors(profile model.APTActorProfile, evidence []model.APTEvidenceRecord) []model.APTScoreFactor {
	factorMap := map[string]model.APTScoreFactor{}
	for _, record := range evidence {
		for _, factor := range record.ScoreFactors {
			key := factor.Direction + ":" + factor.SourceModule + ":" + factor.Name
			if existing, ok := factorMap[key]; ok {
				existing.Weight += factor.Weight
				factorMap[key] = existing
			} else {
				factorMap[key] = factor
			}
		}
	}
	missing := aptMissingScoreFactors(profile, evidence)
	for _, factor := range missing {
		key := factor.Direction + ":profile:" + factor.Name
		factorMap[key] = factor
	}
	out := make([]model.APTScoreFactor, 0, len(factorMap))
	for _, factor := range factorMap {
		out = append(out, factor)
	}
	sort.SliceStable(out, func(i, j int) bool {
		dirRank := map[string]int{"positive": 0, "negative": 1, "missing": 2}
		if dirRank[out[i].Direction] == dirRank[out[j].Direction] {
			if out[i].Weight == out[j].Weight {
				return out[i].Name < out[j].Name
			}
			return out[i].Weight > out[j].Weight
		}
		return dirRank[out[i].Direction] < dirRank[out[j].Direction]
	})
	return out
}

func aptMissingScoreFactors(profile model.APTActorProfile, evidence []model.APTEvidenceRecord) []model.APTScoreFactor {
	hasFamily := false
	hasDelivery := false
	hasC2 := false
	hasThreat := false
	hasObject := false
	weakPortOnly := len(evidence) > 0
	for _, record := range evidence {
		text := strings.ToLower(strings.Join([]string{record.SampleFamily, record.CampaignStage, record.SourceModule, record.EvidenceType, strings.Join(record.Tags, " "), strings.Join(record.InfrastructureHints, " "), strings.Join(record.TransportTraits, " "), strings.Join(aptScoreFactorNames(record), " ")}, " "))
		if strings.Contains(text, "valleyrat") || strings.Contains(text, "winos") || strings.Contains(text, "gh0st") {
			hasFamily = true
		}
		if strings.Contains(text, "delivery") || strings.Contains(text, "downloader") || strings.Contains(text, "hfs-download-chain") {
			hasDelivery = true
		}
		if record.SourceModule == "c2-analysis" {
			hasC2 = true
		}
		if record.SourceModule == "threat-hunting" {
			hasThreat = true
		}
		if record.SourceModule == "object-export" {
			hasObject = true
		}
		for _, factor := range record.ScoreFactors {
			if factor.Name != "silverfox-case-port-weak" {
				weakPortOnly = false
			}
		}
	}
	out := []model.APTScoreFactor{}
	addMissing := func(name, summary string) {
		out = append(out, model.APTScoreFactor{Name: name, Direction: "missing", SourceModule: "profile", Summary: summary})
	}
	if !hasFamily {
		addMissing("missing-sample-family", "缺失 ValleyRAT / Winos 4.0 / Gh0st 任一样本家族证据")
	}
	if !hasDelivery {
		addMissing("missing-delivery-chain", "缺失 delivery / downloader / HFS 下载链证据")
	}
	if !hasC2 {
		addMissing("missing-c2-evidence", "缺失 C2 样本分析页输出的通信证据")
	}
	if !hasThreat {
		addMissing("missing-threat-hunting-evidence", "缺失 Threat Hunting 规则/YARA/异常证据")
	}
	if !hasObject {
		addMissing("missing-object-evidence", "缺失 Object Export 对象/文件证据")
	}
	if weakPortOnly {
		out = append(out, model.APTScoreFactor{Name: "port-only-weak-observation", Weight: -2, Direction: "negative", SourceModule: "profile", Summary: "仅有端口观察，不能强归因"})
	}
	return out
}

func aptScoreFactorNames(record model.APTEvidenceRecord) []string {
	out := make([]string, 0, len(record.ScoreFactors))
	for _, factor := range record.ScoreFactors {
		out = append(out, factor.Name)
	}
	return out
}
