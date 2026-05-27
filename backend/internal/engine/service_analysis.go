package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/tshark"
)

type analysisCacheInput[T any] struct {
	getCached func() *T
	setCached func(*T)
	builder   func(pcap string) (T, error)
}

func cachedAnalysis[T any](ctx context.Context, mu *sync.RWMutex, pcap string, input analysisCacheInput[T]) (T, error) {
	var zero T
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}

	mu.RLock()
	cached := input.getCached()
	currentPCAP := pcap
	mu.RUnlock()

	if cached != nil {
		return *cached, nil
	}
	if strings.TrimSpace(currentPCAP) == "" {
		return zero, errors.New("no capture loaded")
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}

	result, err := input.builder(currentPCAP)
	if err != nil {
		return zero, err
	}

	mu.Lock()
	if input.getCached() == nil {
		input.setCached(&result)
	}
	out := *input.getCached()
	mu.Unlock()
	return out, nil
}

func (s *Service) GlobalTrafficStats() (model.GlobalTrafficStats, error) {
	return s.GlobalTrafficStatsWithContext(context.Background())
}

func (s *Service) GlobalTrafficStatsWithContext(ctx context.Context) (model.GlobalTrafficStats, error) {
	return cachedAnalysis(ctx, &s.mu, s.pcap, analysisCacheInput[model.GlobalTrafficStats]{
		getCached: func() *model.GlobalTrafficStats { return s.globalTrafficStats },
		setCached: func(v *model.GlobalTrafficStats) { s.globalTrafficStats = v },
		builder:   tshark.BuildGlobalTrafficStatsFromFile,
	})
}

func (s *Service) IndustrialAnalysis() (model.IndustrialAnalysis, error) {
	return s.IndustrialAnalysisWithContext(context.Background())
}

func (s *Service) IndustrialAnalysisWithContext(ctx context.Context) (model.IndustrialAnalysis, error) {
	return cachedAnalysis(ctx, &s.mu, s.pcap, analysisCacheInput[model.IndustrialAnalysis]{
		getCached: func() *model.IndustrialAnalysis { return s.industrialAnalysis },
		setCached: func(v *model.IndustrialAnalysis) { s.industrialAnalysis = v },
		builder: func(pcap string) (model.IndustrialAnalysis, error) {
			if err := tshark.WarmSpecializedFieldCache(pcap); err != nil {
				log.Printf("engine: specialized field cache warm failed for industrial analysis: %v", err)
			}
			analysis, err := tshark.BuildIndustrialAnalysisFromFile(pcap)
			if err != nil {
				return analysis, err
			}
			analysis.Report = buildIndustrialInvestigationReport(analysis)
			return analysis, nil
		},
	})
}

func (s *Service) VehicleAnalysis() (model.VehicleAnalysis, error) {
	return s.VehicleAnalysisWithContext(context.Background())
}

func (s *Service) VehicleAnalysisWithContext(ctx context.Context) (model.VehicleAnalysis, error) {
	return cachedAnalysis(ctx, &s.mu, s.pcap, analysisCacheInput[model.VehicleAnalysis]{
		getCached: func() *model.VehicleAnalysis { return s.vehicleAnalysis },
		setCached: func(v *model.VehicleAnalysis) { s.vehicleAnalysis = v },
		builder: func(pcap string) (model.VehicleAnalysis, error) {
			if err := tshark.WarmSpecializedFieldCache(pcap); err != nil {
				log.Printf("engine: specialized field cache warm failed for vehicle analysis: %v", err)
			}
			s.mu.RLock()
			dbcDefs := append([]*tshark.DBCDatabase(nil), s.vehicleDBCDefs...)
			s.mu.RUnlock()

			analysis, err := tshark.BuildVehicleAnalysisFromFile(pcap, dbcDefs...)
			if err != nil {
				return analysis, err
			}
			analysis.Report = buildVehicleInvestigationReport(analysis)
			return analysis, nil
		},
	})
}

func (s *Service) MediaAnalysis() (model.MediaAnalysis, error) {
	return s.mediaAnalysisWithForce(false)
}

func (s *Service) RefreshMediaAnalysis() (model.MediaAnalysis, error) {
	return s.mediaAnalysisWithForce(true)
}

func (s *Service) mediaAnalysisWithForce(force bool) (model.MediaAnalysis, error) {
	s.mu.RLock()
	pcap := s.pcap
	cached := s.mediaAnalysis
	s.mu.RUnlock()

	if !force && cached != nil {
		return *cached, nil
	}
	if strings.TrimSpace(pcap) == "" {
		return model.MediaAnalysis{}, errors.New("no capture loaded")
	}
	s.emitStatus("__progress__:media:0:3:准备媒体流分析")
	cfg := s.buildMediaScanConfig(pcap)

	tempDir, err := os.MkdirTemp("", "gshark-media-")
	if err != nil {
		s.emitStatus("媒体流分析失败: " + err.Error())
		return model.MediaAnalysis{}, err
	}

	progressFn := func(current, total int, label string) {
		s.emitStatus(fmt.Sprintf("__progress__:media:%d:%d:%s", current, total, label))
	}

	var (
		analysis  model.MediaAnalysis
		artifacts map[string]string
	)

	if s.packetStore != nil && s.packetStore.Count() > 0 {
		packetCount := s.packetStore.Count()
		analysis, artifacts, err = tshark.BuildMediaAnalysisFromPacketStream(tempDir, packetCount, cfg, progressFn, func(onPacket func(model.Packet) error) error {
			return s.packetStore.Iterate(nil, onPacket)
		})
		if err != nil {
			log.Printf("engine: media analysis packet-store fast path failed, falling back to tshark file scan: %v", err)
		} else if analysis.TotalMediaPackets > 0 || len(analysis.Sessions) > 0 {
			log.Printf("engine: media analysis completed via packet-store fast path packets=%d sessions=%d", analysis.TotalMediaPackets, len(analysis.Sessions))
		} else {
			log.Printf("engine: media analysis packet-store fast path found no sessions, falling back to tshark file scan")
			err = nil
		}
	}

	if err == nil && analysis.TotalMediaPackets == 0 && len(analysis.Sessions) == 0 {
		analysis, artifacts, err = tshark.BuildMediaAnalysisFromFileWithConfig(pcap, tempDir, cfg, progressFn)
	}
	if err != nil {
		_ = os.RemoveAll(tempDir)
		s.emitStatus("媒体流分析失败: " + err.Error())
		return model.MediaAnalysis{}, err
	}

	s.mu.Lock()
	if force {
		if s.mediaExportDir != "" && s.mediaExportDir != tempDir {
			_ = os.RemoveAll(s.mediaExportDir)
		}
		s.mediaAnalysis = &analysis
		s.mediaExportDir = tempDir
		s.mediaArtifacts = artifacts
		s.mediaPlayback = map[string]string{}
		s.mediaSpeech = map[string]model.MediaTranscription{}
		s.cancelSpeechBatchLocked()
		s.speechBatch = nil
	} else if s.mediaAnalysis == nil {
		if s.mediaExportDir != "" && s.mediaExportDir != tempDir {
			_ = os.RemoveAll(s.mediaExportDir)
		}
		s.mediaAnalysis = &analysis
		s.mediaExportDir = tempDir
		s.mediaArtifacts = artifacts
		s.mediaPlayback = map[string]string{}
		s.mediaSpeech = map[string]model.MediaTranscription{}
		s.cancelSpeechBatchLocked()
		s.speechBatch = nil
	} else {
		_ = os.RemoveAll(tempDir)
	}
	out := *s.mediaAnalysis
	s.mu.Unlock()
	s.emitStatus("媒体流分析完成")
	return out, nil
}

func (s *Service) buildMediaScanConfig(pcap string) tshark.MediaScanConfig {
	cfg := tshark.MediaScanConfig{}
	if s.packetStore == nil || strings.TrimSpace(pcap) == "" {
		return cfg
	}

	candidatePorts, err := s.packetStore.TopUDPDestinationPorts(10, 32)
	if err != nil {
		log.Printf("engine: media preflight failed to query udp ports: %v", err)
		return cfg
	}
	if len(candidatePorts) == 0 {
		return cfg
	}

	decodeAsPorts, err := tshark.DetectLikelyRTPPorts(pcap, candidatePorts, 24)
	if err != nil {
		log.Printf("engine: media preflight failed to detect rtp-like ports: %v", err)
		return cfg
	}
	if len(decodeAsPorts) == 0 {
		return cfg
	}

	cfg.RTPDecodeAsPorts = decodeAsPorts
	cfg.PreflightNotes = append(cfg.PreflightNotes, fmt.Sprintf("预探测发现 RTP-like UDP 端口：%s。", formatPortList(decodeAsPorts)))
	if onlyNonStandardRTPPorts(decodeAsPorts) {
		cfg.SkipControlHints = true
		cfg.PreflightNotes = append(cfg.PreflightNotes, "检测到媒体流位于非标准 RTP 端口，已跳过全量 RTSP/SDP 控制信令扫描以避免大包阻塞。")
	}
	log.Printf("engine: media preflight config skip_control=%t decode_as_ports=%v", cfg.SkipControlHints, cfg.RTPDecodeAsPorts)
	return cfg
}

func onlyNonStandardRTPPorts(ports []int) bool {
	if len(ports) == 0 {
		return false
	}

	known := map[int]struct{}{
		554:   {},
		8554:  {},
		5004:  {},
		5005:  {},
		6970:  {},
		7070:  {},
		47984: {},
		47989: {},
		47990: {},
		47998: {},
		47999: {},
		48000: {},
		48002: {},
		48010: {},
	}

	for _, port := range ports {
		if _, ok := known[port]; ok {
			return false
		}
	}
	return true
}

func formatPortList(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	items := make([]string, 0, len(ports))
	for _, port := range ports {
		items = append(items, strconv.Itoa(port))
	}
	return strings.Join(items, ", ")
}

func (s *Service) USBAnalysis() (model.USBAnalysis, error) {
	return s.USBAnalysisWithContext(context.Background())
}

func (s *Service) USBAnalysisWithContext(ctx context.Context) (model.USBAnalysis, error) {
	return s.USBAnalysisWithOptions(ctx, model.USBAnalysisOptions{})
}

func (s *Service) USBAnalysisWithOptions(ctx context.Context, opts model.USBAnalysisOptions) (model.USBAnalysis, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return model.USBAnalysis{}, err
	}
	mode, ok := model.NormalizeUSBHIDSourceMode(string(opts.HIDSourceMode))
	if !ok {
		mode = model.USBHIDSourceAuto
	}
	hidEventLimit := model.NormalizeUSBHIDEventLimit(opts.HIDEventLimit)
	cacheKey := usbAnalysisCacheKey(mode, hidEventLimit)
	defaultCacheKey := usbAnalysisCacheKey(model.USBHIDSourceAuto, model.DefaultUSBHIDEventLimit)
	s.mu.RLock()
	pcap := s.pcap
	var cached *model.USBAnalysis
	if cacheKey == defaultCacheKey {
		cached = s.usbAnalysis
	}
	if cached == nil && s.usbAnalysisBySource != nil {
		cached = s.usbAnalysisBySource[cacheKey]
	}
	s.mu.RUnlock()

	if cached != nil {
		return *cached, nil
	}
	if strings.TrimSpace(pcap) == "" {
		return model.USBAnalysis{}, errors.New("no capture loaded")
	}
	if err := ctx.Err(); err != nil {
		return model.USBAnalysis{}, err
	}

	analysis, err := tshark.BuildUSBAnalysisFromFileWithOptions(pcap, model.USBAnalysisOptions{HIDSourceMode: mode, HIDEventLimit: hidEventLimit})
	if err != nil {
		return model.USBAnalysis{}, err
	}
	analysis.Report = buildUSBInvestigationReport(analysis)

	s.mu.Lock()
	if s.pcap != pcap {
		s.mu.Unlock()
		return model.USBAnalysis{}, context.Canceled
	}
	if s.usbAnalysisBySource == nil {
		s.usbAnalysisBySource = make(map[string]*model.USBAnalysis)
	}
	if s.usbAnalysisBySource[cacheKey] == nil {
		s.usbAnalysisBySource[cacheKey] = &analysis
	}
	if cacheKey == defaultCacheKey && s.usbAnalysis == nil {
		s.usbAnalysis = &analysis
	}
	out := analysis
	if cacheKey == defaultCacheKey && s.usbAnalysis != nil {
		out = *s.usbAnalysis
	} else if s.usbAnalysisBySource[cacheKey] != nil {
		out = *s.usbAnalysisBySource[cacheKey]
	}
	s.mu.Unlock()
	return out, nil
}

func usbAnalysisCacheKey(mode model.USBHIDSourceMode, hidEventLimit int) string {
	return fmt.Sprintf("source=%s;hid_event_limit=%d", mode, model.NormalizeUSBHIDEventLimit(hidEventLimit))
}

func (s *Service) C2SampleAnalysis(ctx context.Context) (model.C2SampleAnalysis, error) {
	if err := ctx.Err(); err != nil {
		return model.C2SampleAnalysis{}, err
	}

	s.mu.RLock()
	cached := s.c2Analysis
	pcap := strings.TrimSpace(s.pcap)
	s.mu.RUnlock()

	if cached != nil {
		return *cached, nil
	}

	var analysis model.C2SampleAnalysis
	if pcap == "" {
		analysis = emptyC2SampleAnalysis()
		analysis.Notes = append(analysis.Notes, "当前未加载抓包，C2 分析暂未形成候选证据。")
	} else {
		if s.packetStore == nil {
			return model.C2SampleAnalysis{}, errors.New("当前抓包尚未建立本地数据包索引")
		}
		packets, err := s.packetStore.All(nil)
		if err != nil {
			return model.C2SampleAnalysis{}, err
		}
		analysis, err = buildC2SampleAnalysisFromPackets(ctx, packets)
		if err != nil {
			return model.C2SampleAnalysis{}, err
		}
		analysis.Notes = append(analysis.Notes,
			"当前版本已接入 CS / VShell 第一版可观测流量规则；结果仍按\u201c候选证据\u201d处理，静态端口/路径不会单独定性。",
			"Silver Fox / 银狐相关字段已预埋为归因扩展口，后续独立 APT 页面可复用这里的技术证据。",
		)
	}

	if err := ctx.Err(); err != nil {
		return model.C2SampleAnalysis{}, err
	}
	analysis.CS.Report = buildC2FamilyInvestigationReport("cs", analysis.CS)
	analysis.VShell.Report = buildC2FamilyInvestigationReport("vshell", analysis.VShell)

	s.mu.Lock()
	if s.c2Analysis == nil {
		s.c2Analysis = &analysis
	}
	out := *s.c2Analysis
	s.mu.Unlock()
	return out, nil
}

func emptyC2SampleAnalysis() model.C2SampleAnalysis {
	return model.C2SampleAnalysis{
		TotalMatchedPackets: 0,
		Families:            []model.TrafficBucket{},
		Conversations:       []model.AnalysisConversation{},
		CS: model.C2FamilyAnalysis{
			CandidateCount:   0,
			MatchedRuleCount: 0,
			Channels:         []model.TrafficBucket{},
			Indicators:       []model.TrafficBucket{},
			Conversations:    []model.AnalysisConversation{},
			BeaconPatterns:   []model.C2BeaconPattern{},
			Candidates:       []model.C2IndicatorRecord{},
			Notes:            []string{},
			RelatedActors:    []model.TrafficBucket{},
			DeliveryChains:   []model.TrafficBucket{},
			Report:           emptyInvestigationReport(),
		},
		VShell: model.C2FamilyAnalysis{
			CandidateCount:   0,
			MatchedRuleCount: 0,
			Channels:         []model.TrafficBucket{},
			Indicators:       []model.TrafficBucket{},
			Conversations:    []model.AnalysisConversation{},
			BeaconPatterns:   []model.C2BeaconPattern{},
			Candidates:       []model.C2IndicatorRecord{},
			Notes:            []string{},
			RelatedActors:    []model.TrafficBucket{},
			DeliveryChains:   []model.TrafficBucket{},
			Report:           emptyInvestigationReport(),
		},
		Notes: []string{},
	}
}

func (s *Service) APTAnalysis(ctx context.Context) (model.APTAnalysis, error) {
	if err := ctx.Err(); err != nil {
		return model.APTAnalysis{}, err
	}

	s.mu.RLock()
	cached := s.aptAnalysis
	pcap := strings.TrimSpace(s.pcap)
	s.mu.RUnlock()

	if cached != nil {
		return *cached, nil
	}

	analysis := emptyAPTAnalysis()
	if pcap == "" {
		analysis.Notes = append(analysis.Notes, "当前未加载抓包，APT 组织画像暂未形成可评分证据，仅展示框架画像与待验证证据需求。")
	} else {
		c2, err := s.C2SampleAnalysis(ctx)
		if err != nil {
			return model.APTAnalysis{}, err
		}
		analysis = buildAPTAnalysisFromC2(c2)
		threatHits := s.ThreatHuntWithContext(ctx, nil)
		if len(threatHits) > 0 {
			analysis = buildAPTAnalysisFromThreatHits(threatHits, analysis)
		}
		objects := s.ObjectsWithContext(ctx)
		if len(objects) > 0 {
			analysis = buildAPTAnalysisFromObjects(objects, analysis)
		}
		analysis.Notes = append(analysis.Notes,
			"APT 页消费 C2、Threat Hunting 与 Object Export 三个模块的证据。",
			"Silver Fox / 银狐作为首个预置 actor profile；ValleyRAT、Winos 4.0、Gh0st 系、HFS 下载链与 fallback C2 作为后续规则接入口。",
		)
	}
	analysis = finalizeAPTAnalysis(analysis)

	if err := ctx.Err(); err != nil {
		return model.APTAnalysis{}, err
	}

	s.mu.Lock()
	if s.aptAnalysis == nil {
		s.aptAnalysis = &analysis
	}
	out := *s.aptAnalysis
	s.mu.Unlock()
	return out, nil
}

func emptyAPTAnalysis() model.APTAnalysis {
	return model.APTAnalysis{
		TotalEvidence:       0,
		Actors:              []model.TrafficBucket{},
		SampleFamilies:      []model.TrafficBucket{},
		CampaignStages:      []model.TrafficBucket{},
		TransportTraits:     []model.TrafficBucket{},
		InfrastructureHints: []model.TrafficBucket{},
		RelatedC2Families:   []model.TrafficBucket{},
		Profiles: []model.APTActorProfile{
			emptySilverFoxProfile(),
		},
		Evidence: []model.APTEvidenceRecord{},
		Notes:    []string{},
	}
}

func emptySilverFoxProfile() model.APTActorProfile {
	return model.APTActorProfile{
		ID:            "silver-fox",
		Name:          "Silver Fox / 银狐",
		Aliases:       []string{"Swimming Snake", "银狐", "Silver Fox"},
		Summary:       "预置 APT 框架画像：用于承载 ValleyRAT / Winos 4.0 / Gh0st 系、HFS 下载链、HTTPS/TCP C2、fallback C2 与周期回连等后续证据。",
		Confidence:    0,
		EvidenceCount: 0,
		SampleFamilies: []model.TrafficBucket{
			{Label: "ValleyRAT", Count: 0},
			{Label: "Winos 4.0", Count: 0},
			{Label: "Gh0st variant", Count: 0},
		},
		CampaignStages: []model.TrafficBucket{
			{Label: "delivery", Count: 0},
			{Label: "downloader", Count: 0},
			{Label: "rat-c2", Count: 0},
		},
		TransportTraits: []model.TrafficBucket{
			{Label: "https-c2", Count: 0},
			{Label: "tcp-long-connection", Count: 0},
			{Label: "periodic-callback", Count: 0},
		},
		InfrastructureHints: []model.TrafficBucket{
			{Label: "hfs-download-chain", Count: 0},
			{Label: "fallback-c2", Count: 0},
			{Label: "custom-high-port", Count: 0},
		},
		RelatedC2Families: []model.TrafficBucket{},
		TTPTags: []model.TrafficBucket{
			{Label: "multi-stage-delivery", Count: 0},
			{Label: "encrypted-c2", Count: 0},
			{Label: "rat-family", Count: 0},
		},
		Notes: []string{
			"组织画像默认不直接等同于样本家族；只有流量侧证据、样本解析证据与投递链证据交叉后才应提升归因置信度。",
			"端口、路径、单个 IOC 仅作为弱观察位，不能单独作为 Silver Fox 归因结论。",
		},
	}
}

func buildAPTAnalysisFromC2(c2 model.C2SampleAnalysis) model.APTAnalysis {
	analysis := emptyAPTAnalysis()
	actorCounts := map[string]int{}
	sampleFamilies := map[string]int{}
	campaignStages := map[string]int{}
	transportTraits := map[string]int{}
	infrastructureHints := map[string]int{}
	relatedC2Families := map[string]int{}
	ttpTags := map[string]int{}
	profiles := map[string]*model.APTActorProfile{
		"silver-fox": cloneAPTActorProfile(emptySilverFoxProfile()),
	}

	consume := func(records []model.C2IndicatorRecord) {
		for _, item := range records {
			actors := normalizeActorHints(item.ActorHints, item.SampleFamily)
			if len(actors) == 0 {
				continue
			}
			for _, actorName := range actors {
				actorID := aptActorID(actorName)
				profile := profiles[actorID]
				if profile == nil {
					profile = &model.APTActorProfile{
						ID:                  actorID,
						Name:                actorName,
						Aliases:             []string{},
						Summary:             "由 C2 技术证据临时聚合出的 APT 候选画像，仍需人工复核。",
						SampleFamilies:      []model.TrafficBucket{},
						CampaignStages:      []model.TrafficBucket{},
						TransportTraits:     []model.TrafficBucket{},
						InfrastructureHints: []model.TrafficBucket{},
						RelatedC2Families:   []model.TrafficBucket{},
						TTPTags:             []model.TrafficBucket{},
						Notes:               []string{"临时 actor hint：尚未接入正式组织画像基线。"},
					}
					profiles[actorID] = profile
				}
				actorCounts[profile.Name]++
				profile.EvidenceCount++
				if item.Confidence > profile.Confidence {
					profile.Confidence = item.Confidence
				}
				if item.SampleFamily != "" {
					sampleFamilies[item.SampleFamily]++
				}
				if item.CampaignStage != "" {
					campaignStages[item.CampaignStage]++
				}
				for _, value := range item.TransportTraits {
					if strings.TrimSpace(value) != "" {
						transportTraits[value]++
					}
				}
				for _, value := range item.InfrastructureHints {
					if strings.TrimSpace(value) != "" {
						infrastructureHints[value]++
					}
				}
				if item.Family != "" {
					relatedC2Families[item.Family]++
				}
				for _, value := range item.TTPTags {
					if strings.TrimSpace(value) != "" {
						ttpTags[value]++
					}
				}
				record := model.APTEvidenceRecord{
					PacketID:            item.PacketID,
					StreamID:            item.StreamID,
					Time:                item.Time,
					ActorID:             profile.ID,
					ActorName:           profile.Name,
					SourceModule:        "c2-analysis",
					Family:              item.Family,
					EvidenceType:        c2FirstNonEmpty(item.IndicatorType, "c2-indicator"),
					EvidenceValue:       item.IndicatorValue,
					Confidence:          item.Confidence,
					Source:              item.Source,
					Destination:         item.Destination,
					Host:                item.Host,
					URI:                 item.URI,
					SampleFamily:        item.SampleFamily,
					CampaignStage:       item.CampaignStage,
					TransportTraits:     item.TransportTraits,
					InfrastructureHints: item.InfrastructureHints,
					TTPTags:             item.TTPTags,
					Tags:                item.Tags,
					Summary:             item.Summary,
					Evidence:            item.Evidence,
				}
				record.ScoreFactors = aptScoreFactorsForRecord(record)
				analysis.Evidence = append(analysis.Evidence, record)
			}
		}
	}
	consume(c2.CS.Candidates)
	consume(c2.VShell.Candidates)

	for _, profile := range profiles {
		profile.SampleFamilies = mergeAPTProfileBuckets(profile.SampleFamilies, sampleFamilies)
		profile.CampaignStages = mergeAPTProfileBuckets(profile.CampaignStages, campaignStages)
		profile.TransportTraits = mergeAPTProfileBuckets(profile.TransportTraits, transportTraits)
		profile.InfrastructureHints = mergeAPTProfileBuckets(profile.InfrastructureHints, infrastructureHints)
		profile.RelatedC2Families = mergeAPTProfileBuckets(profile.RelatedC2Families, relatedC2Families)
		profile.TTPTags = mergeAPTProfileBuckets(profile.TTPTags, ttpTags)
		analysis.Profiles = appendOrReplaceAPTProfile(analysis.Profiles, *profile)
	}
	sort.SliceStable(analysis.Profiles, func(i, j int) bool {
		if analysis.Profiles[i].EvidenceCount == analysis.Profiles[j].EvidenceCount {
			return analysis.Profiles[i].Name < analysis.Profiles[j].Name
		}
		return analysis.Profiles[i].EvidenceCount > analysis.Profiles[j].EvidenceCount
	})

	analysis.TotalEvidence = len(analysis.Evidence)
	analysis.Actors = bucketsFromMap(actorCounts, 16)
	analysis.SampleFamilies = bucketsFromMap(sampleFamilies, 24)
	analysis.CampaignStages = bucketsFromMap(campaignStages, 24)
	analysis.TransportTraits = bucketsFromMap(transportTraits, 24)
	analysis.InfrastructureHints = bucketsFromMap(infrastructureHints, 24)
	analysis.RelatedC2Families = bucketsFromMap(relatedC2Families, 12)
	return analysis
}

func cloneAPTActorProfile(profile model.APTActorProfile) *model.APTActorProfile {
	out := profile
	return &out
}

func normalizeActorHints(hints []string, sampleFamily string) []string {
	values := make([]string, 0, len(hints)+1)
	for _, hint := range hints {
		if trimmed := strings.TrimSpace(hint); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	family := strings.ToLower(strings.TrimSpace(sampleFamily))
	if family == "valleyrat" || strings.Contains(family, "winos") || strings.Contains(family, "gh0st") {
		values = append(values, "Silver Fox / 银狐")
	}
	return uniqueStrings(values)
}

func aptActorID(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if strings.Contains(lower, "silver") || strings.Contains(name, "银狐") || strings.Contains(lower, "swimming snake") {
		return "silver-fox"
	}
	replacer := strings.NewReplacer(" ", "-", "/", "-", "\\", "-", "_", "-", "：", "-", ":", "-", "(", "", ")", "")
	id := strings.Trim(replacer.Replace(lower), "-")
	if id == "" {
		return "unknown-actor"
	}
	return id
}

func mergeAPTProfileBuckets(base []model.TrafficBucket, counts map[string]int) []model.TrafficBucket {
	merged := map[string]int{}
	for _, item := range base {
		if strings.TrimSpace(item.Label) != "" {
			merged[item.Label] += item.Count
		}
	}
	for label, count := range counts {
		if strings.TrimSpace(label) != "" {
			merged[label] += count
		}
	}
	return bucketsFromMap(merged, 24)
}

func appendOrReplaceAPTProfile(items []model.APTActorProfile, next model.APTActorProfile) []model.APTActorProfile {
	for i := range items {
		if items[i].ID == next.ID {
			items[i] = next
			return items
		}
	}
	return append(items, next)
}

func (s *Service) MediaArtifact(token string) (string, string, error) {
	s.mu.RLock()
	path := s.mediaArtifacts[token]
	analysis := s.mediaAnalysis
	s.mu.RUnlock()

	if strings.TrimSpace(path) == "" {
		return "", "", errors.New("media artifact not found")
	}

	name := filepath.Base(path)
	if analysis != nil {
		for _, session := range analysis.Sessions {
			if session.Artifact != nil && session.Artifact.Token == token && strings.TrimSpace(session.Artifact.Name) != "" {
				name = session.Artifact.Name
				break
			}
		}
	}

	return path, name, nil
}

func (s *Service) VehicleDBCProfiles() []model.DBCProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return buildDBCProfilesForService(s.vehicleDBCDefs)
}

func (s *Service) AddVehicleDBC(path string) ([]model.DBCProfile, error) {
	db, err := tshark.LoadDBCDatabase(path)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cleanPath := filepath.Clean(strings.TrimSpace(path))
	for _, existing := range s.vehicleDBCDefs {
		if existing != nil && strings.EqualFold(existing.Path, cleanPath) {
			return buildDBCProfilesForService(s.vehicleDBCDefs), nil
		}
	}

	s.vehicleDBCDefs = append(s.vehicleDBCDefs, db)
	s.vehicleAnalysis = nil
	return buildDBCProfilesForService(s.vehicleDBCDefs), nil
}

func (s *Service) RemoveVehicleDBC(path string) []model.DBCProfile {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	s.mu.Lock()
	defer s.mu.Unlock()

	filtered := s.vehicleDBCDefs[:0]
	for _, db := range s.vehicleDBCDefs {
		if db == nil || strings.EqualFold(db.Path, cleanPath) {
			continue
		}
		filtered = append(filtered, db)
	}
	s.vehicleDBCDefs = filtered
	s.vehicleAnalysis = nil
	return buildDBCProfilesForService(s.vehicleDBCDefs)
}

func buildDBCProfilesForService(databases []*tshark.DBCDatabase) []model.DBCProfile {
	if len(databases) == 0 {
		return nil
	}
	out := make([]model.DBCProfile, 0, len(databases))
	for _, db := range databases {
		if db == nil {
			continue
		}
		out = append(out, db.Profile())
	}
	return out
}
