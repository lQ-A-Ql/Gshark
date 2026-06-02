package engine

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

var (
	bruteforceHTTPRequestRE  = regexp.MustCompile(`^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)`)
	bruteforceHTTPResponseRE = regexp.MustCompile(`(?i)^HTTP/\S+\s+(\d{3})`)
)

func (s *Service) BruteforceAnalysis(ctx context.Context) (model.BruteforceAnalysis, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.CurrentCapturePath() == "" {
		return model.BruteforceAnalysis{}, fmt.Errorf("当前未加载抓包，请先导入 pcapng 文件")
	}
	if s.packetStore == nil {
		return model.BruteforceAnalysis{}, fmt.Errorf("当前抓包尚未建立本地数据包索引")
	}
	packets, err := s.packetStore.All(nil)
	if err != nil {
		return model.BruteforceAnalysis{}, err
	}
	return buildBruteforceAnalysis(ctx, packets)
}

type portScanKey struct {
	src string
	dst string
}

type portScanGroup struct {
	key         portScanKey
	ports       map[int]struct{}
	synCount    int
	rstCount    int
	totalCount  int
	openPorts   map[int]struct{}
	firstPacket int64
	firstTime   string
	lastTime    string
}

type dirBruteKey struct {
	src  string
	host string
}

type dirBruteGroup struct {
	key            dirBruteKey
	totalRequests  int
	status404Count int
	status403Count int
	status200Count int
	paths          map[string]struct{}
	samplePaths    []string
	firstPacket    int64
	firstTime      string
	lastTime       string
}

func buildBruteforceAnalysis(ctx context.Context, packets []model.Packet) (model.BruteforceAnalysis, error) {
	result := model.BruteforceAnalysis{
		PortScanHits:      []model.PortScanCandidate{},
		DirBruteforceHits: []model.DirBruteforceCandidate{},
		Notes:             []string{},
	}

	portScans := make(map[portScanKey]*portScanGroup)
	dirBrutes := make(map[dirBruteKey]*dirBruteGroup)

	// Track pending HTTP requests for response matching
	type httpReqPending struct {
		key  dirBruteKey
		path string
	}
	pendingHTTP := make(map[int64][]httpReqPending) // streamID -> pending requests

	for _, packet := range packets {
		if err := ctx.Err(); err != nil {
			return model.BruteforceAnalysis{}, err
		}

		proto := strings.ToUpper(packet.Protocol)

		// Port scan detection: TCP packets
		if strings.Contains(proto, "TCP") || packet.Color.TCPSYN || packet.Color.TCPRST {
			if packet.SourceIP == "" || packet.DestIP == "" {
				continue
			}
			key := portScanKey{src: packet.SourceIP, dst: packet.DestIP}
			group := portScans[key]
			if group == nil {
				group = &portScanGroup{
					key:         key,
					ports:       make(map[int]struct{}),
					openPorts:   make(map[int]struct{}),
					firstPacket: packet.ID,
					firstTime:   packet.Timestamp,
				}
				portScans[key] = group
			}
			group.totalCount++
			group.lastTime = packet.Timestamp
			if packet.DestPort > 0 {
				group.ports[packet.DestPort] = struct{}{}
			}

			isSYN := packet.Color.TCPSYN || strings.Contains(packet.Info, "[SYN]")
			isRST := packet.Color.TCPRST || strings.Contains(packet.Info, "[RST]")
			isSYNACK := strings.Contains(packet.Info, "[SYN, ACK]")

			if isSYN && !isSYNACK {
				group.synCount++
			}
			if isRST {
				group.rstCount++
			}
			// Track open ports from SYN-ACK responses (reverse direction)
			if isSYNACK {
				reverseKey := portScanKey{src: packet.DestIP, dst: packet.SourceIP}
				if reverseGroup := portScans[reverseKey]; reverseGroup != nil {
					reverseGroup.openPorts[packet.SourcePort] = struct{}{}
				}
			}
		}

		// Directory bruteforce detection: HTTP packets
		if isHTTPLikePacket(packet) {
			path := extractBruteforceHTTPRequestPath(packet.Info)
			if path != "" {
				host := packet.DestIP
				if packet.DestPort != 80 && packet.DestPort != 443 && packet.DestPort > 0 {
					host = fmt.Sprintf("%s:%d", packet.DestIP, packet.DestPort)
				}
				key := dirBruteKey{src: packet.SourceIP, host: host}
				group := dirBrutes[key]
				if group == nil {
					group = &dirBruteGroup{
						key:         key,
						paths:       make(map[string]struct{}),
						samplePaths: make([]string, 0, 10),
						firstPacket: packet.ID,
						firstTime:   packet.Timestamp,
					}
					dirBrutes[key] = group
				}
				group.totalRequests++
				group.lastTime = packet.Timestamp
				if _, exists := group.paths[path]; !exists {
					group.paths[path] = struct{}{}
					if len(group.samplePaths) < 10 {
						group.samplePaths = append(group.samplePaths, path)
					}
				}
				pendingHTTP[packet.StreamID] = append(pendingHTTP[packet.StreamID], httpReqPending{key: key, path: path})
				continue
			}

			// Check for HTTP response
			statusCode := extractBruteforceHTTPResponseStatus(packet.Info)
			if statusCode > 0 {
				queue := pendingHTTP[packet.StreamID]
				if len(queue) > 0 {
					pending := queue[0]
					pendingHTTP[packet.StreamID] = queue[1:]
					if group := dirBrutes[pending.key]; group != nil {
						switch statusCode {
						case 404:
							group.status404Count++
						case 403:
							group.status403Count++
						case 200:
							group.status200Count++
						}
					}
				}
			}
		}
	}

	// Analyze port scan groups
	for _, group := range portScans {
		uniquePorts := len(group.ports)
		if uniquePorts <= 20 {
			continue
		}
		if group.totalCount == 0 {
			continue
		}
		synRatio := float64(group.synCount) / float64(group.totalCount)
		rstRatio := float64(group.rstCount) / float64(group.synCount+1)

		flagged := synRatio > 0.5 || rstRatio > 0.7
		if !flagged {
			continue
		}

		confidence := 50
		if uniquePorts > 100 {
			confidence = 90
		} else if uniquePorts > 50 {
			confidence = 70
		}

		scanType := "connect-scan"
		if synRatio > 0.7 && group.rstCount > group.synCount/2 {
			scanType = "syn-scan"
		}

		openPortsList := make([]int, 0, len(group.openPorts))
		for p := range group.openPorts {
			openPortsList = append(openPortsList, p)
		}
		sort.Ints(openPortsList)

		duration := estimateDurationSec(group.firstTime, group.lastTime)

		result.PortScanHits = append(result.PortScanHits, model.PortScanCandidate{
			SourceIP:       group.key.src,
			TargetIP:       group.key.dst,
			UniquePortsHit: uniquePorts,
			SynCount:       group.synCount,
			RstCount:       group.rstCount,
			OpenPorts:      openPortsList,
			DurationSec:    duration,
			ScanType:       scanType,
			Confidence:     confidence,
			FirstPacketID:  group.firstPacket,
		})
	}

	// Analyze directory bruteforce groups
	for _, group := range dirBrutes {
		if group.totalRequests <= 30 {
			continue
		}
		failCount := group.status404Count + group.status403Count
		totalResponses := failCount + group.status200Count
		if totalResponses == 0 {
			continue
		}
		failRatio := float64(failCount) / float64(totalResponses)
		if failRatio < 0.7 {
			continue
		}

		duration := estimateDurationSec(group.firstTime, group.lastTime)
		var requestsPerSec float64
		if duration > 0 {
			requestsPerSec = float64(group.totalRequests) / duration
		}
		if requestsPerSec < 3 && duration > 0 {
			continue
		}

		confidence := 60
		if group.totalRequests > 100 && failRatio > 0.8 {
			confidence = 90
		} else if group.totalRequests > 50 {
			confidence = 75
		}

		result.DirBruteforceHits = append(result.DirBruteforceHits, model.DirBruteforceCandidate{
			SourceIP:       group.key.src,
			TargetHost:     group.key.host,
			TotalRequests:  group.totalRequests,
			Status404Count: group.status404Count,
			Status403Count: group.status403Count,
			Status200Count: group.status200Count,
			UniquePaths:    len(group.paths),
			RequestsPerSec: requestsPerSec,
			SamplePaths:    group.samplePaths,
			Confidence:     confidence,
			FirstPacketID:  group.firstPacket,
		})
	}

	// Sort by confidence descending
	sort.SliceStable(result.PortScanHits, func(i, j int) bool {
		return result.PortScanHits[i].Confidence > result.PortScanHits[j].Confidence
	})
	sort.SliceStable(result.DirBruteforceHits, func(i, j int) bool {
		return result.DirBruteforceHits[i].Confidence > result.DirBruteforceHits[j].Confidence
	})

	result.TotalSuspicious = len(result.PortScanHits) + len(result.DirBruteforceHits)
	result.Notes = buildBruteforceNotes(result)
	return result, nil
}

func extractBruteforceHTTPRequestPath(info string) string {
	matches := bruteforceHTTPRequestRE.FindStringSubmatch(strings.TrimSpace(info))
	if len(matches) < 3 {
		return ""
	}
	return matches[2]
}

func extractBruteforceHTTPResponseStatus(info string) int {
	matches := bruteforceHTTPResponseRE.FindStringSubmatch(strings.TrimSpace(info))
	if len(matches) < 2 {
		return 0
	}
	code, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0
	}
	return code
}

func buildBruteforceNotes(result model.BruteforceAnalysis) []string {
	notes := make([]string, 0, 4)
	if result.TotalSuspicious == 0 {
		return []string{"当前抓包中未识别到明显的端口扫描或目录爆破行为。"}
	}
	if len(result.PortScanHits) > 0 {
		notes = append(notes, fmt.Sprintf("发现 %d 个疑似端口扫描行为，建议检查源 IP 和目标端口范围。", len(result.PortScanHits)))
	}
	if len(result.DirBruteforceHits) > 0 {
		notes = append(notes, fmt.Sprintf("发现 %d 个疑似目录爆破行为，高比例 404/403 响应。", len(result.DirBruteforceHits)))
	}
	return notes
}
