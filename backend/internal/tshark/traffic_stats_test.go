package tshark

import (
	"fmt"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestGlobalTrafficStatsAccumulatorConsumesRows(t *testing.T) {
	acc := newGlobalTrafficStatsAccumulator()
	row := make([]string, len(globalTrafficStatsFields))
	row[0] = "1700000000.123"
	row[1] = "HTTP"
	row[2] = "eth:ip:tcp:http"
	row[3] = "192.0.2.10"
	row[6] = "198.51.100.5"
	row[9] = "Example.COM."
	row[14] = "workstation"
	row[22] = "443"
	row[24] = "51514"

	acc.consumeRow(row)
	stats := acc.finish()

	if stats.TotalPackets != 1 || stats.ProtocolKinds != 1 {
		t.Fatalf("unexpected totals: %+v", stats)
	}
	if len(stats.ProtocolDist) != 1 || stats.ProtocolDist[0].Label != "HTTP" || stats.ProtocolDist[0].Count != 1 {
		t.Fatalf("unexpected protocol dist: %+v", stats.ProtocolDist)
	}
	requireTrafficBuckets(t, stats.TopTalkers,
		model.TrafficBucket{Label: "192.0.2.10", Count: 1},
		model.TrafficBucket{Label: "198.51.100.5", Count: 1},
	)
	requireTrafficConversations(t, stats.TopConversations,
		model.TrafficConversation{Src: "192.0.2.10", Dst: "198.51.100.5", Count: 1},
	)
	if len(stats.TopDomains) != 1 || stats.TopDomains[0].Label != "example.com" {
		t.Fatalf("unexpected domains: %+v", stats.TopDomains)
	}
	if len(stats.TopComputerNames) != 1 || stats.TopComputerNames[0].Label != "WORKSTATION" {
		t.Fatalf("unexpected computer names: %+v", stats.TopComputerNames)
	}
	if len(stats.TopDestPorts) != 1 || stats.TopDestPorts[0].Label != "443" {
		t.Fatalf("unexpected destination ports: %+v", stats.TopDestPorts)
	}
	if len(stats.ProtocolHierarchy) == 0 {
		t.Fatalf("expected protocol hierarchy, got empty")
	}
}

func TestGlobalTrafficStatsConversationOrderingAndLimit(t *testing.T) {
	acc := newGlobalTrafficStatsAccumulator()
	addConversationRows(acc, "10.0.0.2", "10.0.0.3", 3)
	addConversationRows(acc, "10.0.0.1", "10.0.0.3", 3)
	addConversationRows(acc, "10.0.0.1", "10.0.0.2", 3)
	addConversationRows(acc, "10.0.0.4", "10.0.0.1", 4)
	addConversationRows(acc, "10.0.0.5", "", 5)
	for i := 0; i < 205; i++ {
		addConversationRows(acc, fmt.Sprintf("192.0.2.%d", i), "198.51.100.1", 1)
	}

	stats := acc.finish()

	if len(stats.TopConversations) != 200 {
		t.Fatalf("top conversations len = %d, want 200", len(stats.TopConversations))
	}
	requireTrafficConversations(t, stats.TopConversations[:4],
		model.TrafficConversation{Src: "10.0.0.4", Dst: "10.0.0.1", Count: 4},
		model.TrafficConversation{Src: "10.0.0.1", Dst: "10.0.0.2", Count: 3},
		model.TrafficConversation{Src: "10.0.0.1", Dst: "10.0.0.3", Count: 3},
		model.TrafficConversation{Src: "10.0.0.2", Dst: "10.0.0.3", Count: 3},
	)
	for _, conversation := range stats.TopConversations {
		if conversation.Src == "10.0.0.5" || conversation.Dst == "" {
			t.Fatalf("unexpected incomplete conversation emitted: %+v", conversation)
		}
	}
}

func addConversationRows(acc *globalTrafficStatsAccumulator, src string, dst string, count int) {
	for range count {
		row := make([]string, len(globalTrafficStatsFields))
		row[1] = "TCP"
		row[2] = "eth:ip:tcp"
		row[3] = src
		row[6] = dst
		acc.consumeRow(row)
	}
}

func requireTrafficBuckets(t *testing.T, got []model.TrafficBucket, want ...model.TrafficBucket) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("traffic buckets len = %d want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("traffic bucket[%d] = %+v want %+v", i, got[i], want[i])
		}
	}
}

func requireTrafficConversations(t *testing.T, got []model.TrafficConversation, want ...model.TrafficConversation) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("traffic conversations len = %d want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("traffic conversation[%d] = %+v want %+v", i, got[i], want[i])
		}
	}
}
