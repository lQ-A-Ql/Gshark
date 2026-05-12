package tshark

import "testing"

func TestGlobalTrafficStatsAccumulatorConsumesRows(t *testing.T) {
	acc := newGlobalTrafficStatsAccumulator()
	row := make([]string, len(globalTrafficStatsFields))
	row[0] = "1700000000.123"
	row[1] = "HTTP"
	row[2] = "192.0.2.10"
	row[5] = "198.51.100.5"
	row[8] = "Example.COM."
	row[13] = "workstation"
	row[21] = "443"
	row[23] = "51514"

	acc.consumeRow(row)
	stats := acc.finish()

	if stats.TotalPackets != 1 || stats.ProtocolKinds != 1 {
		t.Fatalf("unexpected totals: %+v", stats)
	}
	if len(stats.ProtocolDist) != 1 || stats.ProtocolDist[0].Label != "HTTP" || stats.ProtocolDist[0].Count != 1 {
		t.Fatalf("unexpected protocol dist: %+v", stats.ProtocolDist)
	}
	if len(stats.TopDomains) != 1 || stats.TopDomains[0].Label != "example.com" {
		t.Fatalf("unexpected domains: %+v", stats.TopDomains)
	}
	if len(stats.TopComputerNames) != 1 || stats.TopComputerNames[0].Label != "WORKSTATION" {
		t.Fatalf("unexpected computer names: %+v", stats.TopComputerNames)
	}
	if len(stats.TopDestPorts) != 1 || stats.TopDestPorts[0].Label != "443" {
		t.Fatalf("unexpected destination ports: %+v", stats.TopDestPorts)
	}
}
