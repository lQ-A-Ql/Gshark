package tshark

import (
	"context"
	"strings"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestPacketListArgBuildersIncludeExpectedModesAndTLSFallback(t *testing.T) {
	opts := model.ParseOptions{
		FilePath:      "demo.pcapng",
		DisplayFilter: "tcp",
		TLS:           model.TLSConfig{RSAPrivateKey: "server.pem"},
	}
	for _, tt := range []struct {
		name string
		args []string
	}{
		{name: "fast", args: BuildFastListArgs(opts)},
		{name: "first", args: BuildFirstScreenListArgs(opts)},
		{name: "compat", args: BuildCompatListArgs(opts)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			joined := strings.Join(tt.args, "\x00")
			for _, want := range []string{"-n", "-r", "demo.pcapng", "-Y", "tcp", "-T", "fields", "separator=" + packetListFieldSeparator, "rsa_keys:0.0.0.0,443,http,server.pem"} {
				if !strings.Contains(joined, want) {
					t.Fatalf("%s args missing %q: %#v", tt.name, want, tt.args)
				}
			}
		})
	}
}

func TestWarmFieldScanCacheUsesFakeTSharkAndSpecializedPlans(t *testing.T) {
	withFakeTSharkCommand(t, "")
	ClearFieldScanCache("")
	ClearCapabilityCache()
	t.Cleanup(func() {
		ClearFieldScanCache("")
		ClearCapabilityCache()
	})

	if err := WarmFieldScanCache("demo.pcap", []string{"frame.number", "_ws.col.Info"}, fieldScanOptions{DisplayFilter: "tcp"}); err != nil {
		t.Fatalf("WarmFieldScanCache() error = %v", err)
	}
	if err := WarmFieldScanCacheContext(context.Background(), "demo.pcap", []string{"frame.number"}, fieldScanOptions{}); err != nil {
		t.Fatalf("WarmFieldScanCacheContext() error = %v", err)
	}
	plans := specializedFieldWarmPlans()
	if len(plans) != 3 {
		t.Fatalf("specialized warm plans = %+v", plans)
	}
	if err := WarmSpecializedFieldCache("demo.pcap"); err != nil {
		t.Fatalf("WarmSpecializedFieldCache() error = %v", err)
	}
	if err := WarmSpecializedFieldCacheWithContext(context.Background(), "demo.pcap"); err != nil {
		t.Fatalf("WarmSpecializedFieldCacheWithContext() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WarmFieldScanCacheContext(ctx, "demo.pcap", []string{"frame.number"}, fieldScanOptions{}); err == nil {
		t.Fatal("canceled warm field scan should fail")
	}
}
