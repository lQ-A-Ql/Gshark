package engine

import "testing"

func TestNewServiceInitializesOwnerState(t *testing.T) {
	svc := NewService(nil)

	if svc.emitter == nil {
		t.Fatal("expected default emitter")
	}
	if svc.captureCtl.packetStore == nil {
		t.Fatal("expected packet store")
	}
	if svc.captureCtl.captureTasks == nil {
		t.Fatal("expected capture task registry")
	}
	if svc.filterCtl.displayFilterCache == nil {
		t.Fatal("expected display filter cache")
	}
	if svc.streamCtl.streamCache == nil || svc.streamCtl.rawStreamIndex == nil || svc.streamCtl.streamOverrides == nil {
		t.Fatalf("expected stream owner maps, got cache=%v raw=%v overrides=%v", svc.streamCtl.streamCache, svc.streamCtl.rawStreamIndex, svc.streamCtl.streamOverrides)
	}
	if svc.mediaCtl.mediaArtifacts == nil || svc.mediaCtl.mediaPlayback == nil || svc.mediaCtl.mediaSpeech == nil {
		t.Fatalf("expected media owner maps, got artifacts=%v playback=%v speech=%v", svc.mediaCtl.mediaArtifacts, svc.mediaCtl.mediaPlayback, svc.mediaCtl.mediaSpeech)
	}
	if len(svc.huntingCtl.huntingPrefixes) == 0 {
		t.Fatal("expected default hunting prefixes")
	}
	if !svc.huntingCtl.yaraConf.Enabled || svc.huntingCtl.yaraConf.TimeoutMS <= 0 {
		t.Fatalf("expected default yara config, got %+v", svc.huntingCtl.yaraConf)
	}
}
