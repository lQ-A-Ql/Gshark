package engine

import "testing"

func TestNewServiceInitializesOwnerState(t *testing.T) {
	svc := NewService(nil, nil)

	if svc.emitter == nil {
		t.Fatal("expected default emitter")
	}
	if svc.packetStore == nil {
		t.Fatal("expected packet store")
	}
	if svc.captureTasks == nil {
		t.Fatal("expected capture task registry")
	}
	if svc.displayFilterCache == nil {
		t.Fatal("expected display filter cache")
	}
	if svc.streamCache == nil || svc.rawStreamIndex == nil || svc.streamOverrides == nil {
		t.Fatalf("expected stream owner maps, got cache=%v raw=%v overrides=%v", svc.streamCache, svc.rawStreamIndex, svc.streamOverrides)
	}
	if svc.mediaArtifacts == nil || svc.mediaPlayback == nil || svc.mediaSpeech == nil {
		t.Fatalf("expected media owner maps, got artifacts=%v playback=%v speech=%v", svc.mediaArtifacts, svc.mediaPlayback, svc.mediaSpeech)
	}
	if len(svc.huntingPrefixes) == 0 {
		t.Fatal("expected default hunting prefixes")
	}
	if !svc.yaraConf.Enabled || svc.yaraConf.TimeoutMS <= 0 {
		t.Fatalf("expected default yara config, got %+v", svc.yaraConf)
	}
}
