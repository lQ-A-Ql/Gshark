package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/gshark/sentinel/backend/internal/model"
)

func TestToolAnalysisServiceEntrypointsUsePacketStore(t *testing.T) {
	svc := serviceWithPackets(t, []model.Packet{
		{
			ID: 1, Timestamp: "1.000", SourceIP: "10.0.0.10", DestIP: "10.0.0.20",
			SourcePort: 50000, DestPort: 80, Protocol: "HTTP", StreamID: 1,
			Info:    "POST /login HTTP/1.1",
			Payload: "POST /login HTTP/1.1\r\nHost: app.local\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=alice&password=secret",
		},
		{
			ID: 2, Timestamp: "1.050", SourceIP: "10.0.0.20", DestIP: "10.0.0.10",
			SourcePort: 80, DestPort: 50000, Protocol: "HTTP", StreamID: 1,
			Info:    "HTTP/1.1 302 Found",
			Payload: "HTTP/1.1 302 Found\r\nLocation: /dashboard\r\nSet-Cookie: sid=abc\r\n\r\n",
		},
		{
			ID: 3, Timestamp: "2.000", SourceIP: "10.0.0.30", DestIP: "10.0.0.40",
			SourcePort: 51000, DestPort: 53, Protocol: "DNS", Length: 240,
			Info: "Standard query 0x1 TXT verylongrandomlabel1234567890abcdef.evil.test",
		},
		{
			ID: 4, Timestamp: "3.000", SourceIP: "10.0.0.50", DestIP: "10.0.0.60",
			SourcePort: 52000, DestPort: 8080, Protocol: "HTTP", StreamID: 4,
			Info: "GET /dashboard HTTP/1.1",
			Payload: "GET /dashboard HTTP/1.1\r\nHost: shiro.local\r\nCookie: rememberMe=" +
				mustMakeRememberMeCBC(t, "kPH+bIxk5D2deZiIxcaaaA==", append([]byte{0xac, 0xed, 0x00, 0x05}, []byte("org.apache.shiro.subject.SimplePrincipalCollection")...)) +
				"\r\n\r\n",
		},
	})

	httpLogin, err := svc.HTTPLoginAnalysis(context.Background())
	if err != nil {
		t.Fatalf("HTTPLoginAnalysis() error = %v", err)
	}
	if httpLogin.TotalAttempts != 1 || httpLogin.SuccessCount != 1 {
		t.Fatalf("unexpected HTTP login analysis: %+v", httpLogin)
	}

	udp, err := svc.UDPTunnelAnalysis(context.Background())
	if err != nil {
		t.Fatalf("UDPTunnelAnalysis() error = %v", err)
	}
	if udp.TotalSuspicious != 0 || len(udp.Notes) == 0 {
		t.Fatalf("expected stable UDP no-finding result, got %+v", udp)
	}

	brute, err := svc.BruteforceAnalysis(context.Background())
	if err != nil {
		t.Fatalf("BruteforceAnalysis() error = %v", err)
	}
	if brute.TotalSuspicious != 0 || len(brute.Notes) == 0 {
		t.Fatalf("expected stable bruteforce no-finding result, got %+v", brute)
	}

	shiro, err := svc.ShiroRememberMeAnalysis(context.Background(), model.ShiroRememberMeRequest{})
	if err != nil {
		t.Fatalf("ShiroRememberMeAnalysis() error = %v", err)
	}
	if shiro.CandidateCount != 1 || shiro.HitCount != 1 {
		t.Fatalf("unexpected Shiro analysis: %+v", shiro)
	}
}

func TestToolAnalysisServiceEntrypointsValidateCaptureAndCancellation(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.packetStore.Close()

	if _, err := svc.HTTPLoginAnalysis(context.Background()); err == nil {
		t.Fatal("HTTPLoginAnalysis without capture should fail")
	}
	if _, err := svc.UDPTunnelAnalysis(context.Background()); err == nil {
		t.Fatal("UDPTunnelAnalysis without capture should fail")
	}
	if _, err := svc.BruteforceAnalysis(context.Background()); err == nil {
		t.Fatal("BruteforceAnalysis without capture should fail")
	}
	if _, err := svc.ShiroRememberMeAnalysis(context.Background(), model.ShiroRememberMeRequest{}); err == nil {
		t.Fatal("ShiroRememberMeAnalysis without capture should fail")
	}

	svc = serviceWithPackets(t, []model.Packet{{ID: 1, Protocol: "HTTP", Info: "POST /login HTTP/1.1"}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.HTTPLoginAnalysis(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("HTTPLoginAnalysis canceled error = %v", err)
	}
	if _, err := svc.UDPTunnelAnalysis(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("UDPTunnelAnalysis canceled error = %v", err)
	}
	if _, err := svc.BruteforceAnalysis(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("BruteforceAnalysis canceled error = %v", err)
	}
	if _, err := svc.ShiroRememberMeAnalysis(ctx, model.ShiroRememberMeRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("ShiroRememberMeAnalysis canceled error = %v", err)
	}
}

func TestSavedSearchHypothesisAndNoopEmitterEntrypoints(t *testing.T) {
	svc := NewService(NopEmitter{})
	defer svc.packetStore.Close()

	createdSearch, err := svc.CreateSavedSearch(model.SavedSearch{Name: "Find flags", Query: "flag{"})
	if err != nil {
		t.Fatalf("CreateSavedSearch() error = %v", err)
	}
	if got, ok := svc.GetSavedSearch(createdSearch.ID); !ok || got.Name != "Find flags" {
		t.Fatalf("GetSavedSearch() = %+v ok=%v", got, ok)
	}
	updatedSearch, err := svc.UpdateSavedSearch(model.SavedSearch{ID: createdSearch.ID, Name: "Find cmds", Query: "cmd="})
	if err != nil {
		t.Fatalf("UpdateSavedSearch() error = %v", err)
	}
	if updatedSearch.CreatedAt.IsZero() || !updatedSearch.UpdatedAt.After(updatedSearch.CreatedAt) && !updatedSearch.UpdatedAt.Equal(updatedSearch.CreatedAt) {
		t.Fatalf("updated search timestamps not preserved: %+v", updatedSearch)
	}
	if _, err := svc.UpdateSavedSearch(model.SavedSearch{}); err == nil {
		t.Fatal("UpdateSavedSearch with empty ID should fail")
	}
	if _, err := svc.UpdateSavedSearch(model.SavedSearch{ID: "missing"}); err == nil {
		t.Fatal("UpdateSavedSearch missing ID should fail")
	}

	createdHyp, err := svc.CreateHypothesis(model.Hypothesis{Title: "C2 beacon"})
	if err != nil {
		t.Fatalf("CreateHypothesis() error = %v", err)
	}
	if got, ok := svc.GetHypothesis(createdHyp.ID); !ok || got.Title != "C2 beacon" {
		t.Fatalf("GetHypothesis() = %+v ok=%v", got, ok)
	}
	updatedHyp, err := svc.UpdateHypothesis(model.Hypothesis{ID: createdHyp.ID, Title: "C2 confirmed", Status: model.HypothesisStatusConfirmed})
	if err != nil {
		t.Fatalf("UpdateHypothesis() error = %v", err)
	}
	if updatedHyp.Status != model.HypothesisStatusConfirmed {
		t.Fatalf("updated hypothesis status = %+v", updatedHyp)
	}
	if _, err := svc.UpdateHypothesis(model.Hypothesis{}); err == nil {
		t.Fatal("UpdateHypothesis with empty ID should fail")
	}
	if _, err := svc.UpdateHypothesis(model.Hypothesis{ID: "missing"}); err == nil {
		t.Fatal("UpdateHypothesis missing ID should fail")
	}

	NopEmitter{}.EmitPacket(model.Packet{ID: 1})
	NopEmitter{}.EmitStatus("ok")
	NopEmitter{}.EmitError("boom")
}

func serviceWithPackets(t *testing.T, packets []model.Packet) *Service {
	t.Helper()
	svc := NewService(NopEmitter{})
	t.Cleanup(func() { _ = svc.packetStore.Close() })
	svc.pcap = "capture.pcapng"
	if err := svc.packetStore.Append(packets); err != nil {
		t.Fatalf("append packets: %v", err)
	}
	return svc
}
