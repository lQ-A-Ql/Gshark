//go:build wails

package main

import (
	"context"
	"fmt"
	"log"

	"github.com/gshark/sentinel/backend/internal/engine"
	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/plugin"
	"github.com/gshark/sentinel/backend/internal/transport"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type WailsEmitter struct {
	ctx context.Context
}

type BridgeEmitter struct {
	wails *WailsEmitter
	hub   *transport.Hub
}

func (b *BridgeEmitter) EmitPacket(packet model.Packet) {
	if b.wails != nil {
		b.wails.EmitPacket(packet)
	}
	if b.hub != nil {
		b.hub.EmitPacket(packet)
	}
}

func (b *BridgeEmitter) EmitStatus(status string) {
	if b.wails != nil {
		b.wails.EmitStatus(status)
	}
	if b.hub != nil {
		b.hub.EmitStatus(status)
	}
}

func (b *BridgeEmitter) EmitError(message string) {
	if b.wails != nil {
		b.wails.EmitError(message)
	}
	if b.hub != nil {
		b.hub.EmitError(message)
	}
}

func (w *WailsEmitter) EmitPacket(packet model.Packet) {
	if w.ctx != nil {
		runtime.EventsEmit(w.ctx, "packet", packet)
	}
}

func (w *WailsEmitter) EmitStatus(status string) {
	if w.ctx != nil {
		runtime.EventsEmit(w.ctx, "status", map[string]string{"message": status})
	}
}

func (w *WailsEmitter) EmitError(message string) {
	if w.ctx != nil {
		runtime.EventsEmit(w.ctx, "error", map[string]string{"message": message})
	}
}

type WailsApp struct {
	ctx     context.Context
	emitter *WailsEmitter
	engine  *engine.Service
	hub     *transport.Hub
	server  *transport.Server
	cancel  context.CancelFunc
}

func NewWailsApp() *WailsApp {
	emitter := &WailsEmitter{}
	hub := transport.NewHub()
	bridgeEmitter := &BridgeEmitter{wails: emitter, hub: hub}
	pm := plugin.NewManager()
	_ = pm.LoadFromDir("plugins/rules")
	svc := engine.NewService(bridgeEmitter, pm)
	return &WailsApp{
		emitter: emitter,
		engine:  svc,
		hub:     hub,
		server:  transport.NewServer(svc, hub),
	}
}

func (a *WailsApp) Startup(ctx context.Context) {
	a.ctx = ctx
	a.emitter.ctx = ctx

	serverCtx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel

	go func() {
		if err := a.server.Start(serverCtx, ":17891"); err != nil {
			log.Printf("embedded backend server failed: %v", err)
			a.emitter.EmitError(fmt.Sprintf("后端服务启动失败: %v", err))
		}
	}()
}

func (a *WailsApp) Shutdown(_ context.Context) {
	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}
}

func (a *WailsApp) OpenCapture(filePath string, displayFilter string) error {
	if filePath == "" {
		return fmt.Errorf("file path required")
	}
	opts := model.ParseOptions{
		FilePath:      filePath,
		DisplayFilter: displayFilter,
		MaxPackets:    0,
		FastList:      true,
	}
	go func() {
		if err := a.engine.LoadPCAP(context.Background(), opts); err != nil {
			a.emitter.EmitError(err.Error())
		}
	}()
	return nil
}

func (a *WailsApp) StopCapture() {
	a.engine.StopStreaming()
}

func (a *WailsApp) GetPackets() []model.Packet {
	return a.engine.Packets()
}

func (a *WailsApp) GetThreatHits(prefixes []string) []model.ThreatHit {
	if len(prefixes) == 0 {
		prefixes = []string{"flag{", "ctf{"}
	}
	return a.engine.ThreatHunt(prefixes)
}

func (a *WailsApp) GetObjects() []model.ObjectFile {
	return a.engine.Objects()
}

func (a *WailsApp) GetHTTPStream(streamID int64) model.ReassembledStream {
	return a.engine.HTTPStream(streamID)
}

func (a *WailsApp) GetRawStream(protocol string, streamID int64) model.ReassembledStream {
	return a.engine.RawStream(protocol, streamID)
}

func (a *WailsApp) GetTLSConfig() model.TLSConfig {
	return a.engine.TLSConfig()
}

func (a *WailsApp) SetTLSConfig(cfg model.TLSConfig) {
	a.engine.SetTLSConfig(cfg)
}

func (a *WailsApp) ListPlugins() []model.Plugin {
	return a.engine.ListPlugins()
}

func (a *WailsApp) TogglePlugin(id string) (model.Plugin, error) {
	return a.engine.TogglePlugin(id)
}
