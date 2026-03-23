package engine

import "github.com/gshark/sentinel/backend/internal/model"

type EventEmitter interface {
	EmitPacket(packet model.Packet)
	EmitStatus(status string)
	EmitError(message string)
}

type NopEmitter struct{}

func (NopEmitter) EmitPacket(model.Packet) {}
func (NopEmitter) EmitStatus(string)       {}
func (NopEmitter) EmitError(string)        {}
