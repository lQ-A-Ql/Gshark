package engine

import (
	"github.com/gshark/sentinel/backend/internal/engine/payloadinspect"
	"github.com/gshark/sentinel/backend/internal/model"
)

func InspectStreamPayload(raw string) model.StreamPayloadInspection {
	return payloadinspect.InspectStreamPayload(raw)
}
