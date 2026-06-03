package tshark

import (
	"errors"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func projectPacketListLine(line string, plan fieldScanCapabilityPlan) string {
	row := normalizeFieldScanRow(strings.Split(line, packetListFieldSeparator), len(plan.tsharkFields))
	projected := projectCapabilityFieldScanRow(row, plan)
	return strings.Join(projected, packetListFieldSeparator)
}

func parseFastListLine(line string) (model.Packet, error) {
	parts := strings.Split(line, packetListFieldSeparator)
	if len(parts) < 65 {
		return model.Packet{}, errors.New("invalid fast list line")
	}

	id := parseInt64(parts[0])
	src := FirstNonEmpty(parts[2], parts[3], parts[4])
	dst := FirstNonEmpty(parts[5], parts[6], parts[7])
	srcPort := parseInt(FirstNonEmpty(parts[8], parts[9]))
	dstPort := parseInt(FirstNonEmpty(parts[10], parts[11]))
	proto := strings.TrimSpace(parts[12])
	displayProtocol := resolveDisplayProtocol(proto, proto)
	length := parseInt(parts[13])
	info := strings.TrimSpace(parts[14])
	streamID := parseInt64(FirstNonEmpty(parts[15], parts[16]))
	udpPayloadHex := strings.TrimSpace(parts[17])
	ipHeaderLen := parseInt(parts[18])
	l4HeaderLen := parseInt(parts[19])
	if l4HeaderLen == 0 && strings.EqualFold(normalizeProto(proto), "UDP") {
		l4HeaderLen = 8
	}

	color := model.PacketColorFeatures{
		TCPAnalysisFlags:  hasNonEmpty(parts[20]),
		TCPWindowUpdate:   parseTruthy(parts[21]),
		TCPKeepAlive:      parseTruthy(parts[22]),
		TCPKeepAliveAck:   parseTruthy(parts[23]),
		TCPRST:            parseTruthy(parts[24]),
		TCPSYN:            parseTruthy(parts[25]),
		TCPFIN:            parseTruthy(parts[26]),
		HSRPState:         parseInt(parts[27]),
		OSPFMsg:           parseInt(parts[28]),
		STPTopologyChange: strings.EqualFold(strings.TrimSpace(parts[29]), "0x80"),
		ICMPType:          parseInt(parts[30]),
		ICMPv6Type:        parseInt(parts[31]),
		IPv4TTL:           parseInt(parts[32]),
		IPv6HopLimit:      parseInt(parts[33]),
		Broadcast:         strings.EqualFold(strings.TrimSpace(parts[34]), "ff:ff:ff:ff:ff:ff"),
		ChecksumBad:       isBadStatus(parts[35]) || isBadStatus(parts[36]) || isBadStatus(parts[37]) || isBadStatus(parts[38]) || isBadStatus(parts[39]) || isBadStatus(parts[40]) || isBadStatus(parts[41]) || isBadStatus(parts[42]) || isBadStatus(parts[43]) || isBadStatus(parts[44]),
		HasSystemdJnl:     hasNonEmpty(parts[45]),
		HasSysdig:         hasNonEmpty(parts[46]),
		HasSMB:            hasNonEmpty(parts[47]),
		HasNBSS:           hasNonEmpty(parts[48]),
		HasNBNS:           hasNonEmpty(parts[49]),
		HasNetBIOS:        hasNonEmpty(parts[50]),
		HasDCERPC:         hasNonEmpty(parts[51]),
		HasHSRP:           hasNonEmpty(parts[52]),
		HasEIGRP:          hasNonEmpty(parts[53]),
		HasOSPF:           hasNonEmpty(parts[54]),
		HasBGP:            hasNonEmpty(parts[55]),
		HasCDP:            hasNonEmpty(parts[56]),
		HasVRRP:           hasNonEmpty(parts[57]),
		HasCARP:           hasNonEmpty(parts[58]),
		HasGVRP:           hasNonEmpty(parts[59]),
		HasIGMP:           hasNonEmpty(parts[60]),
		HasISMP:           hasNonEmpty(parts[61]),
		HasRIP:            hasNonEmpty(parts[62]),
		HasGLBP:           hasNonEmpty(parts[63]),
		HasPIM:            hasNonEmpty(parts[64]),
	}

	return model.Packet{
		ID:              id,
		Timestamp:       normalizeTimestamp(parts[1]),
		SourceIP:        src,
		SourcePort:      srcPort,
		DestIP:          dst,
		DestPort:        dstPort,
		Protocol:        normalizeProto(proto),
		DisplayProtocol: displayProtocol,
		Length:          length,
		Info:            info,
		Payload:         "",
		UDPPayloadHex:   udpPayloadHex,
		StreamID:        streamID,
		IPHeaderLen:     ipHeaderLen,
		L4HeaderLen:     l4HeaderLen,
		Color:           color,
	}, nil
}

func parseCompatListLine(line string) (model.Packet, error) {
	parts := strings.Split(line, packetListFieldSeparator)
	if len(parts) < 20 {
		return model.Packet{}, errors.New("invalid compat list line")
	}

	id := parseInt64(parts[0])
	src := FirstNonEmpty(parts[2], parts[3], parts[4])
	dst := FirstNonEmpty(parts[5], parts[6], parts[7])
	srcPort := parseInt(FirstNonEmpty(parts[8], parts[9]))
	dstPort := parseInt(FirstNonEmpty(parts[10], parts[11]))
	displayProtoRaw := strings.TrimSpace(parts[12])
	protoPath := strings.TrimSpace(parts[13])
	proto := FirstNonEmpty(displayProtoRaw, protoPath)
	displayProtocol := resolveDisplayProtocol(displayProtoRaw, protoPath)
	length := parseInt(parts[14])
	info := strings.TrimSpace(parts[15])
	streamID := parseInt64(FirstNonEmpty(parts[16], parts[17]))
	ipHeaderLen := parseInt(parts[18])
	l4HeaderLen := parseInt(parts[19])
	if l4HeaderLen == 0 && strings.EqualFold(normalizeProto(proto), "UDP") {
		l4HeaderLen = 8
	}

	if id == 0 && src == "" && dst == "" && length == 0 && info == "" {
		return model.Packet{}, errors.New("not a compat packet line")
	}

	return model.Packet{
		ID:              id,
		Timestamp:       normalizeTimestamp(parts[1]),
		SourceIP:        src,
		SourcePort:      srcPort,
		DestIP:          dst,
		DestPort:        dstPort,
		Protocol:        normalizeProto(proto),
		DisplayProtocol: displayProtocol,
		Length:          length,
		Info:            info,
		StreamID:        streamID,
		IPHeaderLen:     ipHeaderLen,
		L4HeaderLen:     l4HeaderLen,
	}, nil
}
