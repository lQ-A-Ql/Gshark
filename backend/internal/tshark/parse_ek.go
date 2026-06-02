package tshark

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

func ParsePacketFromEK(line string, id int64) (model.Packet, error) {
	if strings.TrimSpace(line) == "" {
		return model.Packet{}, errors.New("empty line")
	}

	var node map[string]any
	if err := json.Unmarshal([]byte(line), &node); err != nil {
		return model.Packet{}, err
	}

	// ek mode emits metadata lines like {"index":...}; skip those.
	if _, isIndex := node["index"]; isIndex {
		return model.Packet{}, errors.New("ek metadata line")
	}

	layers, ok := node["layers"].(map[string]any)
	if !ok {
		return model.Packet{}, errors.New("missing layers payload")
	}

	sourceIP := pickFirstString(
		findStringByPath(node, "layers.ip.ip_src"),
		findStringByPath(node, "layers.ipv6.ipv6_src"),
		findBySuffix(layers, "arpsrcprotoipv4"),
		findBySuffix(layers, "ipsrc"),
		findBySuffix(layers, "ipv6src"),
	)
	destIP := pickFirstString(
		findStringByPath(node, "layers.ip.ip_dst"),
		findStringByPath(node, "layers.ipv6.ipv6_dst"),
		findBySuffix(layers, "arpdstprotoipv4"),
		findBySuffix(layers, "ipdst"),
		findBySuffix(layers, "ipv6dst"),
	)
	sourcePort := pickFirstInt(
		findIntByPath(node, "layers.tcp.tcp_srcport"),
		findIntByPath(node, "layers.udp.udp_srcport"),
		findIntBySuffix(layers, "tcpsrcport"),
		findIntBySuffix(layers, "udpsrcport"),
	)
	destPort := pickFirstInt(
		findIntByPath(node, "layers.tcp.tcp_dstport"),
		findIntByPath(node, "layers.udp.udp_dstport"),
		findIntBySuffix(layers, "tcpdstport"),
		findIntBySuffix(layers, "udpdstport"),
	)
	protocol := pickFirstString(
		findStringByPath(node, "layers.frame.frame_protocols"),
		findBySuffix(layers, "frameprotocols"),
	)
	displayProtocol := resolveDisplayProtocol(
		pickFirstString(
			findStringByPath(node, "layers._ws.col.Protocol"),
			findStringByPath(node, "layers._ws.col.protocol"),
			findBySuffix(layers, "colprotocol"),
		),
		protocol,
	)
	info := buildPacketInfo(node, layers)

	packetLen := pickFirstInt(
		findIntByPath(node, "layers.frame.frame_len"),
		findIntBySuffix(layers, "framelen"),
	)
	frameNumber := pickFirstInt(
		findIntByPath(node, "layers.frame.frame_number"),
		findIntBySuffix(layers, "framenumber"),
	)

	timestamp := normalizeTimestamp(pickFirstString(
		findStringByPath(node, "layers.frame.frame_time_epoch"),
		findBySuffix(layers, "frametimeepoch"),
		findStringByPath(node, "timestamp"),
	))

	streamID := pickFirstInt(
		findIntByPath(node, "layers.tcp.tcp_stream"),
		findIntByPath(node, "layers.udp.udp_stream"),
		findIntBySuffix(layers, "tcpstream"),
		findIntBySuffix(layers, "udpstream"),
	)

	ipHeaderLen := pickFirstInt(
		findIntByPath(node, "layers.ip.ip_hdr_len"),
		findIntBySuffix(layers, "iphdrlen"),
	)
	if ipHeaderLen == 0 {
		if pickFirstString(
			findStringByPath(node, "layers.ipv6.ipv6_src"),
			findBySuffix(layers, "ipv6src"),
		) != "" {
			ipHeaderLen = 40
		}
	}

	l4HeaderLen := pickFirstInt(
		findIntByPath(node, "layers.tcp.tcp_hdr_len"),
		findIntBySuffix(layers, "tcphdrlen"),
	)
	if l4HeaderLen == 0 {
		if pickFirstInt(
			findIntByPath(node, "layers.udp.udp_srcport"),
			findIntBySuffix(layers, "udpsrcport"),
		) != 0 {
			l4HeaderLen = 8
		}
	}

	payload := extractPayload(node, layers)
	rawHex := pickFirstString(
		findStringByPath(node, "layers.frame.frame_raw"),
		findBySuffix(layers, "frameraw"),
	)
	udpPayloadHex := pickFirstString(
		findStringByPath(node, "layers.udp.udp_payload"),
		findBySuffix(layers, "udppayload"),
	)

	if sourceIP == "" && destIP == "" && packetLen == 0 && payload == "" && info == "" {
		return model.Packet{}, errors.New("not a packet line")
	}

	packet := model.Packet{
		ID:              firstNonZeroInt64(int64(frameNumber), id),
		Timestamp:       timestamp,
		SourceIP:        sourceIP,
		SourcePort:      sourcePort,
		DestIP:          destIP,
		DestPort:        destPort,
		Protocol:        normalizeProto(protocol),
		DisplayProtocol: displayProtocol,
		Length:          packetLen,
		Info:            info,
		Payload:         payload,
		RawHex:          rawHex,
		UDPPayloadHex:   udpPayloadHex,
		StreamID:        int64(streamID),
		IPHeaderLen:     ipHeaderLen,
		L4HeaderLen:     l4HeaderLen,
		Color: model.PacketColorFeatures{
			TCPAnalysisFlags: hasNonEmpty(
				findStringByPath(node, "layers.tcp.tcp_analysis_flags"),
				findBySuffix(layers, "tcpanalysisflags"),
			),
			TCPWindowUpdate: hasNonEmpty(
				findStringByPath(node, "layers.tcp.tcp_analysis_window_update"),
				findBySuffix(layers, "tcpanalysiswindowupdate"),
			),
			TCPKeepAlive: hasNonEmpty(
				findStringByPath(node, "layers.tcp.tcp_analysis_keep_alive"),
				findBySuffix(layers, "tcpanalysiskeepalive"),
			),
			TCPKeepAliveAck: hasNonEmpty(
				findStringByPath(node, "layers.tcp.tcp_analysis_keep_alive_ack"),
				findBySuffix(layers, "tcpanalysiskeepaliveack"),
			),
			TCPRST: parseTruthy(
				findStringByPath(node, "layers.tcp.tcp_flags_reset"),
				findBySuffix(layers, "tcpflagsreset"),
			),
			TCPSYN: parseTruthy(
				findStringByPath(node, "layers.tcp.tcp_flags_syn"),
				findBySuffix(layers, "tcpflagssyn"),
			),
			TCPFIN: parseTruthy(
				findStringByPath(node, "layers.tcp.tcp_flags_fin"),
				findBySuffix(layers, "tcpflagsfin"),
			),
			HSRPState: pickFirstInt(
				findIntByPath(node, "layers.hsrp.hsrp_state"),
				findIntBySuffix(layers, "hsrpstate"),
			),
			OSPFMsg: pickFirstInt(
				findIntByPath(node, "layers.ospf.ospf_msg"),
				findIntBySuffix(layers, "ospfmsg"),
			),
			ICMPType: pickFirstInt(
				findIntByPath(node, "layers.icmp.icmp_type"),
				findIntBySuffix(layers, "icmptype"),
			),
			ICMPv6Type: pickFirstInt(
				findIntByPath(node, "layers.icmpv6.icmpv6_type"),
				findIntBySuffix(layers, "icmpv6type"),
			),
			IPv4TTL: pickFirstInt(
				findIntByPath(node, "layers.ip.ip_ttl"),
				findIntBySuffix(layers, "ipttl"),
			),
			IPv6HopLimit: pickFirstInt(
				findIntByPath(node, "layers.ipv6.ipv6_hlim"),
				findIntBySuffix(layers, "ipv6hlim"),
			),
			STPTopologyChange: strings.EqualFold(pickFirstString(
				findStringByPath(node, "layers.stp.stp_type"),
				findBySuffix(layers, "stptype"),
			), "0x80"),
			ChecksumBad: hasBadChecksum(node, layers),
			Broadcast: pickFirstString(
				findStringByPath(node, "layers.eth.eth_dst"),
				findBySuffix(layers, "ethdst"),
			) == "ff:ff:ff:ff:ff:ff",
			HasSystemdJnl: hasNonEmpty(
				findStringByPath(node, "layers.systemd_journal"),
				findBySuffix(layers, "systemdjournal"),
			),
			HasSysdig: hasNonEmpty(
				findStringByPath(node, "layers.sysdig"),
				findBySuffix(layers, "sysdig"),
			),
			HasSMB:     hasNonEmpty(findStringByPath(node, "layers.smb"), findBySuffix(layers, "smb")),
			HasNBSS:    hasNonEmpty(findStringByPath(node, "layers.nbss"), findBySuffix(layers, "nbss")),
			HasNBNS:    hasNonEmpty(findStringByPath(node, "layers.nbns"), findBySuffix(layers, "nbns")),
			HasNetBIOS: hasNonEmpty(findStringByPath(node, "layers.netbios"), findBySuffix(layers, "netbios")),
			HasDCERPC:  hasNonEmpty(findStringByPath(node, "layers.dcerpc"), findBySuffix(layers, "dcerpc")),
			HasHSRP:    hasNonEmpty(findStringByPath(node, "layers.hsrp"), findBySuffix(layers, "hsrp")),
			HasEIGRP:   hasNonEmpty(findStringByPath(node, "layers.eigrp"), findBySuffix(layers, "eigrp")),
			HasOSPF:    hasNonEmpty(findStringByPath(node, "layers.ospf"), findBySuffix(layers, "ospf")),
			HasBGP:     hasNonEmpty(findStringByPath(node, "layers.bgp"), findBySuffix(layers, "bgp")),
			HasCDP:     hasNonEmpty(findStringByPath(node, "layers.cdp"), findBySuffix(layers, "cdp")),
			HasVRRP:    hasNonEmpty(findStringByPath(node, "layers.vrrp"), findBySuffix(layers, "vrrp")),
			HasCARP:    hasNonEmpty(findStringByPath(node, "layers.carp"), findBySuffix(layers, "carp")),
			HasGVRP:    hasNonEmpty(findStringByPath(node, "layers.gvrp"), findBySuffix(layers, "gvrp")),
			HasIGMP:    hasNonEmpty(findStringByPath(node, "layers.igmp"), findBySuffix(layers, "igmp")),
			HasISMP:    hasNonEmpty(findStringByPath(node, "layers.ismp"), findBySuffix(layers, "ismp")),
			HasRIP:     hasNonEmpty(findStringByPath(node, "layers.rip"), findBySuffix(layers, "rip")),
			HasGLBP:    hasNonEmpty(findStringByPath(node, "layers.glbp"), findBySuffix(layers, "glbp")),
			HasPIM:     hasNonEmpty(findStringByPath(node, "layers.pim"), findBySuffix(layers, "pim")),
		},
	}
	return packet, nil
}

func firstNonZeroInt64(values ...int64) int64 {
	for _, v := range values {
		if v != 0 {
			return v
		}
	}
	return 0
}
