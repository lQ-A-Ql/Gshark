package tshark

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gshark/sentinel/backend/internal/model"
)

func BuildArgs(opts model.ParseOptions) []string {
	args := []string{"-n", "-r", opts.FilePath, "-T", "ek"}
	if opts.DisplayFilter != "" {
		args = append(args, "-Y", opts.DisplayFilter)
	}
	args = appendTLSArgs(args, opts.TLS)
	return args
}

func BuildFastListArgs(opts model.ParseOptions) []string {
	const sep = "\x1f"
	args := []string{"-n", "-r", opts.FilePath}
	if opts.DisplayFilter != "" {
		args = append(args, "-Y", opts.DisplayFilter)
	}
	args = appendTLSArgs(args, opts.TLS)

	args = append(args,
		"-T", "fields",
		"-E", "header=n",
		"-E", "occurrence=f",
		"-E", "separator="+sep,
		"-E", "quote=n",
		"-e", "frame.number",
		"-e", "frame.time_epoch",
		"-e", "ip.src",
		"-e", "ipv6.src",
		"-e", "arp.src.proto_ipv4",
		"-e", "ip.dst",
		"-e", "ipv6.dst",
		"-e", "arp.dst.proto_ipv4",
		"-e", "tcp.srcport",
		"-e", "udp.srcport",
		"-e", "tcp.dstport",
		"-e", "udp.dstport",
		"-e", "_ws.col.Protocol",
		"-e", "frame.len",
		"-e", "_ws.col.Info",
		"-e", "tcp.stream",
		"-e", "udp.stream",
		"-e", "ip.hdr_len",
		"-e", "tcp.hdr_len",
		"-e", "tcp.analysis.flags",
		"-e", "tcp.analysis.window_update",
		"-e", "tcp.analysis.keep_alive",
		"-e", "tcp.analysis.keep_alive_ack",
		"-e", "tcp.flags.reset",
		"-e", "tcp.flags.syn",
		"-e", "tcp.flags.fin",
		"-e", "hsrp.state",
		"-e", "ospf.msg",
		"-e", "stp.type",
		"-e", "icmp.type",
		"-e", "icmpv6.type",
		"-e", "ip.ttl",
		"-e", "ipv6.hlim",
		"-e", "eth.dst",
		"-e", "eth.fcs.status",
		"-e", "ip.checksum.status",
		"-e", "tcp.checksum.status",
		"-e", "udp.checksum.status",
		"-e", "sctp.checksum.status",
		"-e", "mstp.checksum.status",
		"-e", "cdp.checksum.status",
		"-e", "edp.checksum.status",
		"-e", "wlan.fcs.status",
		"-e", "stt.checksum.status",
		"-e", "systemd_journal",
		"-e", "sysdig",
		"-e", "smb",
		"-e", "nbss",
		"-e", "nbns",
		"-e", "netbios",
		"-e", "dcerpc",
		"-e", "hsrp",
		"-e", "eigrp",
		"-e", "ospf",
		"-e", "bgp",
		"-e", "cdp",
		"-e", "vrrp",
		"-e", "carp",
		"-e", "gvrp",
		"-e", "igmp",
		"-e", "ismp",
		"-e", "rip",
		"-e", "glbp",
		"-e", "pim",
	)
	return args
}

func BuildCompatListArgs(opts model.ParseOptions) []string {
	const sep = "\x1f"
	args := []string{"-n", "-r", opts.FilePath}
	if opts.DisplayFilter != "" {
		args = append(args, "-Y", opts.DisplayFilter)
	}
	args = appendTLSArgs(args, opts.TLS)
	args = append(args,
		"-T", "fields",
		"-E", "header=n",
		"-E", "occurrence=f",
		"-E", "separator="+sep,
		"-E", "quote=n",
		"-e", "frame.number",
		"-e", "frame.time_epoch",
		"-e", "ip.src",
		"-e", "ipv6.src",
		"-e", "arp.src.proto_ipv4",
		"-e", "ip.dst",
		"-e", "ipv6.dst",
		"-e", "arp.dst.proto_ipv4",
		"-e", "tcp.srcport",
		"-e", "udp.srcport",
		"-e", "tcp.dstport",
		"-e", "udp.dstport",
		"-e", "_ws.col.Protocol",
		"-e", "frame.protocols",
		"-e", "frame.len",
		"-e", "_ws.col.Info",
		"-e", "tcp.stream",
		"-e", "udp.stream",
		"-e", "ip.hdr_len",
		"-e", "tcp.hdr_len",
	)
	return args
}

func appendTLSArgs(args []string, cfg model.TLSConfig) []string {
	if cfg.SSLKeyLogFile != "" {
		args = append(args, "-o", "tls.keylog_file:"+cfg.SSLKeyLogFile)
	}
	if cfg.RSAPrivateKey != "" {
		target := cfg.TargetIPPort
		if target == "" {
			target = "0.0.0.0,443"
		}
		args = append(args, "-o", "rsa_keys:"+target+",http,"+cfg.RSAPrivateKey)
	}
	return args
}

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
		Protocol:        normalizeProto(firstNonEmpty(displayProtocol, protocol)),
		DisplayProtocol: displayProtocol,
		Length:          packetLen,
		Info:            info,
		Payload:         payload,
		RawHex:          rawHex,
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

func StreamPackets(ctx context.Context, opts model.ParseOptions, onPacket func(model.Packet) error, onProgress func(processed int)) error {
	maxPackets := opts.MaxPackets

	cmd, err := CommandContext(ctx, BuildArgs(opts)...)
	if err != nil {
		return fmt.Errorf("resolve tshark: %w", err)
	}
	log.Printf("tshark stream ek: binary=%q file=%q filter=%q", cmd.Path, opts.FilePath, opts.DisplayFilter)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tshark: %w", err)
	}

	reader := bufio.NewReaderSize(stdout, 256*1024)
	var packetCount int64
	processedFrames := 0
	for {
		lineBytes, readErr := reader.ReadBytes('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			_ = cmd.Wait()
			return fmt.Errorf("read tshark output: %w", readErr)
		}
		if len(lineBytes) == 0 && errors.Is(readErr, io.EOF) {
			break
		}

		select {
		case <-ctx.Done():
			_ = cmd.Wait()
			return ctx.Err()
		default:
		}

		line := strings.TrimSpace(string(lineBytes))
		if line == "" {
			if errors.Is(readErr, io.EOF) {
				break
			}
			continue
		}
		if strings.Contains(line, `"index"`) && !strings.Contains(line, `"layers"`) {
			if errors.Is(readErr, io.EOF) {
				break
			}
			continue
		}

		processedFrames++
		if onProgress != nil && (processedFrames == 1 || processedFrames%2000 == 0) {
			onProgress(processedFrames)
		}

		packet, parseErr := ParsePacketFromEK(line, packetCount+1)
		if parseErr != nil {
			if maxPackets > 0 && processedFrames >= maxPackets {
				break
			}
			continue
		}
		packetCount++
		if err := onPacket(packet); err != nil {
			_ = cmd.Wait()
			return err
		}
		if maxPackets > 0 && processedFrames >= maxPackets {
			break
		}

		if errors.Is(readErr, io.EOF) {
			break
		}
	}

	if onProgress != nil {
		onProgress(processedFrames)
	}

	if err := cmd.Wait(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return fmt.Errorf("wait tshark: %w: %s", err, detail)
		}
		return fmt.Errorf("wait tshark: %w", err)
	}
	return nil
}

func StreamPacketsFast(ctx context.Context, opts model.ParseOptions, onPacket func(model.Packet) error, onProgress func(processed int)) error {
	maxPackets := opts.MaxPackets
	cmd, err := CommandContext(ctx, BuildFastListArgs(opts)...)
	if err != nil {
		return fmt.Errorf("resolve tshark: %w", err)
	}
	log.Printf("tshark stream fast_list: binary=%q file=%q filter=%q", cmd.Path, opts.FilePath, opts.DisplayFilter)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tshark: %w", err)
	}

	reader := bufio.NewReaderSize(stdout, 128*1024)
	processed := 0
	for {
		lineBytes, readErr := reader.ReadBytes('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			_ = cmd.Wait()
			return fmt.Errorf("read tshark fields output: %w", readErr)
		}
		if len(lineBytes) == 0 && errors.Is(readErr, io.EOF) {
			break
		}

		line := strings.TrimSpace(string(lineBytes))
		if line == "" {
			if errors.Is(readErr, io.EOF) {
				break
			}
			continue
		}

		processed++
		if onProgress != nil && (processed == 1 || processed%2000 == 0) {
			onProgress(processed)
		}

		packet, parseErr := parseFastListLine(line)
		if parseErr == nil {
			if err := onPacket(packet); err != nil {
				_ = cmd.Wait()
				return err
			}
		}

		if maxPackets > 0 && processed >= maxPackets {
			break
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}

	if onProgress != nil {
		onProgress(processed)
	}

	if err := cmd.Wait(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return fmt.Errorf("wait tshark fields: %w: %s", err, detail)
		}
		return fmt.Errorf("wait tshark fields: %w", err)
	}
	return nil
}

func StreamPacketsCompat(ctx context.Context, opts model.ParseOptions, onPacket func(model.Packet) error, onProgress func(processed int)) error {
	maxPackets := opts.MaxPackets
	cmd, err := CommandContext(ctx, BuildCompatListArgs(opts)...)
	if err != nil {
		return fmt.Errorf("resolve tshark: %w", err)
	}
	log.Printf("tshark stream compat_fields: binary=%q file=%q filter=%q", cmd.Path, opts.FilePath, opts.DisplayFilter)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tshark: %w", err)
	}

	reader := bufio.NewReaderSize(stdout, 64*1024)
	processed := 0
	for {
		lineBytes, readErr := reader.ReadBytes('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			_ = cmd.Wait()
			return fmt.Errorf("read tshark compat output: %w", readErr)
		}
		if len(lineBytes) == 0 && errors.Is(readErr, io.EOF) {
			break
		}

		line := strings.TrimSpace(string(lineBytes))
		if line == "" {
			if errors.Is(readErr, io.EOF) {
				break
			}
			continue
		}

		processed++
		if onProgress != nil && (processed == 1 || processed%2000 == 0) {
			onProgress(processed)
		}

		packet, parseErr := parseCompatListLine(line)
		if parseErr == nil {
			if err := onPacket(packet); err != nil {
				_ = cmd.Wait()
				return err
			}
		}

		if maxPackets > 0 && processed >= maxPackets {
			break
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}

	if onProgress != nil {
		onProgress(processed)
	}

	if err := cmd.Wait(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return fmt.Errorf("wait tshark compat fields: %w: %s", err, detail)
		}
		return fmt.Errorf("wait tshark compat fields: %w", err)
	}
	return nil
}

func parseFastListLine(line string) (model.Packet, error) {
	parts := strings.Split(line, "\x1f")
	if len(parts) < 64 {
		return model.Packet{}, errors.New("invalid fast list line")
	}

	id := parseInt64(parts[0])
	src := firstNonEmpty(parts[2], parts[3], parts[4])
	dst := firstNonEmpty(parts[5], parts[6], parts[7])
	srcPort := parseInt(firstNonEmpty(parts[8], parts[9]))
	dstPort := parseInt(firstNonEmpty(parts[10], parts[11]))
	proto := strings.TrimSpace(parts[12])
	displayProtocol := resolveDisplayProtocol(proto, proto)
	length := parseInt(parts[13])
	info := strings.TrimSpace(parts[14])
	streamID := parseInt64(firstNonEmpty(parts[15], parts[16]))
	ipHeaderLen := parseInt(parts[17])
	l4HeaderLen := parseInt(parts[18])
	if l4HeaderLen == 0 && strings.EqualFold(normalizeProto(proto), "UDP") {
		l4HeaderLen = 8
	}

	color := model.PacketColorFeatures{
		TCPAnalysisFlags:  hasNonEmpty(parts[19]),
		TCPWindowUpdate:   parseTruthy(parts[20]),
		TCPKeepAlive:      parseTruthy(parts[21]),
		TCPKeepAliveAck:   parseTruthy(parts[22]),
		TCPRST:            parseTruthy(parts[23]),
		TCPSYN:            parseTruthy(parts[24]),
		TCPFIN:            parseTruthy(parts[25]),
		HSRPState:         parseInt(parts[26]),
		OSPFMsg:           parseInt(parts[27]),
		STPTopologyChange: strings.EqualFold(strings.TrimSpace(parts[28]), "0x80"),
		ICMPType:          parseInt(parts[29]),
		ICMPv6Type:        parseInt(parts[30]),
		IPv4TTL:           parseInt(parts[31]),
		IPv6HopLimit:      parseInt(parts[32]),
		Broadcast:         strings.EqualFold(strings.TrimSpace(parts[33]), "ff:ff:ff:ff:ff:ff"),
		ChecksumBad:       isBadStatus(parts[34]) || isBadStatus(parts[35]) || isBadStatus(parts[36]) || isBadStatus(parts[37]) || isBadStatus(parts[38]) || isBadStatus(parts[39]) || isBadStatus(parts[40]) || isBadStatus(parts[41]) || isBadStatus(parts[42]) || isBadStatus(parts[43]),
		HasSystemdJnl:     hasNonEmpty(parts[44]),
		HasSysdig:         hasNonEmpty(parts[45]),
		HasSMB:            hasNonEmpty(parts[46]),
		HasNBSS:           hasNonEmpty(parts[47]),
		HasNBNS:           hasNonEmpty(parts[48]),
		HasNetBIOS:        hasNonEmpty(parts[49]),
		HasDCERPC:         hasNonEmpty(parts[50]),
		HasHSRP:           hasNonEmpty(parts[51]),
		HasEIGRP:          hasNonEmpty(parts[52]),
		HasOSPF:           hasNonEmpty(parts[53]),
		HasBGP:            hasNonEmpty(parts[54]),
		HasCDP:            hasNonEmpty(parts[55]),
		HasVRRP:           hasNonEmpty(parts[56]),
		HasCARP:           hasNonEmpty(parts[57]),
		HasGVRP:           hasNonEmpty(parts[58]),
		HasIGMP:           hasNonEmpty(parts[59]),
		HasISMP:           hasNonEmpty(parts[60]),
		HasRIP:            hasNonEmpty(parts[61]),
		HasGLBP:           hasNonEmpty(parts[62]),
		HasPIM:            hasNonEmpty(parts[63]),
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
		StreamID:        streamID,
		IPHeaderLen:     ipHeaderLen,
		L4HeaderLen:     l4HeaderLen,
		Color:           color,
	}, nil
}

func parseCompatListLine(line string) (model.Packet, error) {
	parts := strings.Split(line, "\x1f")
	if len(parts) < 20 {
		return model.Packet{}, errors.New("invalid compat list line")
	}

	id := parseInt64(parts[0])
	src := firstNonEmpty(parts[2], parts[3], parts[4])
	dst := firstNonEmpty(parts[5], parts[6], parts[7])
	srcPort := parseInt(firstNonEmpty(parts[8], parts[9]))
	dstPort := parseInt(firstNonEmpty(parts[10], parts[11]))
	displayProtoRaw := strings.TrimSpace(parts[12])
	protoPath := strings.TrimSpace(parts[13])
	proto := firstNonEmpty(displayProtoRaw, protoPath)
	displayProtocol := resolveDisplayProtocol(displayProtoRaw, protoPath)
	length := parseInt(parts[14])
	info := strings.TrimSpace(parts[15])
	streamID := parseInt64(firstNonEmpty(parts[16], parts[17]))
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

func hasNonEmpty(values ...string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

func parseTruthy(values ...string) bool {
	for _, raw := range values {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" {
			continue
		}
		if v == "0" || v == "false" || v == "no" || v == "none" {
			continue
		}
		return true
	}
	return false
}

func isBadStatus(raw string) bool {
	v := strings.ToLower(strings.TrimSpace(raw))
	return strings.Contains(v, "bad") || strings.Contains(v, "invalid")
}

func hasBadChecksum(node map[string]any, layers map[string]any) bool {
	fields := []string{
		findStringByPath(node, "layers.eth.eth_fcs_status"),
		findStringByPath(node, "layers.ip.ip_checksum_status"),
		findStringByPath(node, "layers.tcp.tcp_checksum_status"),
		findStringByPath(node, "layers.udp.udp_checksum_status"),
		findStringByPath(node, "layers.sctp.sctp_checksum_status"),
		findStringByPath(node, "layers.mstp.mstp_checksum_status"),
		findStringByPath(node, "layers.cdp.cdp_checksum_status"),
		findStringByPath(node, "layers.edp.edp_checksum_status"),
		findStringByPath(node, "layers.wlan.wlan_fcs_status"),
		findStringByPath(node, "layers.stt.stt_checksum_status"),
		findBySuffix(layers, "ethfcsstatus"),
		findBySuffix(layers, "ipchecksumstatus"),
		findBySuffix(layers, "tcpchecksumstatus"),
		findBySuffix(layers, "udpchecksumstatus"),
		findBySuffix(layers, "sctpchecksumstatus"),
		findBySuffix(layers, "mstpchecksumstatus"),
		findBySuffix(layers, "cdpchecksumstatus"),
		findBySuffix(layers, "edpchecksumstatus"),
		findBySuffix(layers, "wlanfcsstatus"),
		findBySuffix(layers, "sttchecksumstatus"),
	}
	for _, f := range fields {
		if isBadStatus(f) {
			return true
		}
	}
	return false
}

func parseInt(raw string) int {
	if v, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
		return v
	}
	return 0
}

func parseInt64(raw string) int64 {
	if v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64); err == nil {
		return v
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func EstimatePackets(ctx context.Context, opts model.ParseOptions) (int, error) {
	args := []string{"-n", "-r", opts.FilePath}
	if opts.DisplayFilter != "" {
		args = append(args, "-Y", opts.DisplayFilter)
	}
	args = append(args, "-T", "fields", "-e", "frame.number")

	cmd, err := CommandContext(ctx, args...)
	if err != nil {
		return 0, fmt.Errorf("resolve tshark for estimate: %w", err)
	}
	log.Printf("tshark estimate: binary=%q file=%q filter=%q", cmd.Path, opts.FilePath, opts.DisplayFilter)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("create stdout pipe for estimate: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start tshark for estimate: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	count := 0
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		count++
	}

	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return 0, fmt.Errorf("scan tshark estimate output: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return 0, fmt.Errorf("wait tshark estimate: %w: %s", err, detail)
		}
		return 0, fmt.Errorf("wait tshark estimate: %w", err)
	}

	return count, nil
}

func findStringByPath(node map[string]any, key string) string {
	if value, ok := walk(node, strings.Split(key, ".")); ok {
		if s, ok := anyToString(value); ok {
			return s
		}
	}
	return ""
}

func findIntByPath(node map[string]any, key string) int {
	s := findStringByPath(node, key)
	if s == "" {
		return 0
	}
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return v
	}
	return 0
}

func findBySuffix(node any, suffix string) string {
	target := normalizeKey(suffix)
	if target == "" {
		return ""
	}

	var search func(current any) string
	search = func(current any) string {
		switch v := current.(type) {
		case map[string]any:
			for k, child := range v {
				norm := normalizeKey(k)
				if strings.HasSuffix(norm, target) {
					if str, ok := anyToString(child); ok && str != "" {
						return str
					}
				}
				if nested := search(child); nested != "" {
					return nested
				}
			}
		case []any:
			for _, child := range v {
				if nested := search(child); nested != "" {
					return nested
				}
			}
		}
		return ""
	}

	return search(node)
}

func findIntBySuffix(node any, suffix string) int {
	s := findBySuffix(node, suffix)
	if s == "" {
		return 0
	}
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return v
	}
	return 0
}

func pickFirstString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func pickFirstInt(values ...int) int {
	for _, v := range values {
		if v != 0 {
			return v
		}
	}
	return 0
}

func anyToString(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case int:
		return strconv.Itoa(v), true
	case int64:
		return strconv.FormatInt(v, 10), true
	case json.Number:
		return v.String(), true
	case []any:
		if len(v) == 0 {
			return "", false
		}
		return anyToString(v[0])
	}
	return "", false
}

func normalizeKey(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func walk(current any, path []string) (any, bool) {
	if len(path) == 0 {
		return current, true
	}
	obj, ok := current.(map[string]any)
	if !ok {
		return nil, false
	}
	next, ok := obj[path[0]]
	if !ok {
		return nil, false
	}
	return walk(next, path[1:])
}

func normalizeProto(proto string) string {
	p := strings.ToLower(proto)
	switch {
	case strings.Contains(p, "http"):
		return "HTTP"
	case strings.Contains(p, "usb"):
		return "USB"
	case strings.Contains(p, "icmpv6"):
		return "ICMPV6"
	case strings.Contains(p, "icmp"):
		return "ICMP"
	case strings.Contains(p, "arp"):
		return "ARP"
	case strings.Contains(p, "tls"):
		return "TLS"
	case strings.Contains(p, "dns"):
		return "DNS"
	case strings.Contains(p, "ssh"):
		return "SSHv2"
	case strings.Contains(p, "udp"):
		return "UDP"
	case strings.Contains(p, "tcp"):
		return "TCP"
	default:
		return "OTHER"
	}
}

func resolveDisplayProtocol(displayProtocol string, fallback string) string {
	if trimmed := strings.TrimSpace(displayProtocol); trimmed != "" {
		return trimmed
	}
	if normalized := normalizeProto(fallback); normalized != "OTHER" {
		return normalized
	}
	return "OTHER"
}

func normalizeTimestamp(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.Format("15:04:05.000000")
	}

	if ms, err := strconv.ParseInt(raw, 10, 64); err == nil {
		if len(raw) >= 13 {
			return time.UnixMilli(ms).UTC().Format("15:04:05.000")
		}
		return time.Unix(ms, 0).UTC().Format("15:04:05")
	}

	if sec, err := strconv.ParseFloat(raw, 64); err == nil {
		whole := int64(sec)
		ns := int64((sec - float64(whole)) * float64(time.Second))
		if ns < 0 {
			ns = 0
		}
		return time.Unix(whole, ns).UTC().Format("15:04:05.000000")
	}

	return raw
}

func extractPayload(node map[string]any, layers map[string]any) string {
	if s := pickFirstString(
		findStringByPath(node, "layers.http.http_file_data"),
		findStringByPath(node, "layers.data.data_data"),
		findStringByPath(node, "layers.tcp.tcp_payload"),
		findStringByPath(node, "layers.usb.usb_frame_data"),
		findStringByPath(node, "layers.usb.usb_control_response"),
		findStringByPath(node, "layers.usb.usb_capdata"),
		findStringByPath(node, "layers.usb.usb_data_fragment"),
		findBySuffix(layers, "httprequestline"),
		findBySuffix(layers, "httpresponseline"),
		findBySuffix(layers, "httpfiledata"),
		findBySuffix(layers, "datadata"),
		findBySuffix(layers, "tcppayload"),
		findBySuffix(layers, "usbframedata"),
		findBySuffix(layers, "usbcontrolresponse"),
		findBySuffix(layers, "usbcapdata"),
		findBySuffix(layers, "usbdatafragment"),
	); s != "" {
		return s
	}

	if s := pickFirstString(
		findStringByPath(node, "layers._ws.col.info"),
		findBySuffix(layers, "colinfo"),
	); s != "" {
		return s
	}

	return ""
}

func buildPacketInfo(node map[string]any, layers map[string]any) string {
	if s := buildHTTPInfo(node, layers); s != "" {
		return s
	}

	if s := pickFirstString(
		findStringByPath(node, "layers._ws.col.info"),
		findStringByPath(node, "layers._ws.col.Info"),
		findBySuffix(layers, "colinfo"),
	); s != "" {
		return s
	}

	if s := buildDNSInfo(node, layers); s != "" {
		return s
	}

	if s := pickFirstString(
		findBySuffix(layers, "expertmessage"),
		findBySuffix(layers, "requestline"),
		findBySuffix(layers, "responseline"),
		findBySuffix(layers, "qryname"),
		findBySuffix(layers, "msg"),
		findBySuffix(layers, "text"),
	); s != "" {
		return s
	}

	return ""
}

func buildHTTPInfo(node map[string]any, layers map[string]any) string {
	method := pickFirstString(
		findStringByPath(node, "layers.http.http_request_method"),
		findBySuffix(layers, "httprequestmethod"),
	)
	uri := pickFirstString(
		findStringByPath(node, "layers.http.http_request_uri"),
		findStringByPath(node, "layers.http.http_request_full_uri"),
		findBySuffix(layers, "httprequesturi"),
	)
	if method != "" {
		if uri != "" {
			return method + " " + uri
		}
		return method
	}

	code := pickFirstString(
		findStringByPath(node, "layers.http.http_response_code"),
		findBySuffix(layers, "httpresponsecode"),
	)
	phrase := pickFirstString(
		findStringByPath(node, "layers.http.http_response_phrase"),
		findBySuffix(layers, "httpresponsephrase"),
	)
	if code != "" {
		if phrase != "" {
			return code + " " + phrase
		}
		return code
	}

	if s := pickFirstString(
		findStringByPath(node, "layers.http.http_request_line"),
		findStringByPath(node, "layers.http.http_response_line"),
		findBySuffix(layers, "httprequestline"),
		findBySuffix(layers, "httpresponseline"),
	); s != "" {
		return s
	}

	return ""
}

func buildDNSInfo(node map[string]any, layers map[string]any) string {
	name := pickFirstString(
		findStringByPath(node, "layers.dns.dns_qry_name"),
		findBySuffix(layers, "dnsqryname"),
	)
	typeText := pickFirstString(
		findBySuffix(layers, "dnsqrytypename"),
		findBySuffix(layers, "dnstype"),
	)
	if name == "" {
		return ""
	}
	if typeText != "" {
		return typeText + " " + name
	}
	return name
}

func ExportObjects(pcapPath, exportDir string) error {
	cmd, err := Command("-r", pcapPath, "-q",
		"--export-objects", "http,"+exportDir,
		"--export-objects", "smb,"+exportDir,
		"--export-objects", "tftp,"+exportDir,
		"--export-objects", "dicom,"+exportDir,
		"--export-objects", "imf,"+exportDir,
	)
	if err != nil {
		return fmt.Errorf("resolve tshark for export objects: %w", err)
	}
	return cmd.Run()
}
