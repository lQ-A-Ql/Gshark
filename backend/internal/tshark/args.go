package tshark

import (
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

const packetListFieldSeparator = "\x1f"

var fastListFields = []string{
	"frame.number",
	"frame.time_epoch",
	"ip.src",
	"ipv6.src",
	"arp.src.proto_ipv4",
	"ip.dst",
	"ipv6.dst",
	"arp.dst.proto_ipv4",
	"tcp.srcport",
	"udp.srcport",
	"tcp.dstport",
	"udp.dstport",
	"_ws.col.Protocol",
	"frame.len",
	"_ws.col.Info",
	"tcp.stream",
	"udp.stream",
	"udp.payload",
	"ip.hdr_len",
	"tcp.hdr_len",
	"tcp.analysis.flags",
	"tcp.analysis.window_update",
	"tcp.analysis.keep_alive",
	"tcp.analysis.keep_alive_ack",
	"tcp.flags.reset",
	"tcp.flags.syn",
	"tcp.flags.fin",
	"hsrp.state",
	"ospf.msg",
	"stp.type",
	"icmp.type",
	"icmpv6.type",
	"ip.ttl",
	"ipv6.hlim",
	"eth.dst",
	"eth.fcs.status",
	"ip.checksum.status",
	"tcp.checksum.status",
	"udp.checksum.status",
	"sctp.checksum.status",
	"mstp.checksum.status",
	"cdp.checksum.status",
	"edp.checksum.status",
	"wlan.fcs.status",
	"stt.checksum.status",
	"systemd_journal",
	"sysdig",
	"smb",
	"nbss",
	"nbns",
	"netbios",
	"dcerpc",
	"hsrp",
	"eigrp",
	"ospf",
	"bgp",
	"cdp",
	"vrrp",
	"carp",
	"gvrp",
	"igmp",
	"ismp",
	"rip",
	"glbp",
	"pim",
}

var firstScreenListFields = []string{
	"frame.number",
	"frame.time_epoch",
	"ip.src",
	"ipv6.src",
	"arp.src.proto_ipv4",
	"ip.dst",
	"ipv6.dst",
	"arp.dst.proto_ipv4",
	"tcp.srcport",
	"udp.srcport",
	"tcp.dstport",
	"udp.dstport",
	"_ws.col.Protocol",
	"frame.protocols",
	"frame.len",
	"_ws.col.Info",
	"tcp.stream",
	"udp.stream",
	"ip.hdr_len",
	"tcp.hdr_len",
}

var compatListFields = []string{
	"frame.number",
	"frame.time_epoch",
	"ip.src",
	"ipv6.src",
	"arp.src.proto_ipv4",
	"ip.dst",
	"ipv6.dst",
	"arp.dst.proto_ipv4",
	"tcp.srcport",
	"udp.srcport",
	"tcp.dstport",
	"udp.dstport",
	"_ws.col.Protocol",
	"frame.protocols",
	"frame.len",
	"_ws.col.Info",
	"tcp.stream",
	"udp.stream",
	"ip.hdr_len",
	"tcp.hdr_len",
}

func BuildFastListArgs(opts model.ParseOptions) []string {
	return buildPacketListArgs(opts, fastListFields)
}

func BuildFirstScreenListArgs(opts model.ParseOptions) []string {
	return buildPacketListArgs(opts, firstScreenListFields)
}

func BuildCompatListArgs(opts model.ParseOptions) []string {
	return buildPacketListArgs(opts, compatListFields)
}

func buildFastListScanArgs(opts model.ParseOptions) ([]string, fieldScanCapabilityPlan, error) {
	return buildCapabilityPlannedPacketListArgs(opts, fastListFields)
}

func buildFirstScreenListScanArgs(opts model.ParseOptions) ([]string, fieldScanCapabilityPlan, error) {
	return buildCapabilityPlannedPacketListArgs(opts, firstScreenListFields)
}

func buildCompatListScanArgs(opts model.ParseOptions) ([]string, fieldScanCapabilityPlan, error) {
	return buildCapabilityPlannedPacketListArgs(opts, compatListFields)
}

func buildCapabilityPlannedPacketListArgs(opts model.ParseOptions, fields []string) ([]string, fieldScanCapabilityPlan, error) {
	plan, err := planFieldScanByCapabilities(fields)
	if err != nil {
		return nil, plan, err
	}
	return buildPacketListArgs(opts, plan.tsharkFields), plan, nil
}

func buildPacketListArgs(opts model.ParseOptions, fields []string) []string {
	args := []string{"-n", "-r", opts.FilePath}
	if opts.DisplayFilter != "" {
		args = append(args, "-Y", opts.DisplayFilter)
	}
	args = appendTLSArgs(args, opts.TLS)
	args = append(args,
		"-T", "fields",
		"-E", "header=n",
		"-E", "occurrence=f",
		"-E", "separator="+packetListFieldSeparator,
		"-E", "quote=n",
	)
	for _, field := range fields {
		args = append(args, "-e", field)
	}
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
