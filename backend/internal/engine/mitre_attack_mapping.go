package engine

import (
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

// MITRE ATT&CK technique and tactic IDs used in this mapping.
// Reference: https://attack.mitre.org/techniques/enterprise/
const (
	// Reconnaissance
	TIDActiveScanning   = "T1595" // Active Scanning
	TIDGatherVictimInfo = "T1592" // Gather Victim Host Information

	// Resource Development
	TIDObtainCapabilities = "T1588" // Obtain Capabilities

	// Initial Access
	TIDExploitPublicApp = "T1190" // Exploit Public-Facing Application
	TIDPhishing         = "T1566" // Phishing

	// Execution
	TIDCommandScriptExec = "T1059"     // Command and Scripting Interpreter
	TIDUnixShell         = "T1059.004" // Unix Shell
	TIDWindowsCmd        = "T1059.003" // Windows Command Shell
	TIDPowerShell        = "T1059.001" // PowerShell

	// Persistence
	TIDServerSoftwareComp = "T1505"     // Server Software Component
	TIDWebShell           = "T1505.003" // Server Software Component: Web Shell

	// Defense Evasion
	TIDObfuscatedFiles  = "T1027" // Obfuscated Files or Information
	TIDIndicatorRemoval = "T1070" // Indicator Removal

	// Credential Access
	TIDBruteForce = "T1110" // Brute Force

	// Discovery
	TIDNetworkServiceScan = "T1046" // Network Service Discovery

	// Lateral Movement
	TIDLateralToolTransfer = "T1570" // Lateral Tool Transfer

	// Command and Control
	TIDAppLayerProtocol    = "T1071"     // Application Layer Protocol
	TIDWebProtocols        = "T1071.001" // Web Protocols
	TIDDNS                 = "T1071.004" // DNS
	TIDEncryptedChannel    = "T1573"     // Encrypted Channel
	TIDNonStandardPort     = "T1571"     // Non-Standard Port
	TIDProxy               = "T1090"     // Proxy
	TIDMultiHopProxy       = "T1090.003" // Multi-hop Proxy
	TIDIngressToolTransfer = "T1105"     // Ingress Tool Transfer
	TIDProtocolTunneling   = "T1572"     // Protocol Tunneling

	// Collection
	TIDDataFromLocalSystem = "T1005" // Data from Local System

	// Exfiltration
	TIDExfilOverC2Channel = "T1041" // Exfiltration Over C2 Channel

	// Impact
	TIDManipulateControl = "T0831" // Manipulation of Control (ICS)

	// Tactics (for TacticIDs)
	TacticReconnaissance    = "TA0043"
	TacticResourceDev       = "TA0042"
	TacticInitialAccess     = "TA0001"
	TacticExecution         = "TA0002"
	TacticPersistence       = "TA0003"
	TacticDefenseEvasion    = "TA0005"
	TacticCredentialAccess  = "TA0006"
	TacticDiscovery         = "TA0007"
	TacticLateralMovement   = "TA0008"
	TacticCommandAndControl = "TA0011"
	TacticCollection        = "TA0009"
	TacticExfiltration      = "TA0010"
	TacticImpact            = "TA0040"
)

// mitreRuleMapping holds ATT&CK technique/tactic IDs for a detection rule.
type mitreRuleMapping struct {
	TechniqueIDs []string
	TacticIDs    []string
}

// mitreRuleMappings maps detection rule names to MITRE ATT&CK mappings.
// Keys are lowercase for case-insensitive matching.
var mitreRuleMappings = map[string]mitreRuleMapping{
	// --- WebShell detection ---
	"webshell": {
		TechniqueIDs: []string{TIDWebShell, TIDCommandScriptExec},
		TacticIDs:    []string{TacticPersistence, TacticExecution},
	},

	// --- C2 detection (Cobalt Strike / VShell / generic) ---
	"c2-http-beacon": {
		TechniqueIDs: []string{TIDWebProtocols, TIDAppLayerProtocol},
		TacticIDs:    []string{TacticCommandAndControl},
	},
	"c2-dns-channel": {
		TechniqueIDs: []string{TIDDNS, TIDAppLayerProtocol, TIDProtocolTunneling},
		TacticIDs:    []string{TacticCommandAndControl},
	},
	"c2-smb-pivot": {
		TechniqueIDs: []string{TIDLateralToolTransfer, TIDAppLayerProtocol},
		TacticIDs:    []string{TacticLateralMovement, TacticCommandAndControl},
	},
	"c2-tcp-stream": {
		TechniqueIDs: []string{TIDEncryptedChannel, TIDAppLayerProtocol},
		TacticIDs:    []string{TacticCommandAndControl},
	},
	"c2-websocket": {
		TechniqueIDs: []string{TIDWebProtocols, TIDProtocolTunneling},
		TacticIDs:    []string{TacticCommandAndControl},
	},
	"c2-indicator": {
		TechniqueIDs: []string{TIDAppLayerProtocol},
		TacticIDs:    []string{TacticCommandAndControl},
	},

	// --- Anomaly detection ---
	"异常扫描行为": {
		TechniqueIDs: []string{TIDNetworkServiceScan, TIDActiveScanning},
		TacticIDs:    []string{TacticDiscovery, TacticReconnaissance},
	},
	"非标准协议端口画像": {
		TechniqueIDs: []string{TIDNonStandardPort, TIDAppLayerProtocol},
		TacticIDs:    []string{TacticCommandAndControl},
	},

	// --- Flag / CTF detection (mapped to data collection/exfil) ---
	"flag 嗅探": {
		TechniqueIDs: []string{TIDDataFromLocalSystem},
		TacticIDs:    []string{TacticCollection},
	},
	"flag base64 变体": {
		TechniqueIDs: []string{TIDDataFromLocalSystem, TIDObfuscatedFiles},
		TacticIDs:    []string{TacticCollection, TacticDefenseEvasion},
	},
	"flag hex 变体": {
		TechniqueIDs: []string{TIDDataFromLocalSystem, TIDObfuscatedFiles},
		TacticIDs:    []string{TacticCollection, TacticDefenseEvasion},
	},

	// --- Steganography ---
	"隐写术初筛异常": {
		TechniqueIDs: []string{TIDObfuscatedFiles},
		TacticIDs:    []string{TacticDefenseEvasion},
	},

	// --- Brute force ---
	"bruteforce": {
		TechniqueIDs: []string{TIDBruteForce},
		TacticIDs:    []string{TacticCredentialAccess},
	},
	"login-bruteforce": {
		TechniqueIDs: []string{TIDBruteForce},
		TacticIDs:    []string{TacticCredentialAccess},
	},

	// --- Industrial control ---
	"modbus-write": {
		TechniqueIDs: []string{TIDManipulateControl},
		TacticIDs:    []string{TacticImpact},
	},
	"modbus 可疑写突发": {
		TechniqueIDs: []string{TIDManipulateControl},
		TacticIDs:    []string{TacticImpact},
	},

	// --- YARA hits (generic; specific YARA rules may refine) ---
	"yara 扫描异常": {
		TechniqueIDs: []string{TIDObtainCapabilities},
		TacticIDs:    []string{TacticResourceDev},
	},

	// --- Exploit / Initial Access ---
	"exploit": {
		TechniqueIDs: []string{TIDExploitPublicApp},
		TacticIDs:    []string{TacticInitialAccess},
	},
	"phishing": {
		TechniqueIDs: []string{TIDPhishing},
		TacticIDs:    []string{TacticInitialAccess},
	},

	// --- Encrypted/proxy C2 ---
	"encrypted-c2": {
		TechniqueIDs: []string{TIDEncryptedChannel, TIDAppLayerProtocol},
		TacticIDs:    []string{TacticCommandAndControl},
	},
	"proxy-c2": {
		TechniqueIDs: []string{TIDProxy, TIDMultiHopProxy},
		TacticIDs:    []string{TacticCommandAndControl},
	},
	"ingress-tool": {
		TechniqueIDs: []string{TIDIngressToolTransfer},
		TacticIDs:    []string{TacticCommandAndControl},
	},
}

// LookupMITREReturns the ATT&CK technique and tactic IDs for a given rule name.
// The lookup is case-insensitive and supports partial matching on the rule name.
func LookupMITREReturns(rule string) (techniqueIDs []string, tacticIDs []string) {
	normalized := strings.ToLower(strings.TrimSpace(rule))
	if normalized == "" {
		return nil, nil
	}

	// Exact match first.
	if m, ok := mitreRuleMappings[normalized]; ok {
		return append([]string(nil), m.TechniqueIDs...), append([]string(nil), m.TacticIDs...)
	}

	// Substring match: find the first mapping whose key is contained in the rule.
	for key, m := range mitreRuleMappings {
		if strings.Contains(normalized, key) {
			return append([]string(nil), m.TechniqueIDs...), append([]string(nil), m.TacticIDs...)
		}
	}

	// Category-based fallback heuristics.
	return lookupMITREByCategory(normalized)
}

// lookupMITREByCategory provides fallback ATT&CK mapping based on category keywords.
func lookupMITREByCategory(normalized string) (techniqueIDs []string, tacticIDs []string) {
	switch {
	case strings.Contains(normalized, "webshell") || strings.Contains(normalized, "shell"):
		return []string{TIDWebShell, TIDCommandScriptExec}, []string{TacticPersistence, TacticExecution}
	case strings.Contains(normalized, "c2") || strings.Contains(normalized, "beacon"):
		return []string{TIDAppLayerProtocol}, []string{TacticCommandAndControl}
	case strings.Contains(normalized, "dns"):
		return []string{TIDDNS, TIDProtocolTunneling}, []string{TacticCommandAndControl}
	case strings.Contains(normalized, "brute") || strings.Contains(normalized, "login"):
		return []string{TIDBruteForce}, []string{TacticCredentialAccess}
	case strings.Contains(normalized, "scan") || strings.Contains(normalized, "anomaly"):
		return []string{TIDNetworkServiceScan, TIDActiveScanning}, []string{TacticDiscovery, TacticReconnaissance}
	case strings.Contains(normalized, "steg") || strings.Contains(normalized, "隐写"):
		return []string{TIDObfuscatedFiles}, []string{TacticDefenseEvasion}
	case strings.Contains(normalized, "exploit"):
		return []string{TIDExploitPublicApp}, []string{TacticInitialAccess}
	case strings.Contains(normalized, "yara"):
		return []string{TIDObtainCapabilities}, []string{TacticResourceDev}
	case strings.Contains(normalized, "modbus") || strings.Contains(normalized, "industrial"):
		return []string{TIDManipulateControl}, []string{TacticImpact}
	case strings.Contains(normalized, "tunnel"):
		return []string{TIDProtocolTunneling, TIDNonStandardPort}, []string{TacticCommandAndControl}
	case strings.Contains(normalized, "flag") || strings.Contains(normalized, "ctf"):
		return []string{TIDDataFromLocalSystem}, []string{TacticCollection}
	default:
		return nil, nil
	}
}

// AnnotateThreatHitWithMITRE adds MITRE ATT&CK technique and tactic IDs to a ThreatHit
// based on its Rule and Category fields. Returns the annotated hit.
func AnnotateThreatHitWithMITRE(hit model.ThreatHit) model.ThreatHit {
	if len(hit.TechniqueIDs) > 0 {
		return hit // already annotated
	}
	techs, tactics := LookupMITREReturns(hit.Rule)
	if len(techs) == 0 {
		// Try category as fallback.
		techs, tactics = LookupMITREReturns(hit.Category)
	}
	if len(techs) > 0 {
		hit.TechniqueIDs = techs
	}
	if len(tactics) > 0 {
		hit.TacticIDs = tactics
	}
	return hit
}

// AnnotateThreatHitsWithMITRE annotates a slice of ThreatHits in-place.
func AnnotateThreatHitsWithMITRE(hits []model.ThreatHit) []model.ThreatHit {
	for i := range hits {
		hits[i] = AnnotateThreatHitWithMITRE(hits[i])
	}
	return hits
}

// AnnotateEvidenceRecordWithMITRE adds MITRE ATT&CK technique IDs to an EvidenceRecord
// based on its Summary and SourceType fields. Returns the annotated record.
func AnnotateEvidenceRecordWithMITRE(record model.EvidenceRecord) model.EvidenceRecord {
	if len(record.TechniqueIDs) > 0 {
		return record // already annotated
	}
	techs, _ := LookupMITREReturns(record.Summary)
	if len(techs) == 0 {
		techs, _ = LookupMITREReturns(record.SourceType)
	}
	if len(techs) == 0 {
		techs, _ = LookupMITREReturns(record.Module)
	}
	if len(techs) > 0 {
		record.TechniqueIDs = techs
	}
	return record
}

// AnnotateEvidenceRecordsWithMITRE annotates a slice of EvidenceRecords in-place.
func AnnotateEvidenceRecordsWithMITRE(records []model.EvidenceRecord) []model.EvidenceRecord {
	for i := range records {
		records[i] = AnnotateEvidenceRecordWithMITRE(records[i])
	}
	return records
}
