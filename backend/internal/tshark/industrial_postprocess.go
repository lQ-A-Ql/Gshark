package tshark

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gshark/sentinel/backend/internal/model"
)

// modbusWriteFunctionCodes are Modbus function codes that perform write operations.
var modbusWriteFunctionCodes = map[int]bool{
	5:  true, // Write Single Coil
	6:  true, // Write Single Register
	15: true, // Write Multiple Coils
	16: true, // Write Multiple Registers
	22: true, // Mask Write Register
	23: true, // Read/Write Multiple Registers
}

// buildModbusSuspiciousWrites aggregates Modbus write transactions by target address,
// sorted by write count descending. Only request-side writes are counted.
func buildModbusSuspiciousWrites(transactions []model.ModbusTransaction) []model.ModbusSuspiciousWrite {
	if len(transactions) == 0 {
		return nil
	}

	type writeAgg struct {
		Target         string
		UnitID         int
		FunctionCode   int
		FunctionName   string
		WriteCount     int
		Sources        map[string]bool
		FirstTime      string
		LastTime       string
		SampleValues   []string
		SamplePacketID int64
	}

	aggMap := make(map[string]*writeAgg)

	for _, tx := range transactions {
		if !modbusWriteFunctionCodes[tx.FunctionCode] {
			continue
		}
		// Only count requests (not responses/exceptions)
		if tx.Kind != "request" {
			continue
		}

		target := tx.Reference
		if target == "" {
			target = fmt.Sprintf("Unit %d / FC %02d", tx.UnitID, tx.FunctionCode)
		}
		key := fmt.Sprintf("%d|%s|%d", tx.UnitID, target, tx.FunctionCode)

		agg, ok := aggMap[key]
		if !ok {
			agg = &writeAgg{
				Target:       target,
				UnitID:       tx.UnitID,
				FunctionCode: tx.FunctionCode,
				FunctionName: tx.FunctionName,
				Sources:      make(map[string]bool),
				FirstTime:    tx.Time,
			}
			aggMap[key] = agg
		}
		agg.WriteCount++
		agg.LastTime = tx.Time
		if tx.Source != "" {
			agg.Sources[tx.Source] = true
		}
		// Collect sample values (up to 5)
		sampleValue := ""
		if tx.RegisterValues != "" {
			sampleValue = tx.RegisterValues
		} else if tx.BitRange != nil && tx.BitRange.Preview != "" {
			sampleValue = tx.BitRange.Preview
		}
		if sampleValue != "" && len(agg.SampleValues) < 5 {
			agg.SampleValues = append(agg.SampleValues, sampleValue)
		}
		if agg.SamplePacketID == 0 {
			agg.SamplePacketID = tx.PacketID
		}
	}

	if len(aggMap) == 0 {
		return nil
	}

	result := make([]model.ModbusSuspiciousWrite, 0, len(aggMap))
	for _, agg := range aggMap {
		sources := make([]string, 0, len(agg.Sources))
		for src := range agg.Sources {
			sources = append(sources, src)
		}
		sort.Strings(sources)

		result = append(result, model.ModbusSuspiciousWrite{
			Target:         agg.Target,
			UnitID:         agg.UnitID,
			FunctionCode:   agg.FunctionCode,
			FunctionName:   agg.FunctionName,
			WriteCount:     agg.WriteCount,
			Sources:        sources,
			FirstTime:      agg.FirstTime,
			LastTime:       agg.LastTime,
			SampleValues:   agg.SampleValues,
			SamplePacketID: agg.SamplePacketID,
		})
	}

	// Sort by write count descending
	sort.Slice(result, func(i, j int) bool {
		return result[i].WriteCount > result[j].WriteCount
	})

	return result
}

// controlCommandKeywords maps protocol names to operation keywords that indicate control commands.
var controlCommandKeywords = map[string][]string{
	"IEC 104": {
		"c_sc_na", "c_dc_na", "c_rc_na",
		"c_se_na", "c_se_nb", "c_se_nc",
		"c_bo_na",
		"c_sc_ta", "c_dc_ta", "c_rc_ta",
		"c_se_ta", "c_se_tb", "c_se_tc",
		"c_bo_ta",
		"clock sync",
		"reset process",
		"interrogation",
	},
	"DNP3": {
		"direct operate",
		"select",
		"operate",
		"cold restart",
		"warm restart",
		"write",
		"enable unsolicited",
		"disable unsolicited",
	},
	"BACnet": {
		"write property",
		"reinitialize device",
	},
}

// extractControlCommands filters IndustrialProtocolDetail records for control/operate commands.
func extractControlCommands(details []model.IndustrialProtocolDetail) []model.IndustrialControlCommand {
	if len(details) == 0 {
		return nil
	}

	var commands []model.IndustrialControlCommand

	for _, detail := range details {
		keywords, hasKeywords := controlCommandKeywords[detail.Name]
		if !hasKeywords {
			continue
		}

		for _, record := range detail.Records {
			opLower := strings.ToLower(record.Operation)
			isControl := false
			for _, kw := range keywords {
				if strings.Contains(opLower, kw) {
					isControl = true
					break
				}
			}
			if !isControl {
				continue
			}

			commands = append(commands, model.IndustrialControlCommand{
				PacketID:    record.PacketID,
				Time:        record.Time,
				Protocol:    detail.Name,
				Source:      record.Source,
				Destination: record.Destination,
				Operation:   record.Operation,
				Target:      record.Target,
				Value:       record.Value,
				Result:      record.Result,
				Summary:     record.Summary,
			})
		}
	}

	return commands
}
