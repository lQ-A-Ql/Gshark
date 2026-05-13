package tshark

// Field-scan cache warm-up helpers.
//
// Warming up the field-scan cache runs representative tshark invocations
// immediately after a PCAP is loaded, so the first analyst-facing request
// for a protocol surface hits a populated cache. The warm plans below
// enumerate the exact (fields, options) tuples each feature uses in steady
// state; keeping them co-located with the warm entry points makes it easy
// to audit and extend the warm matrix.

// fieldScanWarmPlan captures the (fields, options) tuple used to pre-populate
// the field-scan cache for one feature surface.
type fieldScanWarmPlan struct {
	fields []string
	opts   fieldScanOptions
}

// WarmFieldScanCache performs a cache-populating scan for the supplied field
// list and options. The onRow callback is nil because callers only want the
// side-effect (cache fill) — rows are replayed later when a real analyst
// request arrives.
func WarmFieldScanCache(filePath string, fields []string, opts fieldScanOptions) error {
	return scanFieldRowsWithOptions(filePath, fields, opts, nil)
}

// WarmSpecializedFieldCache runs every warm plan in specializedFieldWarmPlans
// sequentially. If any plan fails, the error is returned immediately and the
// remaining plans are skipped — a degraded cache is still safer than a bad
// cache entry from a partial run.
func WarmSpecializedFieldCache(filePath string) error {
	for _, plan := range specializedFieldWarmPlans() {
		if err := WarmFieldScanCache(filePath, plan.fields, plan.opts); err != nil {
			return err
		}
	}
	return nil
}

// specializedFieldWarmPlans enumerates the warm matrix:
//   - industrial + vehicle protocol detail fields in a single large scan
//     (no display filter, all occurrences via the tshark default)
//   - RTSP/SDP media control fields with an aggregator suitable for
//     multi-value headers
//   - RTP media session fields with an rtp display filter
//
// Adding a new feature that benefits from a warm cache should append a new
// entry here rather than calling WarmFieldScanCache ad-hoc.
func specializedFieldWarmPlans() []fieldScanWarmPlan {
	return []fieldScanWarmPlan{
		{
			fields: unionFieldScanFields(
				modbusAnalysisFields,
				s7CommDetailFields,
				dnp3DetailFields,
				cipDetailFields,
				profinetDetailFields,
				bacnetDetailFields,
				iec104DetailFields,
				opcuaDetailFields,
				vehicleAnalysisFields,
				canPayloadAnalysisFields,
				dbcDecodedMessageFields,
			),
			opts: fieldScanOptions{},
		},
		{
			fields: mediaControlFields,
			opts: fieldScanOptions{
				DisplayFilter: "rtsp || sdp",
				Occurrence:    "a",
				Aggregator:    "|",
			},
		},
		{
			fields: mediaRTPFields,
			opts: fieldScanOptions{
				DisplayFilter: "rtp",
			},
		},
	}
}
