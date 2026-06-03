package engine

import (
	"fmt"
	"testing"
)

func TestDebugHeartbeatCalculation(t *testing.T) {
	// Timestamps from stream 208 WebSocket data (from debug output)
	times := []float64{
		51540.000, 51540.030, 51540.045, 51540.050, 51540.080,
		51542.000, 51542.190, 51542.419,
		51551.721, 51551.922,
		51563.269, 51563.643,
		51573.746,
		51574.187,
		51585.331, 51585.737,
		51595.881, 51596.310,
		51605.483, 51605.839,
		51616.243, 51616.500,
		51627.858, 51628.345,
		51638.769, 51639.232,
		51648.531, 51648.771,
		51657.909, 51658.187,
		51669.439, 51669.853,
		51681.353, 51681.462,
		51691.924, 51692.066,
		51703.294, 51703.608,
	}

	allIntervals := []float64{}
	longIntervals := []float64{}
	for i := 1; i < len(times); i++ {
		d := times[i] - times[i-1]
		if d > 0 {
			allIntervals = append(allIntervals, d)
			if d >= 3 {
				longIntervals = append(longIntervals, d)
			}
		}
	}

	avgAll, jitterAll := avgAndJitter(allIntervals)
	avgLong, jitterLong := avgAndJitter(longIntervals)

	fmt.Printf("All intervals: count=%d avg=%.3f jitter=%.3f\n", len(allIntervals), avgAll, jitterAll)
	fmt.Printf("Long intervals (>=3s): count=%d avg=%.3f jitter=%.3f\n", len(longIntervals), avgLong, jitterLong)
	fmt.Printf("Long intervals: %v\n", longIntervals)
	fmt.Printf("Passes all check: avg=%.3f>3=%v jitter=%.3f<0.35=%v\n", avgAll, avgAll > 3, jitterAll, jitterAll < 0.35)
	fmt.Printf("Passes long check: avg=%.3f>3=%v jitter=%.3f<0.35=%v\n", avgLong, avgLong > 3, jitterLong, jitterLong < 0.35)
}
