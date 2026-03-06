package ping

import (
	"math"
	"time"
)

// Stats holds computed statistics for a series of ping results.
type Stats struct {
	PacketsSent     int           `json:"packets_sent"`
	PacketsReceived int           `json:"packets_received"`
	PacketLoss      float64       `json:"packet_loss_pct"`
	MinRTT          time.Duration `json:"min_rtt"`
	MaxRTT          time.Duration `json:"max_rtt"`
	AvgRTT          time.Duration `json:"avg_rtt"`
	StdDevRTT       time.Duration `json:"stddev_rtt"`
	Jitter          time.Duration `json:"jitter"`
}

// ComputeStats calculates comprehensive statistics from a slice of ping results.
// It computes min, max, average, standard deviation of round-trip times, as
// well as jitter (mean deviation between consecutive measurements) and packet
// loss percentage.
func ComputeStats(results []Result) Stats {
	stats := Stats{
		PacketsSent: len(results),
	}

	if len(results) == 0 {
		stats.PacketLoss = 100.0
		return stats
	}

	// Collect successful RTTs
	var rtts []time.Duration
	for _, r := range results {
		if r.Err == nil {
			rtts = append(rtts, r.RTT)
		}
	}

	stats.PacketsReceived = len(rtts)
	stats.PacketLoss = float64(stats.PacketsSent-stats.PacketsReceived) / float64(stats.PacketsSent) * 100.0

	if len(rtts) == 0 {
		return stats
	}

	// Calculate min, max, and sum
	stats.MinRTT = rtts[0]
	stats.MaxRTT = rtts[0]
	var totalNanos int64

	for _, rtt := range rtts {
		if rtt < stats.MinRTT {
			stats.MinRTT = rtt
		}
		if rtt > stats.MaxRTT {
			stats.MaxRTT = rtt
		}
		totalNanos += rtt.Nanoseconds()
	}

	// Average RTT
	avgNanos := totalNanos / int64(len(rtts))
	stats.AvgRTT = time.Duration(avgNanos)

	// Standard deviation
	if len(rtts) > 1 {
		var sumSquaredDiff float64
		avgFloat := float64(avgNanos)

		for _, rtt := range rtts {
			diff := float64(rtt.Nanoseconds()) - avgFloat
			sumSquaredDiff += diff * diff
		}

		variance := sumSquaredDiff / float64(len(rtts)-1)
		stats.StdDevRTT = time.Duration(math.Sqrt(variance))
	}

	// Jitter: mean absolute difference between consecutive RTTs
	if len(rtts) > 1 {
		stats.Jitter = computeJitter(rtts)
	}

	return stats
}

// computeJitter calculates the average absolute difference between consecutive
// round-trip time measurements. This metric indicates network stability: lower
// jitter means more consistent latency.
func computeJitter(rtts []time.Duration) time.Duration {
	if len(rtts) < 2 {
		return 0
	}

	var totalDiff int64
	for i := 1; i < len(rtts); i++ {
		diff := rtts[i].Nanoseconds() - rtts[i-1].Nanoseconds()
		if diff < 0 {
			diff = -diff
		}
		totalDiff += diff
	}

	avgDiff := totalDiff / int64(len(rtts)-1)
	return time.Duration(avgDiff)
}

// FormatRTT returns a human-readable string for a round-trip time duration,
// automatically choosing the appropriate unit (ns, us, ms, s).
func FormatRTT(d time.Duration) string {
	if d < time.Microsecond {
		return formatFloat(float64(d.Nanoseconds()), "ns")
	}
	if d < time.Millisecond {
		return formatFloat(float64(d.Microseconds()), "us")
	}
	if d < time.Second {
		return formatFloat(float64(d.Microseconds())/1000.0, "ms")
	}
	return formatFloat(float64(d.Milliseconds())/1000.0, "s")
}

func formatFloat(val float64, unit string) string {
	if val == float64(int64(val)) {
		return java_fmt(int64(val), unit)
	}
	return float_fmt(val, unit)
}

func java_fmt(val int64, unit string) string {
	return fmt_int(val) + " " + unit
}

func fmt_int(val int64) string {
	s := ""
	if val < 0 {
		s = "-"
		val = -val
	}
	digits := []byte{}
	if val == 0 {
		return "0"
	}
	for val > 0 {
		digits = append([]byte{byte(val%10) + '0'}, digits...)
		val /= 10
	}
	return s + string(digits)
}

func float_fmt(val float64, unit string) string {
	// Format to 2 decimal places
	intPart := int64(val)
	fracPart := int64((val - float64(intPart)) * 100)
	if fracPart < 0 {
		fracPart = -fracPart
	}
	result := fmt_int(intPart) + "."
	if fracPart < 10 {
		result += "0"
	}
	result += fmt_int(fracPart)
	return result + " " + unit
}
