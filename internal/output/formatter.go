package output

import (
	"time"

	"github.com/vladimir120307-droid/netprobe/internal/discovery"
	netdns "github.com/vladimir120307-droid/netprobe/internal/dns"
	nethttp "github.com/vladimir120307-droid/netprobe/internal/http"
	"github.com/vladimir120307-droid/netprobe/internal/ping"
	"github.com/vladimir120307-droid/netprobe/internal/scanner"
	"github.com/vladimir120307-droid/netprobe/internal/trace"
)

// Formatter provides output rendering for all netprobe commands. It delegates
// to the appropriate backend (table, JSON, or plain text) based on the
// format string provided at construction time.
type Formatter struct {
	format string
}

// NewFormatter creates a Formatter configured for the given output format.
// Supported values: "table" (default), "json", "plain".
func NewFormatter(format string) *Formatter {
	if format == "" {
		format = "table"
	}
	return &Formatter{format: format}
}

// FormatScanResults renders port scan results.
func (f *Formatter) FormatScanResults(target string, results []scanner.Result, elapsed time.Duration, openCount int) {
	switch f.format {
	case "json":
		data := map[string]interface{}{
			"target":     target,
			"open_ports": openCount,
			"elapsed_ms": elapsed.Milliseconds(),
			"results":    results,
		}
		PrintJSON(data)
	default:
		PrintScanTable(target, results, elapsed, openCount)
	}
}

// FormatPingStats renders ping statistics.
func (f *Formatter) FormatPingStats(host string, stats ping.Stats) {
	switch f.format {
	case "json":
		data := map[string]interface{}{
			"host":  host,
			"stats": stats,
		}
		PrintJSON(data)
	default:
		PrintPingTable(host, stats)
	}
}

// FormatDNSResults renders DNS lookup results.
func (f *Formatter) FormatDNSResults(domain, server string, results []netdns.RecordResult, elapsed time.Duration) {
	switch f.format {
	case "json":
		data := map[string]interface{}{
			"domain":     domain,
			"server":     server,
			"elapsed_ms": elapsed.Milliseconds(),
			"records":    results,
		}
		PrintJSON(data)
	default:
		PrintDNSTable(domain, server, results, elapsed)
	}
}

// FormatHTTPResult renders HTTP probe results including timing breakdown.
func (f *Formatter) FormatHTTPResult(result *nethttp.ProbeResult) {
	switch f.format {
	case "json":
		PrintJSON(result)
	default:
		PrintHTTPTable(result)
	}
}

// FormatTraceResults renders traceroute hop results.
func (f *Formatter) FormatTraceResults(target string, hops []trace.Hop) {
	switch f.format {
	case "json":
		data := map[string]interface{}{
			"target": target,
			"hops":   hops,
		}
		PrintJSON(data)
	default:
		PrintTraceTable(target, hops)
	}
}

// FormatDiscoveryResults renders subnet discovery results.
func (f *Formatter) FormatDiscoveryResults(hosts []discovery.Host, elapsed time.Duration) {
	switch f.format {
	case "json":
		data := map[string]interface{}{
			"hosts_found": len(hosts),
			"elapsed_ms":  elapsed.Milliseconds(),
			"hosts":       hosts,
		}
		PrintJSON(data)
	default:
		PrintDiscoveryTable(hosts, elapsed)
	}
}
