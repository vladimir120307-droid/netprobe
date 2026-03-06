package output

import (
	"fmt"
	"strings"
	"time"

	netdns "github.com/vladimir120307-droid/netprobe/internal/dns"
	nethttp "github.com/vladimir120307-droid/netprobe/internal/http"
	"github.com/vladimir120307-droid/netprobe/internal/discovery"
	"github.com/vladimir120307-droid/netprobe/internal/ping"
	"github.com/vladimir120307-droid/netprobe/internal/scanner"
	"github.com/vladimir120307-droid/netprobe/internal/trace"
	"github.com/vladimir120307-droid/netprobe/pkg/utils"
)

// PrintScanTable outputs port scan results in a formatted table.
func PrintScanTable(target string, results []scanner.Result, elapsed time.Duration, openCount int) {
	header := fmt.Sprintf("Scan report for %s", target)
	fmt.Println(utils.Bold(header))
	fmt.Println(strings.Repeat("-", len(header)+10))

	if len(results) == 0 {
		fmt.Println(utils.Yellow("No open ports found."))
		return
	}

	// Table header
	fmt.Printf("  %-8s %-10s %-18s %s\n",
		utils.Bold("PORT"), utils.Bold("STATE"), utils.Bold("SERVICE"), utils.Bold("VERSION"))
	fmt.Println(strings.Repeat("-", 60))

	for _, r := range results {
		stateColor := utils.Green(r.State)
		if r.State == "filtered" {
			stateColor = utils.Yellow(r.State)
		}
		svc := r.Service
		if svc == "" {
			svc = "unknown"
		}
		ver := r.Version
		if ver == "" {
			ver = ""
		}
		fmt.Printf("  %-8s %-10s %-18s %s\n",
			fmt.Sprintf("%d/%s", r.Port, r.Proto),
			stateColor, svc, ver)
	}

	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("  %s open ports found in %s\n",
		utils.Bold(fmt.Sprintf("%d", openCount)),
		utils.Cyan(elapsed.Round(time.Millisecond).String()))
}

// PrintPingTable outputs ping statistics in a formatted summary.
func PrintPingTable(host string, stats ping.Stats) {
	fmt.Printf("--- %s ping statistics ---\n", utils.Bold(host))
	fmt.Printf("%d packets transmitted, %d received, %.1f%% packet loss\n",
		stats.PacketsSent, stats.PacketsReceived, stats.PacketLoss)
	fmt.Println()

	if stats.PacketsReceived == 0 {
		fmt.Println(utils.Red("All packets lost."))
		return
	}

	fmt.Printf("  %-12s %s\n", "min:", utils.Cyan(formatDuration(stats.MinRTT)))
	fmt.Printf("  %-12s %s\n", "avg:", utils.Cyan(formatDuration(stats.AvgRTT)))
	fmt.Printf("  %-12s %s\n", "max:", utils.Cyan(formatDuration(stats.MaxRTT)))
	fmt.Printf("  %-12s %s\n", "stddev:", formatDuration(stats.StdDevRTT))
	fmt.Printf("  %-12s %s\n", "jitter:", formatDuration(stats.Jitter))
}

// PrintDNSTable outputs DNS records in a formatted table.
func PrintDNSTable(domain, server string, results []netdns.RecordResult, elapsed time.Duration) {
	header := fmt.Sprintf("DNS records for %s (server: %s)", domain, server)
	fmt.Println(utils.Bold(header))
	fmt.Println(strings.Repeat("-", len(header)+10))

	fmt.Printf("  %-8s %-30s %-40s %s\n",
		utils.Bold("TYPE"), utils.Bold("NAME"), utils.Bold("VALUE"), utils.Bold("TTL"))
	fmt.Println(strings.Repeat("-", 85))

	for _, r := range results {
		typeColor := utils.Cyan(r.Type)
		fmt.Printf("  %-8s %-30s %-40s %d\n", typeColor, r.Name, r.Value, r.TTL)
	}

	fmt.Println(strings.Repeat("-", 85))
	fmt.Printf("  %d records returned in %s\n",
		len(results), utils.Cyan(elapsed.Round(time.Millisecond).String()))
}

// PrintHTTPTable outputs HTTP probe results in a formatted display.
func PrintHTTPTable(result *nethttp.ProbeResult) {
	fmt.Println(utils.Bold("HTTP Probe Result"))
	fmt.Println(strings.Repeat("-", 60))

	statusColor := utils.Green(result.Status)
	if result.StatusCode >= 400 {
		statusColor = utils.Red(result.Status)
	} else if result.StatusCode >= 300 {
		statusColor = utils.Yellow(result.Status)
	}

	fmt.Printf("  %-16s %s\n", "URL:", utils.Cyan(result.URL))
	fmt.Printf("  %-16s %s\n", "Method:", result.Method)
	fmt.Printf("  %-16s %s\n", "Status:", statusColor)
	fmt.Printf("  %-16s %s\n", "Protocol:", result.Proto)
	fmt.Printf("  %-16s %d bytes\n", "Content-Length:", result.ContentLength)
	fmt.Println()

	// Timing breakdown
	fmt.Println(utils.Bold("  Timing Breakdown:"))
	t := result.Timing
	fmt.Printf("    %-16s %s\n", "DNS Lookup:", formatDuration(t.DNSLookup))
	fmt.Printf("    %-16s %s\n", "TCP Connect:", formatDuration(t.TCPConnect))
	fmt.Printf("    %-16s %s\n", "TLS Handshake:", formatDuration(t.TLSHandshake))
	fmt.Printf("    %-16s %s\n", "TTFB:", formatDuration(t.TTFB))
	fmt.Printf("    %-16s %s\n", "Total:", utils.Bold(formatDuration(t.Total)))

	// Redirect chain
	if len(result.RedirectChain) > 0 {
		fmt.Println()
		fmt.Println(utils.Bold("  Redirect Chain:"))
		for i, url := range result.RedirectChain {
			fmt.Printf("    %d. %s\n", i+1, url)
		}
	}

	// Response headers
	if result.ShowHeaders && len(result.Headers) > 0 {
		fmt.Println()
		fmt.Println(utils.Bold("  Response Headers:"))
		for key, val := range result.Headers {
			fmt.Printf("    %s: %s\n", utils.Cyan(key), val)
		}
	}

	// TLS certificate info
	if result.ShowTLS && result.TLS != nil {
		fmt.Println()
		fmt.Println(utils.Bold("  TLS Certificate:"))
		fmt.Printf("    %-16s %s\n", "Subject:", result.TLS.Subject)
		fmt.Printf("    %-16s %s\n", "Issuer:", result.TLS.Issuer)
		fmt.Printf("    %-16s %s\n", "Not Before:", result.TLS.NotBefore)
		fmt.Printf("    %-16s %s\n", "Not After:", result.TLS.NotAfter)
		fmt.Printf("    %-16s %s\n", "Expiry:", nethttp.CertExpiryStatus(result.TLS.DaysLeft))
		fmt.Printf("    %-16s %s\n", "Protocol:", result.TLS.Protocol)
		fmt.Printf("    %-16s %s\n", "Cipher:", result.TLS.CipherSuite)
		fmt.Printf("    %-16s %s\n", "Algorithm:", result.TLS.SignAlgo)
		if len(result.TLS.SANs) > 0 {
			fmt.Printf("    %-16s %s\n", "SANs:", strings.Join(result.TLS.SANs, ", "))
		}
	}
}

// PrintTraceTable outputs traceroute hops in a formatted table.
func PrintTraceTable(target string, hops []trace.Hop) {
	fmt.Printf("  %-4s %-18s %-28s %s\n",
		utils.Bold("HOP"), utils.Bold("ADDRESS"), utils.Bold("HOSTNAME"), utils.Bold("RTT"))
	fmt.Println(strings.Repeat("-", 80))

	for _, h := range hops {
		rtts := formatHopRTTs(h)
		addrColor := h.Address
		if h.Address != "*" {
			addrColor = utils.Cyan(h.Address)
		}
		fmt.Printf("  %-4d %-18s %-28s %s\n", h.TTL, addrColor, h.Hostname, rtts)
	}

	fmt.Println(strings.Repeat("-", 80))
}

// PrintDiscoveryTable outputs discovered hosts in a formatted table.
func PrintDiscoveryTable(hosts []discovery.Host, elapsed time.Duration) {
	fmt.Printf("  %-18s %-20s %-30s %-14s %s\n",
		utils.Bold("IP ADDRESS"), utils.Bold("MAC ADDRESS"),
		utils.Bold("HOSTNAME"), utils.Bold("VENDOR"), utils.Bold("LATENCY"))
	fmt.Println(strings.Repeat("-", 100))

	for _, h := range hosts {
		latency := formatDuration(h.Latency)
		fmt.Printf("  %-18s %-20s %-30s %-14s %s\n",
			utils.Cyan(h.IP), h.MAC, h.Hostname, h.Vendor, latency)
	}

	fmt.Println(strings.Repeat("-", 100))
	fmt.Printf("  %s hosts discovered in %s\n",
		utils.Bold(fmt.Sprintf("%d", len(hosts))),
		utils.Cyan(elapsed.Round(time.Millisecond).String()))
}

// formatDuration returns a human-readable duration string.
func formatDuration(d time.Duration) string {
	if d == 0 {
		return "0ms"
	}
	if d < time.Microsecond {
		return fmt.Sprintf("%dns", d.Nanoseconds())
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%.2fus", float64(d.Nanoseconds())/1000.0)
	}
	if d < time.Second {
		return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000.0)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

// formatHopRTTs builds a display string for traceroute hop RTTs.
func formatHopRTTs(h trace.Hop) string {
	var parts []string
	for _, rtt := range h.RTTs {
		parts = append(parts, fmt.Sprintf("%.2fms", float64(rtt.Microseconds())/1000.0))
	}
	for i := 0; i < h.Lost; i++ {
		parts = append(parts, "*")
	}
	return strings.Join(parts, "  ")
}
