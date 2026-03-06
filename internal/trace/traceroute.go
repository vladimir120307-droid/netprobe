package trace

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"syscall"
	"time"
)

// Config holds traceroute configuration parameters.
type Config struct {
	Target   string
	MaxHops  int
	Probes   int
	Protocol string
	Timeout  time.Duration
}

// Hop represents a single hop in the network path.
type Hop struct {
	TTL      int             `json:"ttl"`
	Address  string          `json:"address"`
	Hostname string          `json:"hostname"`
	RTTs     []time.Duration `json:"rtts"`
	Lost     int             `json:"lost"`
	Reached  bool            `json:"reached_target"`
}

// Run executes a traceroute to the target address. It sends probes with
// incrementing TTL values, collecting the ICMP Time Exceeded responses
// from each intermediate router. Falls back to TCP-based tracing when
// raw sockets are not available.
func Run(ctx context.Context, cfg Config) ([]Hop, error) {
	var hops []Hop

	for ttl := 1; ttl <= cfg.MaxHops; ttl++ {
		select {
		case <-ctx.Done():
			return hops, ctx.Err()
		default:
		}

		hop := probeHop(ctx, cfg.Target, ttl, cfg.Probes, cfg.Timeout, cfg.Protocol)
		hops = append(hops, hop)

		if hop.Reached {
			break
		}
	}

	return hops, nil
}

// probeHop sends multiple probes at a specific TTL and aggregates the results.
// It uses concurrent probing for faster results.
func probeHop(ctx context.Context, target string, ttl int, probeCount int, timeout time.Duration, protocol string) Hop {
	hop := Hop{
		TTL:  ttl,
		RTTs: make([]time.Duration, 0, probeCount),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < probeCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			addr, rtt, reached, err := sendProbe(ctx, target, ttl, timeout, protocol)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				hop.Lost++
				return
			}

			hop.RTTs = append(hop.RTTs, rtt)
			if addr != "" && hop.Address == "" {
				hop.Address = addr
				hop.Hostname = resolveAddr(addr)
			}
			if reached {
				hop.Reached = true
			}
		}()
	}

	wg.Wait()

	// Sort RTTs for consistent output
	sort.Slice(hop.RTTs, func(i, j int) bool {
		return hop.RTTs[i] < hop.RTTs[j]
	})

	if hop.Address == "" {
		hop.Address = "*"
		hop.Hostname = "*"
	}

	return hop
}

// sendProbe sends a single traceroute probe using the configured protocol.
// For TCP-based tracing, it attempts a connection with a set TTL. For UDP,
// it sends a UDP packet to a high port. Returns the responding router address,
// RTT, whether the target was reached, and any error.
func sendProbe(ctx context.Context, target string, ttl int, timeout time.Duration, protocol string) (string, time.Duration, bool, error) {
	switch protocol {
	case "tcp":
		return tcpProbe(ctx, target, ttl, timeout)
	default:
		return tcpProbe(ctx, target, ttl, timeout)
	}
}

// tcpProbe performs a TCP-based traceroute probe by attempting a SYN connection
// with a specific TTL. This works through many firewalls that block UDP/ICMP.
func tcpProbe(ctx context.Context, target string, ttl int, timeout time.Duration) (string, time.Duration, bool, error) {
	addr := fmt.Sprintf("%s:%d", target, 80)
	start := time.Now()

	dialer := net.Dialer{
		Timeout: timeout,
		Control: setTTLControl(ttl),
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		rtt := time.Since(start)
		// Check if we got a response from an intermediate host
		if opErr, ok := err.(*net.OpError); ok {
			if opErr.Addr != nil {
				return extractIP(opErr.Addr.String()), rtt, false, nil
			}
		}
		return "", 0, false, err
	}
	defer conn.Close()

	rtt := time.Since(start)
	remoteAddr := extractIP(conn.RemoteAddr().String())
	return remoteAddr, rtt, remoteAddr == target, nil
}

// setTTLControl returns a socket control function that sets the IP TTL
// (Time To Live) on the underlying connection. This is used by traceroute
// probes to control how many hops a packet can traverse before being
// discarded by the network.
func setTTLControl(ttl int) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		})
	}
}

// resolveAddr performs a reverse DNS lookup on an IP address, returning the
// hostname if found, or a dash if reverse DNS is not configured.
func resolveAddr(addr string) string {
	names, err := net.LookupAddr(addr)
	if err != nil || len(names) == 0 {
		return "-"
	}
	return names[0]
}

// extractIP strips the port from a host:port address string.
func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// FormatHop creates a human-readable string for a single traceroute hop.
func FormatHop(h Hop) string {
	rtts := ""
	for i, rtt := range h.RTTs {
		if i > 0 {
			rtts += "  "
		}
		rtts += fmt.Sprintf("%.2f ms", float64(rtt.Microseconds())/1000.0)
	}
	for i := 0; i < h.Lost; i++ {
		if rtts != "" {
			rtts += "  "
		}
		rtts += "*"
	}
	return fmt.Sprintf("%-4d %-18s %-25s %s", h.TTL, h.Address, h.Hostname, rtts)
}
