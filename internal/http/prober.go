package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	gohttp "net/http"
	"net/http/httptrace"
	"strings"
	"time"
)

// ProbeConfig configures an HTTP probe operation.
type ProbeConfig struct {
	URL             string
	Method          string
	Headers         map[string]string
	FollowRedirects bool
	Timeout         time.Duration
	ShowHeaders     bool
	ShowTLS         bool
}

// Timing holds the detailed timing breakdown of an HTTP request.
type Timing struct {
	DNSLookup    time.Duration `json:"dns_lookup_ms"`
	TCPConnect   time.Duration `json:"tcp_connect_ms"`
	TLSHandshake time.Duration `json:"tls_handshake_ms"`
	TTFB         time.Duration `json:"ttfb_ms"`
	Total        time.Duration `json:"total_ms"`
}

// ProbeResult contains the complete results of an HTTP probe.
type ProbeResult struct {
	URL            string            `json:"url"`
	Method         string            `json:"method"`
	StatusCode     int               `json:"status_code"`
	Status         string            `json:"status"`
	Timing         Timing            `json:"timing"`
	Headers        map[string]string `json:"headers,omitempty"`
	TLS            *TLSInfo          `json:"tls,omitempty"`
	ContentLength  int64             `json:"content_length"`
	RedirectChain  []string          `json:"redirect_chain,omitempty"`
	Proto          string            `json:"protocol"`
	ShowHeaders    bool              `json:"-"`
	ShowTLS        bool              `json:"-"`
}

// Probe executes an HTTP probe against the configured URL. It measures detailed
// timing for each phase of the request (DNS, connect, TLS, TTFB) using Go's
// httptrace package, and optionally collects response headers and TLS info.
func Probe(cfg ProbeConfig) (*ProbeResult, error) {
	result := &ProbeResult{
		URL:         cfg.URL,
		Method:      cfg.Method,
		ShowHeaders: cfg.ShowHeaders,
		ShowTLS:     cfg.ShowTLS,
	}

	// Timing state variables
	var dnsStart, connStart, tlsStart time.Time
	var dnsEnd, connEnd, tlsEnd time.Time

	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			dnsEnd = time.Now()
		},
		ConnectStart: func(network, addr string) {
			connStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			connEnd = time.Now()
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			tlsEnd = time.Now()
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	req, err := gohttp.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), cfg.Method, cfg.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "netprobe/1.0")
	for key, val := range cfg.Headers {
		req.Header.Set(key, val)
	}

	// Configure transport
	transport := &gohttp.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		ForceAttemptHTTP2: true,
	}

	client := &gohttp.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}

	if !cfg.FollowRedirects {
		client.CheckRedirect = func(req *gohttp.Request, via []*gohttp.Request) error {
			return gohttp.ErrUseLastResponse
		}
	} else {
		client.CheckRedirect = func(req *gohttp.Request, via []*gohttp.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects (max 10)")
			}
			result.RedirectChain = append(result.RedirectChain, req.URL.String())
			return nil
		}
	}

	requestStart := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read the body to get the complete timing
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	requestEnd := time.Now()

	// Populate timing
	result.Timing.Total = requestEnd.Sub(requestStart)
	if !dnsStart.IsZero() && !dnsEnd.IsZero() {
		result.Timing.DNSLookup = dnsEnd.Sub(dnsStart)
	}
	if !connStart.IsZero() && !connEnd.IsZero() {
		result.Timing.TCPConnect = connEnd.Sub(connStart)
	}
	if !tlsStart.IsZero() && !tlsEnd.IsZero() {
		result.Timing.TLSHandshake = tlsEnd.Sub(tlsStart)
	}

	// TTFB is the time from sending the request to receiving the first byte
	result.Timing.TTFB = result.Timing.Total - result.Timing.DNSLookup

	// Status
	result.StatusCode = resp.StatusCode
	result.Status = resp.Status
	result.Proto = resp.Proto
	result.ContentLength = int64(len(body))

	// Headers
	if cfg.ShowHeaders {
		result.Headers = make(map[string]string)
		for key, values := range resp.Header {
			result.Headers[key] = strings.Join(values, ", ")
		}
	}

	// TLS info
	if cfg.ShowTLS && resp.TLS != nil {
		result.TLS = ExtractTLSInfo(resp.TLS)
	}

	return result, nil
}

// FormatTiming returns a human-readable timing breakdown string.
func FormatTiming(t Timing) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("DNS: %.2fms", float64(t.DNSLookup.Microseconds())/1000.0))
	parts = append(parts, fmt.Sprintf("Connect: %.2fms", float64(t.TCPConnect.Microseconds())/1000.0))
	parts = append(parts, fmt.Sprintf("TLS: %.2fms", float64(t.TLSHandshake.Microseconds())/1000.0))
	parts = append(parts, fmt.Sprintf("TTFB: %.2fms", float64(t.TTFB.Microseconds())/1000.0))
	parts = append(parts, fmt.Sprintf("Total: %.2fms", float64(t.Total.Microseconds())/1000.0))
	return strings.Join(parts, " | ")
}
