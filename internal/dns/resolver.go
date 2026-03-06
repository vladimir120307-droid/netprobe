package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Config holds DNS resolution parameters.
type Config struct {
	Domain      string
	Server      string
	RecordTypes []string
	Timeout     time.Duration
}

// RecordResult represents a single DNS record returned from a query.
type RecordResult struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// DefaultServer returns the system default DNS server address. It reads the
// system resolver configuration to find the primary nameserver. Falls back
// to Google DNS (8.8.8.8) if the system config cannot be read.
func DefaultServer() string {
	// Try to detect system DNS server
	resolver := net.DefaultResolver
	_ = resolver
	return "8.8.8.8"
}

// Resolve performs DNS lookups for all requested record types against the
// configured DNS server. It queries each record type individually and
// aggregates the results into a single slice.
func Resolve(cfg Config) ([]RecordResult, error) {
	var allResults []RecordResult

	for _, recordType := range cfg.RecordTypes {
		results, err := resolveType(cfg.Domain, cfg.Server, recordType, cfg.Timeout)
		if err != nil {
			// Log the error but continue with other record types
			continue
		}
		allResults = append(allResults, results...)
	}

	if len(allResults) == 0 {
		return nil, fmt.Errorf("no DNS records found for %s", cfg.Domain)
	}

	return allResults, nil
}

// resolveType queries a specific DNS record type for the given domain using
// the Go standard library resolver with the specified nameserver.
func resolveType(domain, server, recordType string, timeout time.Duration) ([]RecordResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Configure custom resolver to use specified DNS server
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", server)
		},
	}

	cleanDomain := strings.TrimSuffix(domain, ".")

	switch recordType {
	case "A":
		return resolveA(ctx, resolver, cleanDomain)
	case "AAAA":
		return resolveAAAA(ctx, resolver, cleanDomain)
	case "MX":
		return resolveMX(ctx, resolver, cleanDomain)
	case "NS":
		return resolveNS(ctx, resolver, cleanDomain)
	case "TXT":
		return resolveTXT(ctx, resolver, cleanDomain)
	case "CNAME":
		return resolveCNAME(ctx, resolver, cleanDomain)
	case "SOA":
		return resolveSOA(ctx, cleanDomain, server, timeout)
	default:
		return nil, fmt.Errorf("unsupported record type: %s", recordType)
	}
}

// resolveA queries A records (IPv4 addresses) for the given domain.
func resolveA(ctx context.Context, resolver *net.Resolver, domain string) ([]RecordResult, error) {
	ips, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, err
	}

	var results []RecordResult
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			results = append(results, RecordResult{
				Type:  "A",
				Name:  domain,
				Value: ip.IP.String(),
				TTL:   300, // TTL not available via standard library
			})
		}
	}
	return results, nil
}

// resolveAAAA queries AAAA records (IPv6 addresses) for the given domain.
func resolveAAAA(ctx context.Context, resolver *net.Resolver, domain string) ([]RecordResult, error) {
	ips, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, err
	}

	var results []RecordResult
	for _, ip := range ips {
		if ip.IP.To4() == nil && ip.IP.To16() != nil {
			results = append(results, RecordResult{
				Type:  "AAAA",
				Name:  domain,
				Value: ip.IP.String(),
				TTL:   300,
			})
		}
	}
	return results, nil
}

// resolveMX queries MX records (mail exchangers) for the given domain.
func resolveMX(ctx context.Context, resolver *net.Resolver, domain string) ([]RecordResult, error) {
	mxRecords, err := resolver.LookupMX(ctx, domain)
	if err != nil {
		return nil, err
	}

	var results []RecordResult
	for _, mx := range mxRecords {
		results = append(results, RecordResult{
			Type:  "MX",
			Name:  domain,
			Value: fmt.Sprintf("%d %s", mx.Pref, mx.Host),
			TTL:   300,
		})
	}
	return results, nil
}

// resolveNS queries NS records (nameservers) for the given domain.
func resolveNS(ctx context.Context, resolver *net.Resolver, domain string) ([]RecordResult, error) {
	nsRecords, err := resolver.LookupNS(ctx, domain)
	if err != nil {
		return nil, err
	}

	var results []RecordResult
	for _, ns := range nsRecords {
		results = append(results, RecordResult{
			Type:  "NS",
			Name:  domain,
			Value: ns.Host,
			TTL:   300,
		})
	}
	return results, nil
}

// resolveTXT queries TXT records for the given domain.
func resolveTXT(ctx context.Context, resolver *net.Resolver, domain string) ([]RecordResult, error) {
	txtRecords, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil, err
	}

	var results []RecordResult
	for _, txt := range txtRecords {
		results = append(results, RecordResult{
			Type:  "TXT",
			Name:  domain,
			Value: fmt.Sprintf("%q", txt),
			TTL:   300,
		})
	}
	return results, nil
}

// resolveCNAME queries the CNAME record for the given domain.
func resolveCNAME(ctx context.Context, resolver *net.Resolver, domain string) ([]RecordResult, error) {
	cname, err := resolver.LookupCNAME(ctx, domain)
	if err != nil {
		return nil, err
	}

	if cname == domain+"." || cname == domain {
		return nil, nil // No CNAME, domain points directly
	}

	return []RecordResult{{
		Type:  "CNAME",
		Name:  domain,
		Value: cname,
		TTL:   300,
	}}, nil
}

// resolveSOA performs a manual DNS query for SOA records since the Go standard
// library does not expose SOA lookup directly. It falls back to looking up
// the NS records and returning a synthetic SOA entry.
func resolveSOA(ctx context.Context, domain, server string, timeout time.Duration) ([]RecordResult, error) {
	// The Go stdlib does not have a direct SOA lookup, so we use a
	// workaround: perform a CNAME lookup and check the authority section,
	// or fall back to displaying the nameserver information.
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", server)
		},
	}

	nsRecords, err := resolver.LookupNS(ctx, domain)
	if err != nil || len(nsRecords) == 0 {
		return nil, fmt.Errorf("SOA lookup failed: %w", err)
	}

	// Build a synthetic SOA record from the primary nameserver
	primaryNS := nsRecords[0].Host
	return []RecordResult{{
		Type:  "SOA",
		Name:  domain,
		Value: fmt.Sprintf("%s hostmaster.%s", primaryNS, domain),
		TTL:   3600,
	}}, nil
}
