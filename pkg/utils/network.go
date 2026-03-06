package utils

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ResolveHostname resolves a hostname to its first IPv4 address. If the input
// is already a valid IP address it is returned unchanged. Returns an error
// if DNS resolution fails entirely.
func ResolveHostname(host string) (string, error) {
	ip := net.ParseIP(host)
	if ip != nil {
		return host, nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}

	// Prefer IPv4
	for _, addr := range ips {
		if v4 := addr.To4(); v4 != nil {
			return v4.String(), nil
		}
	}

	// Fall back to IPv6
	if len(ips) > 0 {
		return ips[0].String(), nil
	}

	return "", fmt.Errorf("no addresses found for %s", host)
}

// ParsePortRange parses a port specification string into a sorted slice of
// unique port numbers. Supports individual ports, comma-separated lists,
// and ranges using dash notation.
//
// Examples:
//
//	"80"          -> [80]
//	"22,80,443"   -> [22, 80, 443]
//	"1-1024"      -> [1, 2, ..., 1024]
//	"22,80,8000-8100" -> [22, 80, 8000, 8001, ..., 8100]
func ParsePortRange(spec string) ([]int, error) {
	if spec == "" {
		return nil, fmt.Errorf("empty port specification")
	}

	seen := make(map[int]bool)
	var ports []int

	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port number %q: %w", rangeParts[0], err)
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port number %q: %w", rangeParts[1], err)
			}
			if err := validatePort(start); err != nil {
				return nil, err
			}
			if err := validatePort(end); err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("invalid port range: %d > %d", start, end)
			}
			for p := start; p <= end; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port number %q: %w", part, err)
			}
			if err := validatePort(p); err != nil {
				return nil, err
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports in specification %q", spec)
	}

	// Sort ports
	sortInts(ports)
	return ports, nil
}

// validatePort checks that a port number is within the valid TCP/UDP range.
func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d out of range (1-65535)", port)
	}
	return nil
}

// sortInts sorts a slice of ints in ascending order using insertion sort.
// Avoids importing sort for this small utility.
func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		key := a[i]
		j := i - 1
		for j >= 0 && a[j] > key {
			a[j+1] = a[j]
			j--
		}
		a[j+1] = key
	}
}

// IsPrivateIP returns true if the given IP address is in a private (RFC 1918)
// or loopback address range.
func IsPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"fc00::/7",
		"::1/128",
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

// FormatBytes converts a byte count to a human-readable string using
// binary SI prefixes (KiB, MiB, GiB).
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	suffixes := []string{"KiB", "MiB", "GiB", "TiB"}
	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), suffixes[exp])
}

// LocalIP returns the primary outbound IP address of the machine by dialing
// a well-known external address. Does not actually send any traffic.
func LocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}
