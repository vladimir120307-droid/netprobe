package scanner

import (
	"context"
	"fmt"
	"net"
	"time"
)

// ScanTCP performs a TCP connect scan on the given target and port. It attempts
// to establish a full TCP connection within the specified timeout. If the
// connection succeeds the port is reported as open, otherwise closed or filtered.
func ScanTCP(ctx context.Context, target string, port int, timeout interface{}) Result {
	result := Result{
		Port:  port,
		State: "closed",
		Proto: "tcp",
	}

	var dialTimeout time.Duration
	switch t := timeout.(type) {
	case time.Duration:
		dialTimeout = t
	default:
		dialTimeout = 5 * time.Second
	}

	addr := fmt.Sprintf("%s:%d", target, port)

	dialer := net.Dialer{
		Timeout: dialTimeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if isTimeoutError(err) {
			result.State = "filtered"
		}
		return result
	}
	defer conn.Close()

	result.State = "open"
	return result
}

// ScanTCPRange performs a TCP scan on a contiguous range of ports, returning
// only the open ones. This is a convenience wrapper around ScanTCP that runs
// each port sequentially within the provided context.
func ScanTCPRange(ctx context.Context, target string, startPort, endPort int, timeout interface{}) []Result {
	var results []Result
	for port := startPort; port <= endPort; port++ {
		select {
		case <-ctx.Done():
			return results
		default:
		}
		r := ScanTCP(ctx, target, port, timeout)
		if r.State == "open" {
			results = append(results, r)
		}
	}
	return results
}

// TCPBannerGrab attempts to read a service banner from an open TCP port.
// It connects, waits briefly for data, and returns whatever bytes are
// received. Common services like SSH, FTP, and SMTP send banners immediately
// after connection.
func TCPBannerGrab(target string, port int, timeout time.Duration) (string, error) {
	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		// Many services require us to send data first. Try sending
		// a generic probe and reading the response.
		conn2, err2 := net.DialTimeout("tcp", addr, timeout)
		if err2 != nil {
			return "", fmt.Errorf("banner grab failed: %w", err)
		}
		defer conn2.Close()

		conn2.SetWriteDeadline(time.Now().Add(timeout))
		conn2.Write([]byte("
"))
		conn2.SetReadDeadline(time.Now().Add(timeout))

		n2, err3 := conn2.Read(buf)
		if err3 != nil {
			return "", fmt.Errorf("banner grab failed after probe: %w", err3)
		}
		return sanitizeBanner(string(buf[:n2])), nil
	}

	return sanitizeBanner(string(buf[:n])), nil
}

// sanitizeBanner cleans up a raw banner string by removing control characters
// and trimming whitespace, making it safe for display in terminal output.
func sanitizeBanner(s string) string {
	var clean []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 32 && c < 127 {
			clean = append(clean, c)
		} else if c == '
' || c == '' || c == '	' {
			clean = append(clean, ' ')
		}
	}
	return string(clean)
}

// isTimeoutError checks whether an error indicates a network timeout, which
// is used to distinguish filtered ports from closed ones.
func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}
