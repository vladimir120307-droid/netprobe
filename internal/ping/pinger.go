package ping

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Config holds the parameters for a ping operation.
type Config struct {
	Host     string
	Count    int
	Interval time.Duration
	Size     int
	Timeout  time.Duration
}

// Result represents a single ping attempt outcome.
type Result struct {
	Seq  int
	RTT  time.Duration
	TTL  int
	Err  error
	Addr string
}

// ResultCallback is called after each individual ping completes, allowing
// real-time output as pings are sent.
type ResultCallback func(Result)

// Run executes a ping operation, sending Count packets to the target host at
// the configured interval. It uses TCP connect as a cross-platform fallback
// when raw ICMP sockets are not available (which requires elevated privileges).
// Each result is passed to the callback for real-time output.
func Run(ctx context.Context, cfg Config, callback ResultCallback) ([]Result, error) {
	results := make([]Result, 0, cfg.Count)
	var mu sync.Mutex

	for i := 1; i <= cfg.Count; i++ {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		result := pingOnce(cfg.Host, i, cfg.Size, cfg.Timeout)

		mu.Lock()
		results = append(results, result)
		mu.Unlock()

		if callback != nil {
			callback(result)
		}

		// Wait the interval before the next ping (except after the last one)
		if i < cfg.Count {
			select {
			case <-ctx.Done():
				return results, ctx.Err()
			case <-time.After(cfg.Interval):
			}
		}
	}

	return results, nil
}

// pingOnce performs a single ping using TCP connect to port 80 or 443 as a
// fallback mechanism. True ICMP requires raw sockets and elevated privileges,
// so TCP connect provides a reliable cross-platform alternative that measures
// network round-trip time.
func pingOnce(host string, seq int, size int, timeout time.Duration) Result {
	result := Result{
		Seq:  seq,
		Addr: host,
	}

	// Try ICMP first via raw socket, fall back to TCP connect
	if rtt, ttl, err := icmpPing(host, seq, timeout); err == nil {
		result.RTT = rtt
		result.TTL = ttl
		return result
	}

	// TCP connect fallback - measures RTT via TCP handshake
	ports := []int{80, 443, 22}
	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", host, port)
		start := time.Now()

		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			continue
		}
		conn.Close()

		result.RTT = time.Since(start)
		result.TTL = 64 // Estimated TTL for TCP fallback
		return result
	}

	result.Err = fmt.Errorf("host unreachable (all probe ports failed)")
	return result
}

// icmpPing sends an ICMP echo request and waits for a reply. This requires
// raw socket access which typically needs root/admin privileges. Returns
// an error if raw sockets are not available, triggering the TCP fallback.
func icmpPing(host string, seq int, timeout time.Duration) (time.Duration, int, error) {
	// Build ICMP echo request packet
	id := uint16(seq) // Process-scoped identifier
	seqNum := uint16(seq)

	msg := buildICMPEchoRequest(id, seqNum)

	conn, err := net.DialTimeout("ip4:icmp", host, timeout)
	if err != nil {
		return 0, 0, fmt.Errorf("raw socket unavailable: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	start := time.Now()
	_, err = conn.Write(msg)
	if err != nil {
		return 0, 0, fmt.Errorf("write failed: %w", err)
	}

	reply := make([]byte, 1500)
	n, err := conn.Read(reply)
	if err != nil {
		return 0, 0, fmt.Errorf("read failed: %w", err)
	}
	rtt := time.Since(start)

	ttl := 0
	if n >= 9 {
		ttl = int(reply[8])
	}

	return rtt, ttl, nil
}

// buildICMPEchoRequest constructs a raw ICMP echo request packet with the
// given identifier and sequence number. The checksum is computed over the
// entire message body.
func buildICMPEchoRequest(id, seq uint16) []byte {
	msg := make([]byte, 8)
	msg[0] = 8  // Type: Echo Request
	msg[1] = 0  // Code: 0
	msg[2] = 0  // Checksum (placeholder)
	msg[3] = 0  // Checksum (placeholder)
	msg[4] = byte(id >> 8)
	msg[5] = byte(id & 0xff)
	msg[6] = byte(seq >> 8)
	msg[7] = byte(seq & 0xff)

	cs := icmpChecksum(msg)
	msg[2] = byte(cs >> 8)
	msg[3] = byte(cs & 0xff)

	return msg
}

// icmpChecksum computes the Internet checksum for an ICMP message as defined
// in RFC 1071. The checksum is the ones-complement of the ones-complement sum
// of the 16-bit words in the message.
func icmpChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)

	for i := 0; i+1 < length; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}

	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}
