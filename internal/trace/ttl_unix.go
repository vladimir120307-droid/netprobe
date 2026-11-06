//go:build unix

package trace

import "syscall"

// setSocketTTL sets the IP TTL on a socket. Unix descriptors are plain ints.
func setSocketTTL(fd uintptr, ttl int) {
	syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
}
