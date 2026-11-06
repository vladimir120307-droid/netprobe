package trace

import "syscall"

// setSocketTTL sets the IP TTL on a socket. Windows sockets are Handle values.
func setSocketTTL(fd uintptr, ttl int) {
	syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
}
