package discovery

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// SubnetInfo holds parsed subnet information derived from CIDR notation.
type SubnetInfo struct {
	Network   string   `json:"network"`
	Broadcast string   `json:"broadcast"`
	Netmask   string   `json:"netmask"`
	CIDR      string   `json:"cidr"`
	HostCount int      `json:"host_count"`
	FirstHost string   `json:"first_host"`
	LastHost  string   `json:"last_host"`
	PrefixLen int      `json:"prefix_length"`
	AllHosts  []string `json:"-"`
}

// Config holds host discovery configuration.
type Config struct {
	Subnet  *SubnetInfo
	Workers int
	Timeout time.Duration
}

// Host represents a discovered host on the network.
type Host struct {
	IP       string        `json:"ip"`
	MAC      string        `json:"mac"`
	Hostname string        `json:"hostname"`
	Vendor   string        `json:"vendor"`
	Latency  time.Duration `json:"latency_ms"`
}

// ParseSubnet parses a CIDR notation string and calculates all subnet parameters
// including network address, broadcast, usable host range, and enumerates all
// host addresses for scanning.
func ParseSubnet(cidr string) (*SubnetInfo, error) {
	if !strings.Contains(cidr, "/") {
		cidr = cidr + "/32"
	}

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("only IPv4 subnets are supported")
	}

	networkIP := ipNet.IP.To4()
	if networkIP == nil {
		return nil, fmt.Errorf("invalid IPv4 address")
	}

	networkUint := binary.BigEndian.Uint32(networkIP)
	hostBits := uint(bits - ones)
	hostCount := int(math.Pow(2, float64(hostBits))) - 2

	if hostCount < 0 {
		hostCount = 0
	}
	if ones == 32 {
		hostCount = 1
	}

	broadcastUint := networkUint | uint32(math.Pow(2, float64(hostBits)))-1
	broadcastIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(broadcastIP, broadcastUint)

	maskIP := net.IP(ipNet.Mask)

	info := &SubnetInfo{
		Network:   networkIP.String(),
		Broadcast: broadcastIP.String(),
		Netmask:   maskIP.String(),
		CIDR:      cidr,
		HostCount: hostCount,
		PrefixLen: ones,
	}

	if ones == 32 {
		info.FirstHost = ip.String()
		info.LastHost = ip.String()
		info.AllHosts = []string{ip.String()}
	} else if ones == 31 {
		info.HostCount = 2
		first := make(net.IP, 4)
		binary.BigEndian.PutUint32(first, networkUint)
		second := make(net.IP, 4)
		binary.BigEndian.PutUint32(second, networkUint+1)
		info.FirstHost = first.String()
		info.LastHost = second.String()
		info.AllHosts = []string{first.String(), second.String()}
	} else {
		firstUint := networkUint + 1
		lastUint := broadcastUint - 1

		firstIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(firstIP, firstUint)
		lastIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(lastIP, lastUint)

		info.FirstHost = firstIP.String()
		info.LastHost = lastIP.String()

		if hostCount <= 65534 {
			info.AllHosts = make([]string, 0, hostCount)
			for i := firstUint; i <= lastUint; i++ {
				hostIP := make(net.IP, 4)
				binary.BigEndian.PutUint32(hostIP, i)
				info.AllHosts = append(info.AllHosts, hostIP.String())
			}
		}
	}

	return info, nil
}

// Run performs host discovery on the configured subnet. It uses concurrent
// TCP probing to common ports to determine which hosts are alive. Discovered
// hosts are resolved for hostname and MAC address information.
func Run(ctx context.Context, cfg Config) ([]Host, error) {
	if cfg.Subnet == nil || len(cfg.Subnet.AllHosts) == 0 {
		return nil, fmt.Errorf("no hosts to scan in subnet")
	}

	workers := cfg.Workers
	if workers <= 0 {
		workers = 50
	}

	var (
		hostsMu sync.Mutex
		hosts   []Host
		wg      sync.WaitGroup
		sem     = make(chan struct{}, workers)
	)

	for _, ip := range cfg.Subnet.AllHosts {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(targetIP string) {
			defer wg.Done()
			defer func() { <-sem }()

			host, alive := probeHost(ctx, targetIP, cfg.Timeout)
			if alive {
				hostsMu.Lock()
				hosts = append(hosts, host)
				hostsMu.Unlock()
			}
		}(ip)
	}

	wg.Wait()

	sort.Slice(hosts, func(i, j int) bool {
		return IPtoUint32(net.ParseIP(hosts[i].IP)) < IPtoUint32(net.ParseIP(hosts[j].IP))
	})

	return hosts, nil
}

// probeHost attempts to determine if a host is alive by trying TCP connections
// to common ports. If any port responds (open or refused), the host is alive.
func probeHost(ctx context.Context, ip string, timeout time.Duration) (Host, bool) {
	host := Host{IP: ip}

	probePorts := []int{80, 443, 22, 445, 139, 135, 3389, 8080, 21, 25}

	for _, port := range probePorts {
		select {
		case <-ctx.Done():
			return host, false
		default:
		}

		addr := fmt.Sprintf("%s:%d", ip, port)
		start := time.Now()

		conn, err := net.DialTimeout("tcp", addr, timeout)
		latency := time.Since(start)

		if err == nil {
			conn.Close()
			host.Latency = latency
			enrichHost(&host)
			return host, true
		}

		if isConnectionRefused(err) {
			host.Latency = latency
			enrichHost(&host)
			return host, true
		}
	}

	return host, false
}

// enrichHost populates additional information for a discovered host including
// hostname (via reverse DNS) and MAC address (from the local ARP table).
func enrichHost(host *Host) {
	names, err := net.LookupAddr(host.IP)
	if err == nil && len(names) > 0 {
		host.Hostname = names[0]
		if len(host.Hostname) > 0 && host.Hostname[len(host.Hostname)-1] == '.' {
			host.Hostname = host.Hostname[:len(host.Hostname)-1]
		}
	} else {
		host.Hostname = "-"
	}

	host.MAC = lookupMAC(host.IP)
	if host.MAC != "" && host.MAC != "-" {
		host.Vendor = lookupVendor(host.MAC)
	}
}

// lookupMAC attempts to find the MAC address for an IP from the system ARP table.
func lookupMAC(ip string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "-"
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.String() == ip {
					return iface.HardwareAddr.String()
				}
			}
		}
	}

	return "-"
}

// lookupVendor returns the hardware vendor name based on the OUI (first 3 bytes)
// of a MAC address. Contains a curated list of common vendors.
func lookupVendor(mac string) string {
	if len(mac) < 8 {
		return "-"
	}

	ouiDB := map[string]string{
		"00:50:56": "VMware",
		"00:0c:29": "VMware",
		"00:1c:42": "Parallels",
		"08:00:27": "VirtualBox",
		"dc:a6:32": "Raspberry Pi",
		"b8:27:eb": "Raspberry Pi",
		"e4:5f:01": "Raspberry Pi",
		"ac:de:48": "Intel Corp.",
		"00:1b:21": "Intel Corp.",
		"3c:22:fb": "Apple Inc.",
		"a4:83:e7": "Apple Inc.",
		"f0:18:98": "Apple Inc.",
		"14:7d:da": "Apple Inc.",
		"00:25:00": "Apple Inc.",
		"68:5b:35": "Apple Inc.",
		"30:de:4b": "TP-Link",
		"50:c7:bf": "TP-Link",
		"e8:de:27": "TP-Link",
		"c0:25:e9": "TP-Link",
		"b0:be:76": "TP-Link",
		"10:fe:ed": "TP-Link",
		"00:e0:4c": "Realtek",
		"52:54:00": "QEMU/KVM",
		"00:15:5d": "Hyper-V",
		"00:1a:a0": "Dell Inc.",
		"f8:bc:12": "Dell Inc.",
		"18:03:73": "Dell Inc.",
		"d0:67:e5": "Dell Inc.",
		"00:17:a4": "HP Inc.",
		"3c:d9:2b": "HP Inc.",
		"9c:8e:99": "HP Inc.",
		"00:26:55": "Cisco",
		"00:1e:13": "Cisco",
		"00:1b:d5": "Cisco",
		"f4:4d:30": "Google",
		"54:60:09": "Google",
	}

	prefix := mac[:8]
	if vendor, ok := ouiDB[prefix]; ok {
		return vendor
	}
	return "-"
}

// isConnectionRefused checks if the error indicates the remote host actively
// refused the TCP connection (RST), which means the host is alive.
func isConnectionRefused(err error) bool {
	if opErr, ok := err.(*net.OpError); ok {
		errMsg := opErr.Error()
		if strings.Contains(errMsg, "refused") || strings.Contains(errMsg, "reset") {
			return true
		}
	}
	return false
}

// IPtoUint32 converts a net.IP to a uint32 for arithmetic operations.
func IPtoUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// Uint32toIP converts a uint32 back to a net.IP.
func Uint32toIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
