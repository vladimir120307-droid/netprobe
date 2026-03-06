package scanner

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// serviceNames maps well-known port numbers to their standard service names.
// This database covers the most commonly encountered services across TCP and UDP.
var serviceNames = map[int]string{
	7:     "echo",
	20:    "ftp-data",
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	43:    "whois",
	53:    "dns",
	67:    "dhcp",
	68:    "dhcp",
	69:    "tftp",
	80:    "http",
	88:    "kerberos",
	110:   "pop3",
	111:   "rpcbind",
	119:   "nntp",
	123:   "ntp",
	135:   "msrpc",
	137:   "netbios-ns",
	138:   "netbios-dgm",
	139:   "netbios-ssn",
	143:   "imap",
	161:   "snmp",
	162:   "snmptrap",
	179:   "bgp",
	194:   "irc",
	389:   "ldap",
	443:   "https",
	445:   "microsoft-ds",
	464:   "kpasswd",
	465:   "smtps",
	500:   "isakmp",
	514:   "syslog",
	515:   "printer",
	520:   "rip",
	523:   "ibm-db2",
	548:   "afp",
	554:   "rtsp",
	587:   "submission",
	631:   "ipp",
	636:   "ldaps",
	873:   "rsync",
	902:   "vmware-auth",
	993:   "imaps",
	995:   "pop3s",
	1080:  "socks",
	1194:  "openvpn",
	1433:  "mssql",
	1434:  "mssql-m",
	1521:  "oracle",
	1723:  "pptp",
	1883:  "mqtt",
	1900:  "upnp",
	2049:  "nfs",
	2082:  "cpanel",
	2083:  "cpanels",
	2086:  "whm",
	2087:  "whms",
	2181:  "zookeeper",
	2222:  "ssh-alt",
	2375:  "docker",
	2376:  "docker-s",
	3000:  "grafana",
	3128:  "squid",
	3268:  "globalcat",
	3306:  "mysql",
	3389:  "rdp",
	3690:  "svn",
	4443:  "https-alt",
	4567:  "tram",
	5000:  "upnp",
	5060:  "sip",
	5222:  "xmpp",
	5353:  "mdns",
	5432:  "postgresql",
	5672:  "amqp",
	5900:  "vnc",
	5984:  "couchdb",
	6379:  "redis",
	6443:  "kubernetes",
	6667:  "irc",
	8000:  "http-alt",
	8008:  "http-alt",
	8080:  "http-proxy",
	8081:  "http-alt",
	8443:  "https-alt",
	8888:  "http-alt",
	9090:  "prometheus",
	9200:  "elasticsearch",
	9300:  "elasticsearch",
	9418:  "git",
	10000: "webmin",
	11211: "memcached",
	27017: "mongodb",
	27018: "mongodb",
	28017: "mongodb-web",
	50000: "sap",
}

// LookupService returns the service name associated with a port number and
// protocol. If the port is not in the database an empty string is returned.
func LookupService(port int, protocol string) string {
	if name, ok := serviceNames[port]; ok {
		return name
	}
	return ""
}

// DetectService attempts to connect to the given port and extract a service
// banner or version string. It first tries a passive read, then falls back
// to sending protocol-specific probes.
func DetectService(target string, port int, protocol string) (service string, version string) {
	service = LookupService(port, protocol)

	if protocol != "tcp" {
		return service, ""
	}

	timeout := 3 * time.Second
	banner, err := TCPBannerGrab(target, port, timeout)
	if err != nil {
		return service, ""
	}

	if banner == "" {
		return service, ""
	}

	// Parse common banner formats to extract version information
	version = parseVersion(banner, port)
	if detectedSvc := detectServiceFromBanner(banner); detectedSvc != "" {
		service = detectedSvc
	}

	return service, version
}

// parseVersion attempts to extract version information from a service banner
// based on common banner format patterns.
func parseVersion(banner string, port int) string {
	banner = strings.TrimSpace(banner)

	// SSH banner: SSH-2.0-OpenSSH_8.9
	if strings.HasPrefix(banner, "SSH-") {
		parts := strings.SplitN(banner, "-", 3)
		if len(parts) >= 3 {
			return strings.Split(parts[2], " ")[0]
		}
	}

	// FTP banner: 220 ProFTPD 1.3.6
	if strings.HasPrefix(banner, "220") {
		clean := strings.TrimPrefix(banner, "220 ")
		clean = strings.TrimPrefix(clean, "220-")
		if idx := strings.Index(clean, "
"); idx > 0 {
			clean = clean[:idx]
		}
		return strings.TrimSpace(clean)
	}

	// SMTP banner: 220 mail.example.com ESMTP Postfix
	if strings.Contains(banner, "ESMTP") || strings.Contains(banner, "SMTP") {
		if idx := strings.Index(banner, "ESMTP"); idx >= 0 {
			return strings.TrimSpace(banner[idx:])
		}
	}

	// HTTP banner detection
	if strings.HasPrefix(banner, "HTTP/") {
		lines := strings.Split(banner, "
")
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "Server:") {
				return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "Server:"))
			}
		}
	}

	// MySQL greeting
	if port == 3306 && len(banner) > 5 {
		// MySQL protocol version + version string
		for i, c := range banner {
			if c == 0 && i > 1 {
				return "MySQL " + banner[1:i]
			}
		}
	}

	// Redis
	if strings.HasPrefix(banner, "+PONG") || strings.HasPrefix(banner, "-ERR") {
		return "Redis"
	}

	// Generic: return first line truncated
	if idx := strings.IndexAny(banner, "
"); idx > 0 {
		if idx > 60 {
			return banner[:60] + "..."
		}
		return banner[:idx]
	}
	if len(banner) > 60 {
		return banner[:60] + "..."
	}
	return banner
}

// detectServiceFromBanner identifies the service type from banner content
// when the port-based lookup is insufficient or returns a generic name.
func detectServiceFromBanner(banner string) string {
	lower := strings.ToLower(banner)
	switch {
	case strings.HasPrefix(lower, "ssh-"):
		return "ssh"
	case strings.Contains(lower, "ftp"):
		return "ftp"
	case strings.Contains(lower, "smtp") || strings.Contains(lower, "esmtp"):
		return "smtp"
	case strings.HasPrefix(lower, "http/"):
		return "http"
	case strings.Contains(lower, "imap"):
		return "imap"
	case strings.Contains(lower, "pop3") || strings.HasPrefix(lower, "+ok"):
		return "pop3"
	case strings.Contains(lower, "mysql"):
		return "mysql"
	case strings.Contains(lower, "postgresql"):
		return "postgresql"
	case strings.HasPrefix(lower, "+pong") || strings.HasPrefix(lower, "-err"):
		return "redis"
	}
	return ""
}

// ProbeService sends a protocol-specific probe to the target port and returns
// the response for analysis. Used by DetectService for services that do not
// send banners automatically.
func ProbeService(target string, port int, timeout time.Duration) ([]byte, error) {
	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Send an HTTP probe
	httpProbe := fmt.Sprintf("GET / HTTP/1.0
Host: %s

", target)
	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte(httpProbe))
	if err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
