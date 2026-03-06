# netprobe

[![Go Version](https://img.shields.io/badge/go-%3E%3D1.21-blue.svg)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/actions/workflow/status/vladimir120307-droid/netprobe/build.yml?branch=main)](https://github.com/vladimir120307-droid/netprobe/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/vladimir120307-droid/netprobe)](https://goreportcard.com/report/github.com/vladimir120307-droid/netprobe)
[![Release](https://img.shields.io/github/v/release/vladimir120307-droid/netprobe)](https://github.com/vladimir120307-droid/netprobe/releases)

**Fast, concurrent network diagnostics CLI tool.** Port scanning, latency testing, DNS lookup, HTTP probing, traceroute, and subnet discovery -- all from a single binary.

Built with Go for maximum performance using goroutine pools and semaphore-based concurrency control.

---

## Features

- **Port Scanner** -- concurrent TCP port scanning with configurable worker pools, service detection, and banner grabbing for 50+ known services
- **Ping / Latency** -- TCP-based ping with full statistics: min, max, avg, standard deviation, jitter, and packet loss percentage
- **DNS Resolver** -- query A, AAAA, MX, NS, TXT, CNAME, and SOA records against any DNS server
- **HTTP Prober** -- detailed request timing breakdown (DNS lookup, TCP connect, TLS handshake, TTFB, total) with optional TLS certificate inspection and response header display
- **Traceroute** -- TTL-based route tracing with concurrent probes per hop and reverse DNS resolution
- **Subnet Discovery** -- CIDR-based host discovery with MAC address lookup, reverse DNS, and OUI vendor identification
- **Output Formats** -- beautiful colored tables or machine-readable JSON
- **Cross-platform** -- works on Linux, macOS, and Windows

---

## Installation

### From source (recommended)

Requires Go 1.21 or later:

```bash
go install github.com/vladimir120307-droid/netprobe@latest
```

### Build from repository

```bash
git clone https://github.com/vladimir120307-droid/netprobe.git
cd netprobe
go build -o netprobe .
```

### Build with version info

```bash
go build -ldflags "-X main.version=1.0.0 -X main.commit=$(git rev-parse --short HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o netprobe .
```

---

## Quick Start

```bash
# Scan top 100 ports on a host
netprobe scan example.com --top-ports 100

# Ping a host 10 times
netprobe ping 8.8.8.8 -c 10

# Look up DNS records
netprobe dns example.com --type A,MX,NS,TXT

# Probe an HTTPS endpoint with timing breakdown
netprobe http https://example.com --show-tls --show-headers

# Trace the route to a host
netprobe trace google.com

# Discover hosts on your local subnet
netprobe discover 192.168.1.0/24
```

---

## Commands

### `scan` -- Port Scanner

Perform TCP port scanning with concurrent workers and optional service detection.

```bash
# Scan default ports (1-1024)
netprobe scan 192.168.1.1

# Scan all 65535 ports with 500 workers
netprobe scan 192.168.1.1 -p 1-65535 --workers 500

# Scan specific ports with service detection
netprobe scan example.com -p 22,80,443,3306,5432,8080 --service-detect

# Scan top 100 common ports, output as JSON
netprobe scan 10.0.0.1 --top-ports 100 -o json

# Scan with custom timeout
netprobe scan 192.168.1.1 -p 1-10000 -t 3s --workers 300
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --ports` | `1-1024` | Port range (e.g. `80`, `1-1000`, `22,80,443`) |
| `--top-ports` | `0` | Scan top N most common ports |
| `--protocol` | `tcp` | Protocol to use |
| `--workers` | `200` | Number of concurrent workers |
| `--service-detect` | `false` | Enable service banner detection |

### `ping` -- Latency Testing

Send TCP-based ping probes and measure round-trip time with comprehensive statistics.

```bash
# Ping with default settings (4 packets)
netprobe ping google.com

# Ping 20 times with 500ms interval
netprobe ping 8.8.8.8 -c 20 -i 500ms

# Ping with larger packet size
netprobe ping example.com --size 1024

# Ping with JSON output
netprobe ping cloudflare.com -c 10 -o json
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-c, --count` | `4` | Number of ping packets to send |
| `-i, --interval` | `1s` | Interval between pings |
| `--size` | `64` | Packet size in bytes |

**Statistics reported:** min RTT, max RTT, average RTT, standard deviation, jitter (mean consecutive difference), packet loss percentage.

### `dns` -- DNS Resolver

Query DNS records for any domain with support for all major record types.

```bash
# Look up A records (default)
netprobe dns example.com

# Query multiple record types
netprobe dns example.com --type A,AAAA,MX,NS,TXT

# Use a specific DNS server
netprobe dns example.com --server 1.1.1.1

# Query SOA record with JSON output
netprobe dns example.com --type SOA -o json

# Query CNAME records
netprobe dns www.github.com --type CNAME
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--type` | `A` | Record types (comma-separated: `A,AAAA,MX,NS,TXT,CNAME,SOA`) |
| `--server` | system default | Custom DNS server address |

### `http` -- HTTP Prober

Probe HTTP/HTTPS endpoints with detailed timing breakdown and optional TLS certificate inspection.

```bash
# Basic HTTP probe
netprobe http https://example.com

# Follow redirects and show TLS info
netprobe http https://github.com --follow-redirects --show-tls

# Show response headers
netprobe http https://api.github.com --show-headers

# POST request with custom headers
netprobe http https://httpbin.org/post --method POST -H "Content-Type: application/json"

# Full inspection with JSON output
netprobe http https://example.com --show-tls --show-headers -o json
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--method` | `GET` | HTTP method to use |
| `-H, --header` | none | Custom headers (repeatable) |
| `--follow-redirects` | `false` | Follow HTTP redirects |
| `--show-headers` | `false` | Display response headers |
| `--show-tls` | `false` | Display TLS certificate details |

**Timing breakdown:** DNS lookup, TCP connect, TLS handshake, time to first byte (TTFB), total request time.

**TLS info:** subject, issuer, validity period, days until expiry, SANs, protocol version, cipher suite, signature algorithm.

### `trace` -- Traceroute

Trace the network path to a destination with concurrent probes per hop.

```bash
# Basic traceroute
netprobe trace 8.8.8.8

# Custom max hops and probes per hop
netprobe trace google.com --max-hops 20 --probes 5

# TCP-based traceroute (better firewall traversal)
netprobe trace example.com --protocol tcp

# JSON output
netprobe trace cloudflare.com -o json
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--max-hops` | `30` | Maximum number of hops |
| `--probes` | `3` | Number of probes per hop |
| `--protocol` | `udp` | Protocol: `udp`, `tcp`, `icmp` |

### `discover` -- Subnet Discovery

Discover live hosts on a local network subnet using TCP probing.

```bash
# Discover hosts on a /24 subnet
netprobe discover 192.168.1.0/24

# Increase worker count for faster scanning
netprobe discover 10.0.0.0/24 --workers 100

# JSON output for scripting
netprobe discover 172.16.0.0/24 -o json
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--workers` | `50` | Number of concurrent discovery workers |

**Reported info:** IP address, MAC address, hostname (reverse DNS), vendor (OUI database), latency.

---

## Global Flags

These flags apply to all commands:

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output` | `table` | Output format: `table`, `json`, `plain` |
| `-t, --timeout` | `5s` | Global timeout for operations |
| `-v, --verbose` | `false` | Enable verbose output |
| `--no-color` | `false` | Disable colored output |
| `--version` | | Show version information |
| `-h, --help` | | Show help for any command |

---

## Output Examples

### Table Output (default)

```
Scan report for example.com
---------------------------------------
  PORT     STATE      SERVICE            VERSION
------------------------------------------------------------
  22/tcp   open       ssh                OpenSSH_8.9p1
  80/tcp   open       http               nginx/1.24.0
  443/tcp  open       https
------------------------------------------------------------
  3 open ports found in 2.847s
```

### JSON Output

```json
{
  "target": "example.com",
  "open_ports": 3,
  "elapsed_ms": 2847,
  "results": [
    {"port": 22, "state": "open", "service": "ssh", "version": "OpenSSH_8.9p1", "protocol": "tcp"},
    {"port": 80, "state": "open", "service": "http", "version": "nginx/1.24.0", "protocol": "tcp"},
    {"port": 443, "state": "open", "service": "https", "protocol": "tcp"}
  ]
}
```

---

## Architecture

```
netprobe/
├── main.go                  # Entry point
├── cmd/                     # CLI command definitions (cobra)
│   ├── root.go              # Root command, global flags
│   ├── scan.go              # Port scanner command
│   ├── ping.go              # Ping/latency command
│   ├── dns.go               # DNS lookup command
│   ├── http.go              # HTTP prober command
│   ├── trace.go             # Traceroute command
│   └── discover.go          # Subnet discovery command
├── internal/                # Private packages
│   ├── scanner/             # Port scanning engine
│   │   ├── scanner.go       # Concurrent scan orchestrator
│   │   ├── tcp.go           # TCP connect scanner
│   │   └── service.go       # Service/banner detection (50+ mappings)
│   ├── ping/                # Ping engine
│   │   ├── pinger.go        # ICMP/TCP ping implementation
│   │   └── stats.go         # Statistics computation
│   ├── dns/                 # DNS resolver
│   │   ├── resolver.go      # Multi-type DNS resolution
│   │   └── records.go       # Record type definitions
│   ├── http/                # HTTP prober
│   │   ├── prober.go        # HTTP client with timing hooks
│   │   └── tls.go           # TLS certificate extraction
│   ├── trace/               # Traceroute engine
│   │   └── traceroute.go    # TTL-based route tracing
│   ├── discovery/           # Network discovery
│   │   └── subnet.go        # CIDR parsing and host discovery
│   └── output/              # Output formatting
│       ├── formatter.go     # Format dispatcher
│       ├── table.go         # Pretty table renderer
│       └── json.go          # JSON output renderer
└── pkg/utils/               # Public utilities
    ├── network.go           # Host resolution, port parsing
    └── color.go             # ANSI terminal colors
```

---

## Concurrency Model

netprobe uses a **semaphore-based goroutine pool** pattern for all concurrent operations:

1. A buffered channel acts as the semaphore, limiting active goroutines
2. Each task acquires a slot before execution and releases it on completion
3. A `sync.WaitGroup` tracks overall completion
4. Results are collected via mutex-protected shared slices

This pattern provides:
- Bounded resource usage regardless of input size
- Configurable parallelism via `--workers`
- Clean cancellation through `context.Context`

---

## Performance Tips

- **Large port ranges**: increase `--workers` to 500+ for faster scans
- **Slow networks**: increase `--timeout` to avoid false negatives
- **Subnet discovery**: use `--workers 100` or higher for large subnets
- **Scripting**: use `-o json` for machine-readable output
- **CI/CD pipelines**: use `--no-color` to avoid ANSI codes in logs

---

## Requirements

- Go 1.21 or later (for building from source)
- Some features (ICMP ping, raw traceroute) may require elevated privileges
- TCP fallback is used automatically when raw sockets are unavailable

---

## Contributing

Contributions are welcome. Please open an issue or submit a pull request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Open a Pull Request

---

## License

MIT License. Copyright (c) 2024-2025 Cyber_Lord.

See [LICENSE](LICENSE) for details.

---

## Author

**Cyber_Lord** (Vladimir)

- GitHub: [@vladimir120307-droid](https://github.com/vladimir120307-droid)
- Email: Vladimir120307@gmail.com
