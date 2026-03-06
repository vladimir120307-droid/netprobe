package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	netdns "github.com/vladimir120307-droid/netprobe/internal/dns"
	"github.com/vladimir120307-droid/netprobe/internal/output"
)

var (
	dnsRecordTypes string
	dnsServer      string
)

var dnsCmd = &cobra.Command{
	Use:   "dns <domain>",
	Short: "Perform DNS lookups",
	Long: `Query DNS records for a domain. Supports A, AAAA, MX, NS, TXT, CNAME,
and SOA record types. Optionally specify a custom DNS server.

Examples:
  netprobe dns example.com
  netprobe dns example.com --type A,MX,TXT
  netprobe dns example.com --server 8.8.8.8 -o json`,
	Args: cobra.ExactArgs(1),
	RunE: runDNS,
}

func init() {
	dnsCmd.Flags().StringVar(&dnsRecordTypes, "type", "A",
		"Record types to query (comma-separated: A,AAAA,MX,NS,TXT,CNAME,SOA)")
	dnsCmd.Flags().StringVar(&dnsServer, "server", "",
		"Custom DNS server address (e.g. 8.8.8.8)")
}

func runDNS(cmd *cobra.Command, args []string) error {
	domain := args[0]
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	types := strings.Split(strings.ToUpper(dnsRecordTypes), ",")
	for i, t := range types {
		types[i] = strings.TrimSpace(t)
	}

	server := dnsServer
	if server == "" {
		server = netdns.DefaultServer()
	}
	if !strings.Contains(server, ":") {
		server = server + ":53"
	}

	cfg := netdns.Config{
		Domain:      domain,
		Server:      server,
		RecordTypes: types,
		Timeout:     globalTimeout,
	}

	startTime := time.Now()
	results, err := netdns.Resolve(cfg)
	if err != nil {
		return fmt.Errorf("DNS lookup failed: %w", err)
	}
	elapsed := time.Since(startTime)

	formatter := output.NewFormatter(outputFormat)
	formatter.FormatDNSResults(strings.TrimSuffix(domain, "."), server, results, elapsed)
	return nil
}
