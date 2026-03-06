package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vladimir120307-droid/netprobe/internal/output"
	"github.com/vladimir120307-droid/netprobe/internal/scanner"
	"github.com/vladimir120307-droid/netprobe/pkg/utils"
)

var (
	scanPorts     string
	scanTopPorts  int
	scanProtocol  string
	scanWorkers   int
	serviceDetect bool
)

var scanCmd = &cobra.Command{
	Use:   "scan <target>",
	Short: "Scan ports on a target host",
	Long: `Perform TCP or UDP port scanning on a target host.
Supports concurrent scanning with configurable worker count,
service/banner detection, and multiple output formats.

Examples:
  netprobe scan 192.168.1.1
  netprobe scan 192.168.1.1 -p 1-65535 --workers 500
  netprobe scan example.com -p 22,80,443 --service-detect
  netprobe scan 10.0.0.1 --top-ports 100 -o json`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&scanPorts, "ports", "p", "1-1024", "Port range (e.g. 80, 1-1000, 22,80,443)")
	scanCmd.Flags().IntVar(&scanTopPorts, "top-ports", 0, "Scan top N most common ports")
	scanCmd.Flags().StringVar(&scanProtocol, "protocol", "tcp", "Protocol: tcp or udp")
	scanCmd.Flags().IntVar(&scanWorkers, "workers", 200, "Number of concurrent workers")
	scanCmd.Flags().BoolVar(&serviceDetect, "service-detect", false, "Detect service banners")
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]
	resolvedIP, err := utils.ResolveHostname(target)
	if err != nil {
		return fmt.Errorf("failed to resolve target %q: %w", target, err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Resolved %s -> %s
", target, resolvedIP)
	}

	var ports []int
	if scanTopPorts > 0 {
		ports = scanner.TopPorts(scanTopPorts)
	} else {
		ports, err = utils.ParsePortRange(scanPorts)
		if err != nil {
			return fmt.Errorf("invalid port specification %q: %w", scanPorts, err)
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Scanning %d ports on %s (%s) with %d workers
",
			len(ports), target, scanProtocol, scanWorkers)
	}

	maxDuration := globalTimeout + time.Duration(len(ports)/scanWorkers+1)*globalTimeout
	ctx, cancel := context.WithTimeout(context.Background(), maxDuration)
	defer cancel()

	cfg := scanner.Config{
		Target:        resolvedIP,
		Ports:         ports,
		Protocol:      scanProtocol,
		Workers:       scanWorkers,
		Timeout:       globalTimeout,
		ServiceDetect: serviceDetect,
	}

	startTime := time.Now()
	results, err := scanner.Run(ctx, cfg)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	elapsed := time.Since(startTime)

	openCount := 0
	for _, r := range results {
		if r.State == "open" {
			openCount++
		}
	}

	formatter := output.NewFormatter(outputFormat)
	formatter.FormatScanResults(target, results, elapsed, openCount)
	return nil
}
