package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vladimir120307-droid/netprobe/internal/output"
	netping "github.com/vladimir120307-droid/netprobe/internal/ping"
	"github.com/vladimir120307-droid/netprobe/pkg/utils"
)

var (
	pingCount    int
	pingInterval time.Duration
	pingSize     int
)

var pingCmd = &cobra.Command{
	Use:   "ping <host>",
	Short: "Ping a host and measure latency",
	Long: `Send ICMP echo requests (or TCP fallback) to a host and measure
round-trip time, jitter, and packet loss.

Examples:
  netprobe ping google.com
  netprobe ping 8.8.8.8 -c 10 -i 500ms
  netprobe ping example.com --size 1024 -o json`,
	Args: cobra.ExactArgs(1),
	RunE: runPing,
}

func init() {
	pingCmd.Flags().IntVarP(&pingCount, "count", "c", 4, "Number of ping packets to send")
	pingCmd.Flags().DurationVarP(&pingInterval, "interval", "i", 1*time.Second, "Interval between pings")
	pingCmd.Flags().IntVar(&pingSize, "size", 64, "Packet size in bytes")
}

func runPing(cmd *cobra.Command, args []string) error {
	host := args[0]
	resolvedIP, err := utils.ResolveHostname(host)
	if err != nil {
		return fmt.Errorf("failed to resolve host %q: %w", host, err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Resolved %s -> %s
", host, resolvedIP)
	}

	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(pingCount)*pingInterval+globalTimeout)
	defer cancel()

	cfg := netping.Config{
		Host:     resolvedIP,
		Count:    pingCount,
		Interval: pingInterval,
		Size:     pingSize,
		Timeout:  globalTimeout,
	}

	fmt.Printf("PING %s (%s) %d bytes of data

", host, resolvedIP, pingSize)

	results, err := netping.Run(ctx, cfg, func(r netping.Result) {
		if r.Err != nil {
			fmt.Printf("From %s: seq=%d error: %v
", resolvedIP, r.Seq, r.Err)
		} else {
			fmt.Printf("%d bytes from %s: seq=%d ttl=%d time=%.2f ms
",
				pingSize, resolvedIP, r.Seq, r.TTL,
				float64(r.RTT.Microseconds())/1000.0)
		}
	})
	if err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	stats := netping.ComputeStats(results)
	fmt.Println()
	formatter := output.NewFormatter(outputFormat)
	formatter.FormatPingStats(host, stats)
	return nil
}
