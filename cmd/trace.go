package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vladimir120307-droid/netprobe/internal/output"
	"github.com/vladimir120307-droid/netprobe/internal/trace"
	"github.com/vladimir120307-droid/netprobe/pkg/utils"
)

var (
	traceMaxHops  int
	traceProbes   int
	traceProtocol string
)

var traceCmd = &cobra.Command{
	Use:   "trace <target>",
	Short: "Trace the route to a host",
	Long: `Perform a traceroute to a target host, displaying each hop along the
network path with latency measurements. Supports multiple probes per hop
and configurable maximum hop count.

Examples:
  netprobe trace 8.8.8.8
  netprobe trace google.com --max-hops 20 --probes 5
  netprobe trace example.com -o json`,
	Args: cobra.ExactArgs(1),
	RunE: runTrace,
}

func init() {
	traceCmd.Flags().IntVar(&traceMaxHops, "max-hops", 30, "Maximum number of hops")
	traceCmd.Flags().IntVar(&traceProbes, "probes", 3, "Number of probes per hop")
	traceCmd.Flags().StringVar(&traceProtocol, "protocol", "udp", "Protocol: udp, tcp, icmp")
}

func runTrace(cmd *cobra.Command, args []string) error {
	target := args[0]
	resolvedIP, err := utils.ResolveHostname(target)
	if err != nil {
		return fmt.Errorf("failed to resolve target %q: %w", target, err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Resolved %s -> %s
", target, resolvedIP)
	}

	ctx, cancel := context.WithTimeout(context.Background(),
		globalTimeout*time.Duration(traceMaxHops))
	defer cancel()

	cfg := trace.Config{
		Target:   resolvedIP,
		MaxHops:  traceMaxHops,
		Probes:   traceProbes,
		Protocol: traceProtocol,
		Timeout:  globalTimeout,
	}

	fmt.Printf("TRACEROUTE to %s (%s), max %d hops

", target, resolvedIP, traceMaxHops)

	hops, err := trace.Run(ctx, cfg)
	if err != nil {
		return fmt.Errorf("traceroute failed: %w", err)
	}

	formatter := output.NewFormatter(outputFormat)
	formatter.FormatTraceResults(target, hops)
	return nil
}
