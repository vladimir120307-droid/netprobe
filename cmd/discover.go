package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vladimir120307-droid/netprobe/internal/discovery"
	"github.com/vladimir120307-droid/netprobe/internal/output"
)

var (
	discoverWorkers int
)

var discoverCmd = &cobra.Command{
	Use:   "discover <cidr>",
	Short: "Discover hosts on a subnet",
	Long: `Discover live hosts on a local network subnet using ARP requests
and TCP probing. Displays IP addresses, MAC addresses, hostnames,
and vendor information when available.

Examples:
  netprobe discover 192.168.1.0/24
  netprobe discover 10.0.0.0/24 --workers 100
  netprobe discover 172.16.0.0/16 -o json`,
	Args: cobra.ExactArgs(1),
	RunE: runDiscover,
}

func init() {
	discoverCmd.Flags().IntVar(&discoverWorkers, "workers", 50,
		"Number of concurrent discovery workers")
}

func runDiscover(cmd *cobra.Command, args []string) error {
	cidr := args[0]

	subnetInfo, err := discovery.ParseSubnet(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation %q: %w", cidr, err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Subnet: %s, Network: %s, Broadcast: %s, Hosts: %d
",
			cidr, subnetInfo.Network, subnetInfo.Broadcast, subnetInfo.HostCount)
	}

	fmt.Printf("DISCOVERING HOSTS ON %s

", cidr)

	ctx, cancel := context.WithTimeout(context.Background(),
		globalTimeout+time.Duration(subnetInfo.HostCount/discoverWorkers+1)*globalTimeout)
	defer cancel()

	cfg := discovery.Config{
		Subnet:  subnetInfo,
		Workers: discoverWorkers,
		Timeout: globalTimeout,
	}

	startTime := time.Now()
	hosts, err := discovery.Run(ctx, cfg)
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}
	elapsed := time.Since(startTime)

	formatter := output.NewFormatter(outputFormat)
	formatter.FormatDiscoveryResults(hosts, elapsed)
	return nil
}
