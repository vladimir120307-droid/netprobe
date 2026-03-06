package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vladimir120307-droid/netprobe/pkg/utils"
)

var (
	outputFormat  string
	globalTimeout time.Duration
	verbose       bool
	noColor       bool

	appVersion string
	appCommit  string
	appDate    string
)

// SetVersionInfo configures the build version metadata displayed in the CLI banner.
func SetVersionInfo(version, commit, date string) {
	appVersion = version
	appCommit = commit
	appDate = date
}

var rootCmd = &cobra.Command{
	Use:   "netprobe",
	Short: "Fast network diagnostics CLI tool",
	Long: `netprobe - a fast, multi-purpose network diagnostics CLI tool.

Perform port scanning, ping, DNS lookup, HTTP probing, traceroute,
and subnet discovery from a single binary. Built for speed using
concurrent goroutine pools.

Author: Cyber_Lord
Repository: https://github.com/vladimir120307-droid/netprobe`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if noColor {
			utils.DisableColor()
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "netprobe %s (commit: %s, built: %s)\n",
				appVersion, appCommit, appDate)
			fmt.Fprintf(os.Stderr, "Output format: %s, Timeout: %s\n",
				outputFormat, globalTimeout)
		}
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table",
		"Output format: table, json, plain")
	rootCmd.PersistentFlags().DurationVarP(&globalTimeout, "timeout", "t", 5*time.Second,
		"Global timeout for operations")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"Enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false,
		"Disable colored output")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(pingCmd)
	rootCmd.AddCommand(dnsCmd)
	rootCmd.AddCommand(httpCmd)
	rootCmd.AddCommand(traceCmd)
	rootCmd.AddCommand(discoverCmd)

	rootCmd.Version = appVersion
}

// Execute runs the root command tree. Called from main.
func Execute() error {
	return rootCmd.Execute()
}

// GetOutputFormat returns the current output format setting.
func GetOutputFormat() string {
	return outputFormat
}

// GetGlobalTimeout returns the globally configured timeout.
func GetGlobalTimeout() time.Duration {
	return globalTimeout
}

// IsVerbose returns whether verbose mode is enabled.
func IsVerbose() bool {
	return verbose
}
