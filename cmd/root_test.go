package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// run executes the CLI in-process and returns what it printed. These tests only
// use the help and version paths, so no command reaches the network.
func run(t *testing.T, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs(args)
	defer func() {
		// Cobra keeps flag values between runs of the same command tree.
		rootCmd.Flags().Set("help", "false")
		rootCmd.Flags().Set("version", "false")
	}()
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return out.String()
}

func TestVersionFlag(t *testing.T) {
	SetVersionInfo("1.2.3", "abc123", "2026-01-01")
	if got, want := run(t, "--version"), "netprobe version 1.2.3\n"; got != want {
		t.Errorf("--version printed %q, want %q", got, want)
	}
}

func TestHelpForEveryCommand(t *testing.T) {
	if got := run(t, "--help"); !strings.Contains(got, "Usage:") {
		t.Errorf("--help printed %q", got)
	}
	for _, name := range []string{"scan", "ping", "dns", "http", "trace", "discover"} {
		if got := run(t, name, "--help"); !strings.Contains(got, "Usage:") {
			t.Errorf("%s --help printed %q", name, got)
		}
	}
}
