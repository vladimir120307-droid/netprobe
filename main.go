package main

import (
	"os"

	"github.com/vladimir120307-droid/netprobe/cmd"
)

// netprobe - fast network diagnostics CLI tool
// Author: Cyber_Lord
// License: MIT

var (
	version = "1.0.0"
	commit  = "dev"
	date    = "unknown"
)

func main() {
	cmd.SetVersionInfo(version, commit, date)
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
