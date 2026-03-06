package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	nethttp "github.com/vladimir120307-droid/netprobe/internal/http"
	"github.com/vladimir120307-droid/netprobe/internal/output"
)

var (
	httpFollowRedirects bool
	httpMethod          string
	httpHeaders         []string
	httpShowHeaders     bool
	httpShowTLS         bool
)

var httpCmd = &cobra.Command{
	Use:   "http <url>",
	Short: "Probe an HTTP endpoint",
	Long: `Probe an HTTP/HTTPS endpoint with detailed timing breakdown including
DNS lookup, TCP connect, TLS handshake, time to first byte, and total
response time. Optionally display response headers and TLS certificate info.

Examples:
  netprobe http https://example.com
  netprobe http https://api.github.com --follow-redirects --show-tls
  netprobe http http://localhost:8080 --method POST -H "Content-Type: application/json"
  netprobe http https://example.com --show-headers -o json`,
	Args: cobra.ExactArgs(1),
	RunE: runHTTP,
}

func init() {
	httpCmd.Flags().BoolVar(&httpFollowRedirects, "follow-redirects", false,
		"Follow HTTP redirects")
	httpCmd.Flags().StringVar(&httpMethod, "method", "GET", "HTTP method to use")
	httpCmd.Flags().StringArrayVarP(&httpHeaders, "header", "H", nil,
		"Custom headers (repeatable)")
	httpCmd.Flags().BoolVar(&httpShowHeaders, "show-headers", false,
		"Show response headers")
	httpCmd.Flags().BoolVar(&httpShowTLS, "show-tls", false,
		"Show TLS certificate details")
}

func runHTTP(cmd *cobra.Command, args []string) error {
	rawURL := args[0]
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	headerMap := make(map[string]string)
	for _, h := range httpHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	cfg := nethttp.ProbeConfig{
		URL:             rawURL,
		Method:          httpMethod,
		Headers:         headerMap,
		FollowRedirects: httpFollowRedirects,
		Timeout:         globalTimeout,
		ShowHeaders:     httpShowHeaders,
		ShowTLS:         httpShowTLS,
	}

	result, err := nethttp.Probe(cfg)
	if err != nil {
		return fmt.Errorf("HTTP probe failed: %w", err)
	}

	formatter := output.NewFormatter(outputFormat)
	formatter.FormatHTTPResult(result)
	return nil
}
