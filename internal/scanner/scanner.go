package scanner

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Config holds the configuration for a port scan operation.
type Config struct {
	Target        string
	Ports         []int
	Protocol      string
	Workers       int
	Timeout       interface{} // time.Duration passed from cmd
	ServiceDetect bool
}

// Result represents the outcome of scanning a single port.
type Result struct {
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
	Version string `json:"version,omitempty"`
	Proto   string `json:"protocol"`
}

// Run executes the port scan with the given configuration. It distributes work
// across a pool of goroutines controlled by a semaphore pattern and collects
// results into a sorted slice.
func Run(ctx context.Context, cfg Config) ([]Result, error) {
	if len(cfg.Ports) == 0 {
		return nil, fmt.Errorf("no ports specified")
	}

	workers := cfg.Workers
	if workers <= 0 {
		workers = 200
	}
	if workers > len(cfg.Ports) {
		workers = len(cfg.Ports)
	}

	var (
		resultsMu sync.Mutex
		results   []Result
		wg        sync.WaitGroup
		sem       = make(chan struct{}, workers)
	)

	for _, port := range cfg.Ports {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			var result Result
			result = ScanTCP(ctx, cfg.Target, p, cfg.Timeout)

			if result.State == "open" && cfg.ServiceDetect {
				svc, ver := DetectService(cfg.Target, p, cfg.Protocol)
				result.Service = svc
				result.Version = ver
			} else if result.State == "open" {
				result.Service = LookupService(p, cfg.Protocol)
			}

			if result.State == "open" {
				resultsMu.Lock()
				results = append(results, result)
				resultsMu.Unlock()
			}
		}(port)
	}

	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	return results, nil
}

// TopPorts returns the N most commonly open ports based on frequency data
// gathered from internet-wide scan datasets.
func TopPorts(n int) []int {
	top := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
		143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
		8443, 8888, 1080, 1433, 1521, 2049, 2082, 2083, 2086, 2087,
		3000, 3128, 5432, 5800, 5901, 6379, 6667, 8000, 8008, 8081,
		8181, 8880, 9090, 9200, 9300, 10000, 27017, 27018, 28017, 50000,
		514, 515, 548, 554, 587, 631, 636, 873, 902, 989,
		990, 1025, 1026, 1027, 1028, 1029, 1110, 1194, 1701, 1720,
		1900, 2000, 2001, 2222, 2375, 2376, 4443, 4444, 4567, 4711,
		4848, 4993, 5000, 5001, 5003, 5004, 5060, 5222, 5353, 5500,
		5555, 5601, 5631, 5632, 5666, 5672, 5938, 5984, 6000, 6001,
	}
	if n > len(top) {
		n = len(top)
	}
	return top[:n]
}
