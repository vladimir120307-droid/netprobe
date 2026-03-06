package dns

import (
	"fmt"
	"strings"
)

// RecordType represents a DNS record type with its numeric code and description.
type RecordType struct {
	Name        string
	Code        uint16
	Description string
}

// SupportedTypes lists all DNS record types supported by netprobe.
var SupportedTypes = []RecordType{
	{Name: "A", Code: 1, Description: "IPv4 address"},
	{Name: "AAAA", Code: 28, Description: "IPv6 address"},
	{Name: "CNAME", Code: 5, Description: "Canonical name (alias)"},
	{Name: "MX", Code: 15, Description: "Mail exchange"},
	{Name: "NS", Code: 2, Description: "Nameserver"},
	{Name: "TXT", Code: 16, Description: "Text record"},
	{Name: "SOA", Code: 6, Description: "Start of authority"},
	{Name: "PTR", Code: 12, Description: "Pointer (reverse DNS)"},
	{Name: "SRV", Code: 33, Description: "Service locator"},
	{Name: "CAA", Code: 257, Description: "Certificate authority authorization"},
}

// IsSupported checks whether a given record type string is supported by the
// resolver implementation. Returns true for all types listed in SupportedTypes.
func IsSupported(recordType string) bool {
	upper := strings.ToUpper(recordType)
	for _, t := range SupportedTypes {
		if t.Name == upper {
			return true
		}
	}
	return false
}

// GetTypeCode returns the numeric DNS type code for a given record type name.
// Returns 0 if the type is not recognized.
func GetTypeCode(name string) uint16 {
	upper := strings.ToUpper(name)
	for _, t := range SupportedTypes {
		if t.Name == upper {
			return t.Code
		}
	}
	return 0
}

// GetTypeName returns the human-readable name for a numeric DNS type code.
// Returns "UNKNOWN" if the code is not in the supported types list.
func GetTypeName(code uint16) string {
	for _, t := range SupportedTypes {
		if t.Code == code {
			return t.Name
		}
	}
	return fmt.Sprintf("TYPE%d", code)
}

// FormatRecord produces a human-readable string representation of a DNS record.
func FormatRecord(r RecordResult) string {
	return fmt.Sprintf("%-8s %-30s %-40s %d", r.Type, r.Name, r.Value, r.TTL)
}

// FormatRecordShort produces a compact string representation suitable for
// plain text output mode.
func FormatRecordShort(r RecordResult) string {
	return fmt.Sprintf("%s %s %s", r.Type, r.Name, r.Value)
}

// ParseRecordTypes splits a comma-separated list of record type names and
// validates each one. Returns an error if any type is not supported.
func ParseRecordTypes(input string) ([]string, error) {
	parts := strings.Split(input, ",")
	var types []string

	for _, part := range parts {
		t := strings.TrimSpace(strings.ToUpper(part))
		if t == "" {
			continue
		}

		if t == "ALL" || t == "*" {
			return getAllTypeNames(), nil
		}

		if !IsSupported(t) {
			return nil, fmt.Errorf("unsupported DNS record type: %s (supported: %s)",
				t, strings.Join(getAllTypeNames(), ", "))
		}
		types = append(types, t)
	}

	if len(types) == 0 {
		types = []string{"A"}
	}
	return types, nil
}

// getAllTypeNames returns the names of all supported record types.
func getAllTypeNames() []string {
	names := make([]string, len(SupportedTypes))
	for i, t := range SupportedTypes {
		names[i] = t.Name
	}
	return names
}

// RecordSortOrder defines the display order for DNS record types. Lower
// values appear first in sorted output.
var RecordSortOrder = map[string]int{
	"SOA":   1,
	"NS":    2,
	"A":     3,
	"AAAA":  4,
	"CNAME": 5,
	"MX":    6,
	"TXT":   7,
	"SRV":   8,
	"PTR":   9,
	"CAA":   10,
}

// SortRecords sorts a slice of DNS records by type order, then by value.
func SortRecords(records []RecordResult) {
	for i := 1; i < len(records); i++ {
		key := records[i]
		j := i - 1
		for j >= 0 && recordLess(key, records[j]) {
			records[j+1] = records[j]
			j--
		}
		records[j+1] = key
	}
}

func recordLess(a, b RecordResult) bool {
	orderA, okA := RecordSortOrder[a.Type]
	orderB, okB := RecordSortOrder[b.Type]
	if !okA {
		orderA = 99
	}
	if !okB {
		orderB = 99
	}
	if orderA != orderB {
		return orderA < orderB
	}
	return a.Value < b.Value
}
