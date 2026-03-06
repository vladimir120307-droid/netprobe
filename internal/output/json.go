package output

import (
	"encoding/json"
	"fmt"
	"os"
)

// PrintJSON marshals the provided data structure to indented JSON and writes
// it to stdout. This is the output backend used when -o json is specified.
// On encoding failure it prints an error message to stderr.
func PrintJSON(data interface{}) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(data); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
	}
}

// ToJSONString converts the given data to a compact JSON string.
// Returns an empty object "{}" on encoding failure.
func ToJSONString(data interface{}) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// ToJSONPretty converts the given data to an indented JSON string suitable
// for human reading. Returns an empty object on encoding failure.
func ToJSONPretty(data interface{}) string {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

// JSONResponse is a generic wrapper for JSON output that includes metadata
// about the operation alongside the results.
type JSONResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
	Error   string      `json:"error,omitempty"`
}

// NewJSONResponse creates a success response wrapping the given data.
func NewJSONResponse(data interface{}) JSONResponse {
	return JSONResponse{
		Success: true,
		Data:    data,
	}
}

// NewJSONError creates an error response with the given message.
func NewJSONError(err string) JSONResponse {
	return JSONResponse{
		Success: false,
		Error:   err,
	}
}

// PrintJSONResponse prints a JSONResponse to stdout.
func PrintJSONResponse(resp JSONResponse) {
	PrintJSON(resp)
}

// MergeJSON combines multiple maps into a single map. Later entries take
// precedence when keys collide. Useful for building composite JSON outputs
// from multiple data sources.
func MergeJSON(maps ...map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}
