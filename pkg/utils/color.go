package utils

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// ANSI escape codes for terminal colors and text formatting.
const (
	ansiReset     = "\033[0m"
	ansiBold      = "\033[1m"
	ansiDim       = "\033[2m"
	ansiUnderline = "\033[4m"
	ansiRed       = "\033[31m"
	ansiGreen     = "\033[32m"
	ansiYellow    = "\033[33m"
	ansiBlue      = "\033[34m"
	ansiMagenta   = "\033[35m"
	ansiCyan      = "\033[36m"
	ansiWhite     = "\033[37m"
	ansiBgRed     = "\033[41m"
	ansiBgGreen   = "\033[42m"
)

// colorEnabled tracks whether ANSI color output is active. It defaults to true
// on terminals that support it and can be disabled with DisableColor.
var colorEnabled = detectColorSupport()

// detectColorSupport checks whether the current terminal supports ANSI color
// codes by inspecting environment variables and OS type.
func detectColorSupport() bool {
	// Check for explicit NO_COLOR convention (https://no-color.org)
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}

	// Check for TERM=dumb
	if os.Getenv("TERM") == "dumb" {
		return false
	}

	// On Windows, modern terminals and Windows Terminal support ANSI
	if runtime.GOOS == "windows" {
		// WT_SESSION is set by Windows Terminal
		if os.Getenv("WT_SESSION") != "" {
			return true
		}
		// ConEmu, cmder, etc.
		if os.Getenv("ConEmuANSI") == "ON" {
			return true
		}
		// ANSICON indicates ANSI support
		if os.Getenv("ANSICON") != "" {
			return true
		}
		// Default to enabled on modern Windows (10+)
		return true
	}

	return true
}

// DisableColor turns off ANSI color code output globally. Useful when the
// output is piped to a file or the --no-color flag is set.
func DisableColor() {
	colorEnabled = false
}

// EnableColor turns on ANSI color code output globally.
func EnableColor() {
	colorEnabled = true
}

// IsColorEnabled returns whether color output is currently active.
func IsColorEnabled() bool {
	return colorEnabled
}

// colorize wraps text with the given ANSI code if colors are enabled.
func colorize(code, text string) string {
	if !colorEnabled {
		return text
	}
	return code + text + ansiReset
}

// Red returns text colored red, typically used for errors and failures.
func Red(text string) string {
	return colorize(ansiRed, text)
}

// Green returns text colored green, typically used for success states.
func Green(text string) string {
	return colorize(ansiGreen, text)
}

// Yellow returns text colored yellow, typically used for warnings.
func Yellow(text string) string {
	return colorize(ansiYellow, text)
}

// Blue returns text colored blue, typically used for informational messages.
func Blue(text string) string {
	return colorize(ansiBlue, text)
}

// Cyan returns text colored cyan, used for highlights and emphasis.
func Cyan(text string) string {
	return colorize(ansiCyan, text)
}

// Magenta returns text colored magenta.
func Magenta(text string) string {
	return colorize(ansiMagenta, text)
}

// White returns text colored white.
func White(text string) string {
	return colorize(ansiWhite, text)
}

// Bold returns text in bold formatting.
func Bold(text string) string {
	return colorize(ansiBold, text)
}

// Dim returns text in dim/faint formatting.
func Dim(text string) string {
	return colorize(ansiDim, text)
}

// Underline returns text with underline formatting.
func Underline(text string) string {
	return colorize(ansiUnderline, text)
}

// BgRed returns text with a red background.
func BgRed(text string) string {
	return colorize(ansiBgRed, text)
}

// BgGreen returns text with a green background.
func BgGreen(text string) string {
	return colorize(ansiBgGreen, text)
}

// StatusColor returns a colored status string: green for positive values
// like "open" or "up", red for "closed" or "down", yellow otherwise.
func StatusColor(status string) string {
	lower := strings.ToLower(status)
	switch {
	case lower == "open" || lower == "up" || lower == "alive" || lower == "ok":
		return Green(status)
	case lower == "closed" || lower == "down" || lower == "error" || lower == "expired":
		return Red(status)
	case lower == "filtered" || lower == "warning" || lower == "unknown":
		return Yellow(status)
	default:
		return status
	}
}

// ProgressBar returns a simple text-based progress bar string.
func ProgressBar(current, total int, width int) string {
	if total <= 0 {
		return ""
	}
	pct := float64(current) / float64(total)
	filled := int(pct * float64(width))
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("=", filled)
	if filled < width {
		bar += ">"
		bar += strings.Repeat(" ", width-filled-1)
	}
	return fmt.Sprintf("[%s] %3.0f%%", bar, pct*100)
}
