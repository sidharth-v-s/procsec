package output

import (
	"fmt"
)

// Enabled controls whether color/style codes are emitted. Set once
// at startup by main() based on: explicit --no-color flag, the
// NO_COLOR env convention (https://no-color.org), and whether stdout
// is actually a terminal (colors are auto-disabled when piped, e.g.
// `procsec ps | grep foo`, so scripts never see escape codes unless
// they ask for them).
var Enabled = true

const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	gray    = "\033[90m"
	brRed   = "\033[91m"
	brGreen = "\033[92m"
)

func wrap(code, s string) string {
	if !Enabled {
		return s
	}
	return code + s + reset
}

func Bold(s string) string    { return wrap(bold, s) }
func Dim(s string) string     { return wrap(dim, s) }
func Red(s string) string     { return wrap(red, s) }
func Green(s string) string   { return wrap(green, s) }
func Yellow(s string) string  { return wrap(yellow, s) }
func Blue(s string) string    { return wrap(blue, s) }
func Magenta(s string) string { return wrap(magenta, s) }
func Cyan(s string) string    { return wrap(cyan, s) }
func Gray(s string) string    { return wrap(gray, s) }

// BoldRed / BoldGreen etc. combine two codes for emphasis (used for
// the sharpest warnings — RWX memory, full capability sets).
func BoldRed(s string) string {
	if !Enabled {
		return s
	}
	return bold + red + s + reset
}

func BoldGreen(s string) string {
	if !Enabled {
		return s
	}
	return bold + green + s + reset
}

// Warn renders a "!" flagged warning line consistently across every
// command — bold red bang, then the message in default color.
func Warn(s string) string {
	return wrap(bold+brRed, "!") + " " + s
}

// Ok renders a green checkmark-prefixed line, for hardening features
// that ARE present (no_new_privs=true, seccomp active, LSM confined).
func Ok(s string) string {
	return wrap(brGreen, "✓") + " " + s
}

// SeverityColor picks a color for a 0-100 risk-ish score: green under
// 30, yellow 30-69, red 70+. Used by the risk-scoring feature.
func SeverityColor(score int) func(string) string {
	switch {
	case score >= 70:
		return BoldRed
	case score >= 30:
		return Yellow
	default:
		return Green
	}
}

// Fprintf is a color-aware helper — identical to fmt.Fprintf, kept
// here only so call sites in this package don't need to import fmt
// separately just for the rare non-color line.
func Fprintf(w interface{ Write([]byte) (int, error) }, format string, a ...interface{}) {
	fmt.Fprintf(w, format, a...)
}
