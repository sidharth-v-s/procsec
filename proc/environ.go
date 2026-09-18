package proc

import (
	"fmt"
	"os"
	"strings"
)

// EnvVar is one KEY=VALUE pair from a process's environment.
type EnvVar struct {
	Key   string
	Value string
}

// sensitiveKeyMarkers are substrings that, when found in an
// environment variable's key, mark it as potentially sensitive.
// This is a naming heuristic only — it does not inspect values —
// deliberately, so procsec can flag *which* vars look sensitive
// without needing to read (and thus expose) their contents by
// default (design principle: minimize sensitive data exposure).
var sensitiveKeyMarkers = []string{
	"TOKEN", "KEY", "SECRET", "PASSWORD", "PASSWD", "PWD_",
	"AWS_", "CREDENTIAL", "AUTH", "PRIVATE", "APIKEY", "API_KEY",
	"ACCESS_KEY", "CLIENT_SECRET", "SESSION",
}

// ReadEnviron parses /proc/<pid>/environ into KEY=VALUE pairs.
// Requires same-UID or root; a permission error is common and
// expected for other users' processes and should be surfaced as
// "environment not readable" by callers rather than a crash.
func ReadEnviron(pid int) ([]EnvVar, error) {
	data, err := os.ReadFile(pidPath(pid, "environ"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("pid %d: %w", pid, ErrProcessGone)
		}
		return nil, err
	}

	trimmed := strings.TrimRight(string(data), "\x00")
	if trimmed == "" {
		return []EnvVar{}, nil
	}

	entries := strings.Split(trimmed, "\x00")
	vars := make([]EnvVar, 0, len(entries))
	for _, e := range entries {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		vars = append(vars, EnvVar{Key: k, Value: v})
	}
	return vars, nil
}

// IsSensitiveKey reports whether an environment variable's name
// matches a known secret-naming pattern (AWS_*, *_TOKEN, PASSWORD,
// etc.), per the design doc's "flag but don't dump" policy.
func IsSensitiveKey(key string) bool {
	upper := strings.ToUpper(key)
	for _, marker := range sensitiveKeyMarkers {
		if strings.Contains(upper, marker) {
			return true
		}
	}
	return false
}

// SensitiveKeys returns just the names (never the values) of
// environment variables that look sensitive, for default-safe
// display. Callers that explicitly want values must opt in
// separately (e.g. an explicit --reveal flag), never implicitly.
func SensitiveKeys(vars []EnvVar) []string {
	keys := make([]string, 0)
	for _, v := range vars {
		if IsSensitiveKey(v.Key) {
			keys = append(keys, v.Key)
		}
	}
	return keys
}
