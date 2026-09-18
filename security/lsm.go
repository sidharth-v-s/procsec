package security

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LSMContext holds what we could learn about a process's Linux
// Security Module confinement. Every field is best-effort: LSM
// interfaces vary wildly by distro/kernel config, so an empty
// LSMContext (Module == "") is a normal, expected outcome, not
// an error — callers must render that gracefully rather than
// treating it as a failure.
type LSMContext struct {
	Module  string // "apparmor", "selinux", "none", or "" if undetermined
	Context string // raw contents of /proc/<pid>/attr/current, trimmed
}

// ReadLSMContext inspects /proc/<pid>/attr/current to determine LSM
// confinement. The file's presence/format differs by which LSM is
// active:
//   - AppArmor: "profile-name (enforce)" or "unconfined"
//   - SELinux:  "user:role:type:level"
//   - No LSM / unreadable: the read fails, which we treat as
//     "unknown" rather than propagating an error, since this is one
//     of the most environment-dependent interfaces in /proc.
func ReadLSMContext(pid int) LSMContext {
	path := fmt.Sprintf("/proc/%d/attr/current", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return LSMContext{}
	}

	raw := strings.TrimSpace(strings.TrimRight(string(data), "\x00"))
	if raw == "" {
		return LSMContext{}
	}

	return LSMContext{
		Module:  detectLSMModule(raw),
		Context: raw,
	}
}

// detectLSMModule guesses which LSM produced a given /attr/current
// value based on its shape. This is a heuristic, not a guarantee —
// checking /sys/kernel/security/lsm (when readable) is more
// authoritative but requires broader privileges than /proc/<pid>/attr.
func detectLSMModule(raw string) string {
	switch {
	case raw == "unconfined":
		return "apparmor" // AppArmor's specific "no profile" spelling
	case strings.Contains(raw, "(enforce)"), strings.Contains(raw, "(complain)"):
		return "apparmor"
	case strings.Count(raw, ":") >= 3:
		return "selinux" // user:role:type:level[:category]
	default:
		return "unknown"
	}
}

// ActiveLSMs reads /sys/kernel/security/lsm if available, which lists
// every LSM compiled in and active on this system (not just what's
// applied to one process). Requires the securityfs to be mounted and
// readable; returns nil, not an error, if it isn't.
func ActiveLSMs() []string {
	data, err := os.ReadFile(filepath.Join("/sys/kernel/security", "lsm"))
	if err != nil {
		return nil
	}
	raw := strings.TrimSpace(string(data))
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}
