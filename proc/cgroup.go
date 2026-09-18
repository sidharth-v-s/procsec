package proc

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// CgroupEntry is one line of /proc/<pid>/cgroup: "ID:controllers:path".
// Under cgroup v2 (unified hierarchy, the common case on modern
// distros) there is exactly one line with ID=0 and an empty
// controller list; under v1 there is one line per controller
// (cpu, memory, pids, ...).
type CgroupEntry struct {
	ID          string
	Controllers []string // empty under pure cgroup v2
	Path        string
}

// ReadCgroups parses /proc/<pid>/cgroup.
func ReadCgroups(pid int) ([]CgroupEntry, error) {
	f, err := os.Open(pidPath(pid, "cgroup"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("pid %d: %w", pid, ErrProcessGone)
		}
		return nil, err
	}
	defer f.Close()

	var entries []CgroupEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 3)
		if len(parts) != 3 {
			continue
		}
		var controllers []string
		if parts[1] != "" {
			controllers = strings.Split(parts[1], ",")
		}
		entries = append(entries, CgroupEntry{
			ID:          parts[0],
			Controllers: controllers,
			Path:        parts[2],
		})
	}
	return entries, scanner.Err()
}

// IsCgroupV2 reports whether entries represents a pure cgroup v2
// (unified hierarchy) layout — a single entry with no controller list.
func IsCgroupV2(entries []CgroupEntry) bool {
	return len(entries) == 1 && len(entries[0].Controllers) == 0
}
