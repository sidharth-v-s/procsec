package proc

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Process represents a single process discovered under /proc/<pid>.
// Fields are populated progressively by the various readers in this
// package (status.go, maps.go, fd.go, ...). A zero-value Process is
// valid; readers should be tolerant of missing/unreadable data since
// processes can disappear between the initial scan and a later read.
type Process struct {
	PID     int
	PPID    int
	Name    string // Comm, from status "Name:" (truncated to 15 chars by kernel)
	Exe     string // resolved target of /proc/<pid>/exe, may be empty if unreadable
	Cmdline []string
	State   string // e.g. "S", "R", "Z"
	UID     int
	GID     int
	Threads int
}

// ErrProcessGone indicates the process exited between discovery and read.
// Callers (especially watch/monitor code) should treat this as expected,
// not as a fatal error.
var ErrProcessGone = fmt.Errorf("process no longer exists")

// procRoot allows tests to point at a fake /proc tree. Defaults to /proc.
var procRoot = "/proc"

// ListPIDs scans /proc and returns every numeric PID directory found.
// It intentionally ignores non-numeric entries (self, sys, net, etc.)
// and silently skips entries that vanish mid-scan (ReadDir raced with
// process exit) rather than failing the whole enumeration.
func ListPIDs() ([]int, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", procRoot, err)
	}

	pids := make([]int, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a PID dir (self, thread-self, sys, ...)
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// pidPath builds a path under /proc/<pid>/...
func pidPath(pid int, parts ...string) string {
	elems := append([]string{procRoot, strconv.Itoa(pid)}, parts...)
	return filepath.Join(elems...)
}

// ReadProcess builds a Process by reading the core /proc/<pid> files
// (status, exe, cmdline). It returns ErrProcessGone (wrapped) if the
// process exits partway through the read, so callers can distinguish
// "expected race" from "real error".
func ReadProcess(pid int) (*Process, error) {
	p := &Process{PID: pid}

	if err := p.readStatus(); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("pid %d: %w", pid, ErrProcessGone)
		}
		return nil, fmt.Errorf("pid %d: status: %w", pid, err)
	}

	// exe and cmdline are best-effort: a kernel thread or a process we
	// don't have permission for will fail here, and that's fine — we
	// keep whatever we got from status and move on rather than
	// discarding the whole Process.
	if exe, err := readExe(pid); err == nil {
		p.Exe = exe
	}
	if cmdline, err := readCmdline(pid); err == nil {
		p.Cmdline = cmdline
	}

	return p, nil
}

// ReadAll enumerates every PID and reads each one. Processes that
// disappear mid-enumeration are silently dropped rather than causing
// the whole call to fail — this is the expected steady state of a
// live /proc tree, not an error condition (design principle: assume
// processes can disappear at any time).
func ReadAll() ([]*Process, error) {
	pids, err := ListPIDs()
	if err != nil {
		return nil, err
	}

	procs := make([]*Process, 0, len(pids))
	for _, pid := range pids {
		p, err := ReadProcess(pid)
		if err != nil {
			continue // gone, or permission denied — skip, don't abort
		}
		procs = append(procs, p)
	}
	return procs, nil
}

// readExe resolves the /proc/<pid>/exe symlink to the executable path.
// This can legitimately fail (kernel threads have no exe, permission
// denied for other users' processes), which callers should treat as
// "unknown" rather than fatal.
func readExe(pid int) (string, error) {
	return os.Readlink(pidPath(pid, "exe"))
}

// readCmdline parses the NUL-separated argv from /proc/<pid>/cmdline.
// A kernel thread has an empty cmdline (zero args), which is valid.
func readCmdline(pid int) ([]string, error) {
	data, err := os.ReadFile(pidPath(pid, "cmdline"))
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimRight(string(data), "\x00")
	if trimmed == "" {
		return []string{}, nil
	}
	return strings.Split(trimmed, "\x00"), nil
}
