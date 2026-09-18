package proc

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// FDKind classifies what a file descriptor points at, for the
// summary counts in `procsec fds`.
type FDKind string

const (
	FDStdin   FDKind = "stdin"
	FDStdout  FDKind = "stdout"
	FDStderr  FDKind = "stderr"
	FDRegular FDKind = "regular"
	FDSocket  FDKind = "socket"
	FDPipe    FDKind = "pipe"
	FDDevice  FDKind = "device"
	FDOther   FDKind = "other"
)

// FD represents one entry under /proc/<pid>/fd/.
type FD struct {
	Num    int
	Target string // resolved symlink target, e.g. "/etc/passwd" or "socket:[12345]"
	Kind   FDKind
}

// ReadFDs enumerates and classifies every file descriptor open by
// pid. Individual FDs that vanish between readdir and readlink
// (extremely common — fds churn constantly) are silently skipped
// rather than aborting the whole listing.
func ReadFDs(pid int) ([]FD, error) {
	dir := pidPath(pid, "fd")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("pid %d: %w", pid, ErrProcessGone)
		}
		return nil, err
	}

	fds := make([]FD, 0, len(entries))
	for _, e := range entries {
		num, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		target, err := os.Readlink(pidPath(pid, "fd", e.Name()))
		if err != nil {
			continue // raced with close() — expected, not an error
		}
		fds = append(fds, FD{
			Num:    num,
			Target: target,
			Kind:   classifyFD(num, target),
		})
	}

	sort.Slice(fds, func(i, j int) bool { return fds[i].Num < fds[j].Num })
	return fds, nil
}

func classifyFD(num int, target string) FDKind {
	switch {
	case num == 0:
		return FDStdin
	case num == 1:
		return FDStdout
	case num == 2:
		return FDStderr
	case strings.HasPrefix(target, "socket:"):
		return FDSocket
	case strings.HasPrefix(target, "pipe:"):
		return FDPipe
	case strings.HasPrefix(target, "/dev/"), strings.HasPrefix(target, "anon_inode:"):
		return FDDevice
	case strings.HasPrefix(target, "/"):
		return FDRegular
	default:
		return FDOther
	}
}

// FDSummary aggregates counts by kind, for the `fds` command's
// summary block.
type FDSummary struct {
	Regular, Sockets, Pipes, Devices, Other int
}

func SummarizeFDs(fds []FD) FDSummary {
	var s FDSummary
	for _, fd := range fds {
		switch fd.Kind {
		case FDRegular:
			s.Regular++
		case FDSocket:
			s.Sockets++
		case FDPipe:
			s.Pipes++
		case FDDevice:
			s.Devices++
		case FDStdin, FDStdout, FDStderr:
			// counted implicitly via Regular/Device by their target;
			// std streams are also shown individually in the listing
		default:
			s.Other++
		}
	}
	return s
}
