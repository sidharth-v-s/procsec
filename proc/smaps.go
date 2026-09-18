package proc

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// SmapsSummary aggregates the per-mapping detail in /proc/<pid>/smaps
// into totals useful for a security overview: how much memory is
// private vs shared, anonymous vs file-backed, and — most
// interesting from a security angle — how much executable memory has
// no backing file (a common shellcode/injection indicator).
type SmapsSummary struct {
	RSS              int64 // KB, total resident
	PSS              int64 // KB, proportional set size
	PrivateClean     int64
	PrivateDirty     int64
	SharedClean      int64
	SharedDirty      int64
	AnonymousKB      int64
	AnonHugePagesKB  int64
	LockedKB         int64
	ExecutableAnonKB int64 // anonymous mappings that are also executable
	RWXKB            int64 // writable+executable mapping memory
}

// ReadSmapsSummary parses /proc/<pid>/smaps, which interleaves one
// "maps"-style header line per mapping with a block of "Key: N kB"
// detail lines. Requires read access to smaps (root or same-UID);
// callers should treat a permission error as "unavailable" rather
// than fatal, since smaps is more heavily gated than maps on many
// hardened systems.
func ReadSmapsSummary(pid int) (*SmapsSummary, error) {
	f, err := os.Open(pidPath(pid, "smaps"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("pid %d: %w", pid, ErrProcessGone)
		}
		return nil, err
	}
	defer f.Close()

	sum := &SmapsSummary{}
	scanner := bufio.NewScanner(f)

	var curPerms string
	var curAnon bool

	for scanner.Scan() {
		line := scanner.Text()

		// A new mapping header looks like a maps.go line: starts with
		// a hex address range. Detect it by checking for '-' before
		// the first space in the first field.
		if isMapsHeaderLine(line) {
			m, ok := parseMapsLine(line)
			if ok {
				curPerms = m.Perms
				curAnon = m.Anonymous()
			}
			continue
		}

		key, val, ok := splitSmapsLine(line)
		if !ok {
			continue
		}

		kb := smapsKB(val)
		switch key {
		case "Rss":
			sum.RSS += kb
		case "Pss":
			sum.PSS += kb
		case "Private_Clean":
			sum.PrivateClean += kb
		case "Private_Dirty":
			sum.PrivateDirty += kb
		case "Shared_Clean":
			sum.SharedClean += kb
		case "Shared_Dirty":
			sum.SharedDirty += kb
		case "Anonymous":
			sum.AnonymousKB += kb
			if strings.Contains(curPerms, "x") {
				sum.ExecutableAnonKB += kb
			}
		case "AnonHugePages":
			sum.AnonHugePagesKB += kb
		case "Locked":
			sum.LockedKB += kb
		}

		if strings.Contains(curPerms, "w") && strings.Contains(curPerms, "x") {
			if key == "Rss" {
				sum.RWXKB += kb
			}
		}
		_ = curAnon // reserved for future anon-specific breakdowns
	}
	return sum, scanner.Err()
}

func isMapsHeaderLine(line string) bool {
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return false
	}
	return strings.Contains(line[:sp], "-")
}

func splitSmapsLine(line string) (key, val string, ok bool) {
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		return "", "", false
	}
	return line[:idx], strings.TrimSpace(line[idx+1:]), true
}

func smapsKB(val string) int64 {
	fields := strings.Fields(val)
	if len(fields) == 0 {
		return 0
	}
	n, _ := strconv.ParseInt(fields[0], 10, 64)
	return n
}
