package proc

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Mapping represents one line of /proc/<pid>/maps — a single
// contiguous virtual memory region.
type Mapping struct {
	Start, End uint64 // virtual address range
	Perms      string // e.g. "r-xp", "rw-p"
	Offset     uint64
	Dev        string
	Inode      uint64
	Path       string // file-backed path, or "[heap]"/"[stack]"/"" for anonymous
}

// Readable/Writable/Executable/Private/Shared decode the 4-char
// perms string. Perms is always "rwxp" or "rwxs" shaped (dashes for
// unset flags), so a straightforward byte check is sufficient and
// avoids a regex per line across potentially thousands of mappings.
func (m Mapping) Readable() bool   { return len(m.Perms) > 0 && m.Perms[0] == 'r' }
func (m Mapping) Writable() bool   { return len(m.Perms) > 1 && m.Perms[1] == 'w' }
func (m Mapping) Executable() bool { return len(m.Perms) > 2 && m.Perms[2] == 'x' }
func (m Mapping) Private() bool    { return len(m.Perms) > 3 && m.Perms[3] == 'p' }
func (m Mapping) Shared() bool     { return len(m.Perms) > 3 && m.Perms[3] == 's' }

// Anonymous reports whether this mapping has no backing file — i.e.
// heap, stack, or an anonymous mmap, as opposed to a mapped library
// or executable.
func (m Mapping) Anonymous() bool {
	return m.Path == "" || strings.HasPrefix(m.Path, "[") || m.Inode == 0
}

// RWX reports whether this mapping is simultaneously writable and
// executable — the classic red-flag memory permission combination
// (W^X violation) worth calling out explicitly in security views.
func (m Mapping) RWX() bool {
	return m.Writable() && m.Executable()
}

// ReadMaps parses /proc/<pid>/maps into a slice of Mapping. Returns
// ErrProcessGone (wrapped) if the process exits mid-read.
func ReadMaps(pid int) ([]Mapping, error) {
	f, err := os.Open(pidPath(pid, "maps"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("pid %d: %w", pid, ErrProcessGone)
		}
		return nil, err
	}
	defer f.Close()

	var maps []Mapping
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		m, ok := parseMapsLine(scanner.Text())
		if ok {
			maps = append(maps, m)
		}
	}
	return maps, scanner.Err()
}

// parseMapsLine parses one line of /proc/<pid>/maps, e.g.:
//
//	7f2a10000000-7f2a10200000 r-xp 00000000 08:01 131076  /usr/lib/libc.so.6
//
// The path field is optional (anonymous mappings have no trailing
// path); everything else is mandatory. Malformed lines are skipped
// (ok=false) rather than aborting the whole parse — a single odd
// line (kernel quirk, race during read) shouldn't lose the rest of
// the map.
func parseMapsLine(line string) (Mapping, bool) {
	fields := strings.SplitN(line, " ", 6)
	// Fields may contain repeated spaces before the path; SplitN with
	// a fixed count of spaces is fragile, so re-split properly below.
	fields = strings.Fields(line)
	if len(fields) < 5 {
		return Mapping{}, false
	}

	addrs := strings.SplitN(fields[0], "-", 2)
	if len(addrs) != 2 {
		return Mapping{}, false
	}
	start, err1 := strconv.ParseUint(addrs[0], 16, 64)
	end, err2 := strconv.ParseUint(addrs[1], 16, 64)
	if err1 != nil || err2 != nil {
		return Mapping{}, false
	}

	offset, _ := strconv.ParseUint(fields[2], 16, 64)
	inode, _ := strconv.ParseUint(fields[4], 10, 64)

	path := ""
	if len(fields) >= 6 {
		path = strings.Join(fields[5:], " ")
	}

	return Mapping{
		Start:  start,
		End:    end,
		Perms:  fields[1],
		Offset: offset,
		Dev:    fields[3],
		Inode:  inode,
		Path:   path,
	}, true
}

// MapSummary aggregates classification counts over a set of mappings,
// for the quick-glance security view (section 11/21 of the design doc).
type MapSummary struct {
	Total         int
	Executable    int
	Writable      int
	RWX           int
	AnonymousExec int // executable AND anonymous — notably suspicious
	FileBacked    int
	Anonymous     int
}

func SummarizeMaps(maps []Mapping) MapSummary {
	var s MapSummary
	s.Total = len(maps)
	for _, m := range maps {
		if m.Executable() {
			s.Executable++
		}
		if m.Writable() {
			s.Writable++
		}
		if m.RWX() {
			s.RWX++
		}
		if m.Anonymous() {
			s.Anonymous++
			if m.Executable() {
				s.AnonymousExec++
			}
		} else {
			s.FileBacked++
		}
	}
	return s
}
