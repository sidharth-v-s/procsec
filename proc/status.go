package proc

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// StatusExtra holds the security-relevant /proc/<pid>/status fields
// that don't fit neatly into the core Process struct. Kept separate
// so ReadProcess's hot path stays cheap and callers that need the
// full security picture (procsec security/inspect --security) opt in.
type StatusExtra struct {
	Groups     []int
	VmSize     int64 // KB
	VmRSS      int64 // KB
	VmPeak     int64 // KB
	CapInh     uint64
	CapPrm     uint64
	CapEff     uint64
	CapBnd     uint64
	NoNewPrivs bool
	Seccomp    int // 0=disabled, 1=strict, 2=filter
}

// readStatus parses /proc/<pid>/status and populates the core fields
// on p (Name, State, PPid, Uid, Gid, Threads). Line format is
// "Key:\tvalue" or "Key:\tvalue1\tvalue2..." for multi-value fields
// like Uid (real/effective/saved/fs) — we take the first value
// (real) for Process.UID/GID, matching `ps` semantics.
func (p *Process) readStatus() error {
	f, err := os.Open(pidPath(p.PID, "status"))
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		key, val, ok := splitStatusLine(line)
		if !ok {
			continue
		}

		switch key {
		case "Name":
			p.Name = val
		case "State":
			// format: "S (sleeping)" — we want just the letter
			p.State = strings.Fields(val)[0]
		case "PPid":
			p.PPID, _ = strconv.Atoi(val)
		case "Uid":
			p.UID = firstInt(val)
		case "Gid":
			p.GID = firstInt(val)
		case "Threads":
			p.Threads, _ = strconv.Atoi(val)
		}
	}
	return scanner.Err()
}

// ReadStatusExtra parses the security/memory fields from
// /proc/<pid>/status that ReadProcess doesn't populate by default.
// Called explicitly by inspect/security/caps commands rather than
// on every ReadProcess, since most callers (e.g. `procsec ps`)
// don't need it.
func ReadStatusExtra(pid int) (*StatusExtra, error) {
	f, err := os.Open(pidPath(pid, "status"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	extra := &StatusExtra{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, val, ok := splitStatusLine(scanner.Text())
		if !ok {
			continue
		}

		switch key {
		case "Groups":
			extra.Groups = parseIntFields(val)
		case "VmSize":
			extra.VmSize = firstKB(val)
		case "VmRSS":
			extra.VmRSS = firstKB(val)
		case "VmPeak":
			extra.VmPeak = firstKB(val)
		case "CapInh":
			extra.CapInh = parseHex64(val)
		case "CapPrm":
			extra.CapPrm = parseHex64(val)
		case "CapEff":
			extra.CapEff = parseHex64(val)
		case "CapBnd":
			extra.CapBnd = parseHex64(val)
		case "NoNewPrivs":
			extra.NoNewPrivs = val == "1"
		case "Seccomp":
			extra.Seccomp, _ = strconv.Atoi(val)
		}
	}
	return extra, scanner.Err()
}

// splitStatusLine splits a "Key:\tvalue" line into key/value, with
// whitespace trimmed. Returns ok=false for blank or malformed lines
// so callers can skip them with a single check.
func splitStatusLine(line string) (key, val string, ok bool) {
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		return "", "", false
	}
	key = line[:idx]
	val = strings.TrimSpace(line[idx+1:])
	return key, val, true
}

// firstInt returns the first whitespace-separated integer in s,
// e.g. "1000\t1000\t1000\t1000" -> 1000. Used for Uid/Gid lines
// which report real/effective/saved/fs values; we surface "real"
// as the headline value, matching ps/top convention.
func firstInt(s string) int {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(fields[0])
	return n
}

// firstKB parses a "VmRSS:\t1234 kB" style value (already stripped
// of the key) down to just the numeric KB amount.
func firstKB(s string) int64 {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	n, _ := strconv.ParseInt(fields[0], 10, 64)
	return n
}

// parseIntFields splits a whitespace-separated list of ints, e.g.
// the "Groups:" line ("4 24 27 30 46 116 1000").
func parseIntFields(s string) []int {
	fields := strings.Fields(s)
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		if n, err := strconv.Atoi(f); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// parseHex64 parses a capability bitmask like "0000003fffffffff".
// Malformed input yields 0 rather than an error — a missing/garbled
// capability field shouldn't abort an otherwise-useful status read.
func parseHex64(s string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSpace(s), 16, 64)
	return n
}
