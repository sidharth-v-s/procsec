package proc

import (
	"fmt"
	"os"
	"regexp"
)

// nsTypes are the namespace kinds exposed under /proc/<pid>/ns/, per
// the design doc's list. cgroup and time were added in later kernels
// and may be absent on older ones — ReadNamespaces tolerates that.
var nsTypes = []string{
	"cgroup", "ipc", "mnt", "net", "pid", "pid_for_children", "time", "user", "uts",
}

// Namespaces maps namespace type -> its kernel identifier, read from
// the inode number embedded in each /proc/<pid>/ns/<type> symlink
// target (format: "net:[4026531840]").
type Namespaces map[string]uint64

var nsLinkPattern = regexp.MustCompile(`^\w+:\[(\d+)\]$`)

// ReadNamespaces reads every available /proc/<pid>/ns/<type> symlink
// and extracts its inode identifier. Namespace types unavailable on
// this kernel (or unreadable due to permissions) are simply omitted
// from the result rather than causing an error — comparing two
// processes' Namespaces maps naturally treats a namespace present in
// one but not the other as "differs", which is the correct behavior.
func ReadNamespaces(pid int) (Namespaces, error) {
	ns := make(Namespaces)
	found := false

	for _, t := range nsTypes {
		target, err := os.Readlink(pidPath(pid, "ns", t))
		if err != nil {
			continue // type unsupported on this kernel, or permission denied
		}
		found = true
		if m := nsLinkPattern.FindStringSubmatch(target); m != nil {
			var id uint64
			fmt.Sscanf(m[1], "%d", &id)
			ns[t] = id
		}
	}

	if !found {
		return nil, fmt.Errorf("pid %d: %w", pid, ErrProcessGone)
	}
	return ns, nil
}

// NamespaceDiff describes, for two processes, which namespace types
// they share (same inode) and which differ.
type NamespaceDiff struct {
	Shared []string
	Differ []string
	// OnlyA/OnlyB list namespace types present for only one side,
	// e.g. because of a permission difference or kernel feature gap.
	OnlyA []string
	OnlyB []string
}

// CompareNamespaces builds a NamespaceDiff between two processes'
// namespace sets, useful for `procsec ns` when comparing a process
// against its parent or another process (design doc section 13).
func CompareNamespaces(a, b Namespaces) NamespaceDiff {
	var d NamespaceDiff
	for t, idA := range a {
		idB, ok := b[t]
		if !ok {
			d.OnlyA = append(d.OnlyA, t)
			continue
		}
		if idA == idB {
			d.Shared = append(d.Shared, t)
		} else {
			d.Differ = append(d.Differ, t)
		}
	}
	for t := range b {
		if _, ok := a[t]; !ok {
			d.OnlyB = append(d.OnlyB, t)
		}
	}
	return d
}
