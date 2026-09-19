package proc

import (
	"os/user"
	"strconv"
	"strings"
)

// Filter narrows a process list. Zero-value fields are "don't filter
// on this dimension" — an empty Filter matches everything.
type Filter struct {
	Name          string   // substring match against Name or Cmdline, case-insensitive
	User          string   // username or numeric UID
	State         string   // exact state letter, e.g. "Z" for zombies
	UID           *int     // set internally by ResolveUser; nil means unset
	Type          ProcType // exact process type, e.g. TypeKernelThread
	ExcludeKernel bool     // shortcut equivalent to excluding TypeKernelThread
}

// ResolveUser fills f.UID from f.User (accepting either a username
// or a raw numeric UID string), so callers only need to set User and
// call this once before Apply.
func (f *Filter) ResolveUser() {
	if f.User == "" {
		return
	}
	if n, err := strconv.Atoi(f.User); err == nil {
		f.UID = &n
		return
	}
	if u, err := user.Lookup(f.User); err == nil {
		if n, err := strconv.Atoi(u.Uid); err == nil {
			f.UID = &n
		}
	}
}

// Apply returns the subset of procs matching every set dimension of
// f (AND semantics across dimensions).
func (f Filter) Apply(procs []*Process) []*Process {
	if f.Name == "" && f.UID == nil && f.State == "" && f.Type == "" && !f.ExcludeKernel {
		return procs
	}

	out := make([]*Process, 0, len(procs))
	nameLower := strings.ToLower(f.Name)

	for _, p := range procs {
		if f.Name != "" {
			if !strings.Contains(strings.ToLower(p.Name), nameLower) &&
				!cmdlineContains(p.Cmdline, nameLower) {
				continue
			}
		}
		if f.UID != nil && p.UID != *f.UID {
			continue
		}
		if f.State != "" && p.State != f.State {
			continue
		}
		if f.Type != "" || f.ExcludeKernel {
			t := Classify(p)
			if f.Type != "" && t != f.Type {
				continue
			}
			if f.ExcludeKernel && t == TypeKernelThread {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

func cmdlineContains(cmdline []string, needleLower string) bool {
	for _, arg := range cmdline {
		if strings.Contains(strings.ToLower(arg), needleLower) {
			return true
		}
	}
	return false
}

// Zombies filters a process list down to zombie (defunct) processes
// — state "Z" — a common security-relevant signal (orphaned children,
// reaping issues) worth a dedicated one-liner rather than requiring
// operators to remember the state letter.
func Zombies(procs []*Process) []*Process {
	f := Filter{State: "Z"}
	return f.Apply(procs)
}

// RunningAsRoot filters to UID 0 processes.
func RunningAsRoot(procs []*Process) []*Process {
	zero := 0
	f := Filter{UID: &zero}
	return f.Apply(procs)
}
