package proc

import (
	"errors"
	"os"
	"syscall"
)

// AccessState describes whether a particular /proc source for a
// process was readable, and if not, why — distinguishing "the
// process exited" (Gone) from "we don't have permission" (Denied)
// from "something else went wrong" (Error). Callers use this instead
// of a bare bool so output can say *why* a field is missing rather
// than silently rendering blank/dash, per the design doc's
// "represent inaccessibility explicitly" principle.
type AccessState int

const (
	Readable    AccessState = iota
	Gone                    // process exited (ENOENT)
	Denied                  // permission denied (EACCES/EPERM)
	Unavailable             // any other error (unsupported kernel feature, etc.)
)

func (a AccessState) String() string {
	switch a {
	case Readable:
		return "readable"
	case Gone:
		return "gone"
	case Denied:
		return "restricted"
	default:
		return "unavailable"
	}
}

// classifyErr turns a raw error from a /proc read into an
// AccessState. A nil error is Readable. This is the single place
// that maps ENOENT/EACCES/EPERM to their meaning across the whole
// proc package, so every reader reports access failures consistently.
func classifyErr(err error) AccessState {
	if err == nil {
		return Readable
	}
	if errors.Is(err, os.ErrNotExist) {
		return Gone
	}
	if errors.Is(err, os.ErrPermission) {
		return Denied
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return Denied
	}
	if errors.Is(err, syscall.ENOENT) {
		return Gone
	}
	return Unavailable
}

// Accessibility summarizes, per major /proc source, whether we could
// read it for a given PID — the "Environment: inaccessible / Maps:
// readable" report the design doc calls for. Built on demand by
// ProbeAccessibility rather than during every ReadProcess, since
// most callers don't need it and probing every source is itself
// several syscalls.
type Accessibility struct {
	Status  AccessState
	Exe     AccessState
	Cmdline AccessState
	Environ AccessState
	Maps    AccessState
	Smaps   AccessState
	FDs     AccessState
	NS      AccessState
	Cgroup  AccessState
}

// ProbeAccessibility checks every major /proc/<pid> source for pid
// and reports which are readable, restricted, gone, or otherwise
// unavailable — without fully parsing any of them. Used by `inspect`
// and `investigate` to show the operator exactly what procsec could
// and couldn't see for a process, rather than silently omitting
// sections.
func ProbeAccessibility(pid int) Accessibility {
	return Accessibility{
		Status:  classifyErr(probeReadable(pidPath(pid, "status"))),
		Exe:     classifyErr(probeReadlink(pidPath(pid, "exe"))),
		Cmdline: classifyErr(probeReadable(pidPath(pid, "cmdline"))),
		Environ: classifyErr(probeReadable(pidPath(pid, "environ"))),
		Maps:    classifyErr(probeReadable(pidPath(pid, "maps"))),
		Smaps:   classifyErr(probeReadable(pidPath(pid, "smaps"))),
		FDs:     classifyErr(probeListable(pidPath(pid, "fd"))),
		NS:      classifyErr(probeListable(pidPath(pid, "ns"))),
		Cgroup:  classifyErr(probeReadable(pidPath(pid, "cgroup"))),
	}
}

func probeReadable(path string) error {
	f, err := os.Open(path)
	if err == nil {
		f.Close()
	}
	return err
}

func probeReadlink(path string) error {
	_, err := os.Readlink(path)
	return err
}

func probeListable(path string) error {
	_, err := os.ReadDir(path)
	return err
}
