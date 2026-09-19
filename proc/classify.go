package proc

import (
	"os"
	"strings"
)

// ProcType classifies what kind of process this is, so downstream
// consumers (risk scoring, top, watch, filtering) can treat kernel
// threads differently from user processes rather than penalizing
// both for the same properties (root UID, full capabilities, no
// seccomp) that are completely normal for a kernel thread but
// genuinely worth attention for a user process.
type ProcType string

const (
	TypeKernelThread ProcType = "kernel-thread"
	TypeUserProcess  ProcType = "user-process"
	TypeDaemon       ProcType = "daemon"
	TypeInteractive  ProcType = "interactive"
	TypeUnknown      ProcType = "unknown"
)

// Classify determines a process's ProcType from signals already
// available on Process plus one cheap extra check (session/tty via
// /proc/<pid>/stat). This is a heuristic, not a kernel-exposed fact —
// the kernel doesn't label processes "daemon" vs "interactive" — but
// the signals used (no exe, PPID 2 lineage, no controlling tty) are
// the same ones `ps`/`ps -e` and ecosystem tools rely on.
func Classify(p *Process) ProcType {
	if isKernelThread(p) {
		return TypeKernelThread
	}

	hasTTY := hasControllingTTY(p.PID)
	if hasTTY {
		return TypeInteractive
	}

	// No controlling TTY and not a kernel thread: almost certainly a
	// daemon/service (started by init/systemd, backgrounded, or
	// re-parented to PID 1 after its original parent exited).
	if p.PPID == 1 || p.PPID == 0 {
		return TypeDaemon
	}

	if p.Exe != "" {
		return TypeUserProcess
	}

	return TypeUnknown
}

// isKernelThread reports whether p is a kernel thread. The reliable
// signal is: no /proc/<pid>/exe target (kernel threads have no
// userspace executable — the readlink fails with ENOENT, which
// ReadProcess already treats as "Exe stays empty" rather than an
// error) AND either PPID 2 (kthreadd, the kernel thread parent on
// modern Linux) or PID 2 itself. Checking both catches kthreadd's
// direct children as well as kthreadd itself.
func isKernelThread(p *Process) bool {
	if p.Exe != "" {
		return false // has a real userspace executable, definitely not a kernel thread
	}
	if p.PID == 2 {
		return true // kthreadd itself
	}
	return p.PPID == 2
}

// hasControllingTTY reports whether pid has a controlling terminal,
// by checking whether /proc/<pid>/fd/0 (stdin) resolves to a
// /dev/pts/* or /dev/tty* device. This is a best-effort heuristic:
// permission-denied or a redirected stdin both read as "no tty"
// (false), which biases toward classifying as daemon rather than
// interactive on uncertainty — a reasonable default since daemons
// vastly outnumber interactive shells on a typical box.
func hasControllingTTY(pid int) bool {
	target, err := readFD0Target(pid)
	if err != nil {
		return false
	}
	return strings.HasPrefix(target, "/dev/pts/") || strings.HasPrefix(target, "/dev/tty")
}

func readFD0Target(pid int) (string, error) {
	return os.Readlink(pidPath(pid, "fd", "0"))
}

// TypeLabel returns a short display label, colored/plain handled by
// the output package — this just returns the plain classification.
func (p *Process) TypeLabel() ProcType {
	return Classify(p)
}
