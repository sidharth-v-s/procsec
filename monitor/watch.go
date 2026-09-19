// Package monitor implements procsec's live-observation features:
// polling-based process creation/exit detection (pspy-style) and
// security-context-change detection for processes that persist
// across polls (design doc section: "Security Context Change
// Detection"). This is deliberately poll-based, not netlink/eBPF —
// see design philosophy section 30 for why (simplicity + portability
// over completeness; a fast poll interval catches the vast majority
// of short-lived processes without requiring elevated capabilities).
package monitor

import (
	"strings"
	"time"

	"procsec/proc"
)

// EventKind distinguishes the two kinds of events a Watcher emits.
type EventKind int

const (
	EventStarted EventKind = iota
	EventExited
	EventContextChanged
)

// Event is one observed change, emitted on the Watcher's channel.
type Event struct {
	Kind    EventKind
	Time    time.Time
	Process *proc.Process // full snapshot at time of the event
	Type    string        // proc.ProcType as a string, to avoid a proc<->monitor import cycle concern at call sites

	// Populated only for EventContextChanged: what changed and how.
	Changes []ContextChange
}

// ContextChange describes a single security-relevant field that
// changed for a still-running PID between two polls — e.g. a process
// that started as UID 1000 and is now UID 0 (a privilege escalation
// in progress), or one whose capability set grew. Reported as an
// observation, never auto-classified as malicious — per the design
// doc, the operator decides what a given transition means.
type ContextChange struct {
	Field string // "uid", "gid", "exe", "cap_eff", "netns", "seccomp", "no_new_privs"
	Old   string
	New   string
}

// Filter narrows which processes a Watcher reports on. Zero-value
// fields mean "don't filter on this dimension". Applied at poll time
// before any event is emitted, so filtered-out processes never even
// enter the tracked `known` map — keeping overhead down on a busy,
// heavily-filtered watch.
type Filter struct {
	UID           *int   // only this UID
	ExcludeKernel bool   // skip kernel threads entirely (kworker/*, ksoftirqd/*, etc.)
	Exe           string // substring match against resolved exe path
}

func (f Filter) matches(p *proc.Process, ptype proc.ProcType) bool {
	if f.ExcludeKernel && ptype == proc.TypeKernelThread {
		return false
	}
	if f.UID != nil && p.UID != *f.UID {
		return false
	}
	if f.Exe != "" && !strings.Contains(p.Exe, f.Exe) {
		return false
	}
	return true
}

// snapshot is the internal per-PID state a Watcher tracks between
// polls, holding just enough to detect the changes we care about
// without re-reading full StatusExtra on every single poll for every
// PID (only diffed when something cheap already looks different, or
// periodically — see Watcher.deepCheckEvery).
type snapshot struct {
	proc.Process
	CapEff        uint64
	NetNS         uint64
	Seccomp       int
	NoNewPrivs    bool
	lastDeepCheck time.Time
}

// Watcher polls /proc at Interval and emits Events for process
// lifecycle changes and (optionally) security context changes.
type Watcher struct {
	Interval time.Duration

	// DeepCheckInterval controls how often, per PID, we read the
	// heavier StatusExtra (capabilities) to look for context changes,
	// versus just the cheap core status fields every poll. Zero
	// disables context-change detection entirely (pure pspy-style
	// start/exit watching).
	DeepCheckInterval time.Duration

	// Filter, if set, restricts which processes generate events at
	// all (see Filter above). Nil/zero-value Filter means no filtering.
	Filter Filter

	known map[int]*snapshot
}

// NewWatcher returns a Watcher with sane defaults matching the
// design doc's stated goal of catching most short-lived processes:
// a 100ms poll interval, with a capability/UID deep-check every 2s
// per PID to bound overhead on busy systems.
func NewWatcher() *Watcher {
	return &Watcher{
		Interval:          100 * time.Millisecond,
		DeepCheckInterval: 2 * time.Second,
		known:             make(map[int]*snapshot),
	}
}

// Run polls until stop is closed, sending Events to out. Run performs
// an initial poll synchronously (so the very first tick after Run
// starts can already report events) and does not close out — the
// caller owns that, since Run may be one of several producers in a
// larger program.
func (w *Watcher) Run(out chan<- Event, stop <-chan struct{}) {
	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()

	w.poll(out) // prime `known` + report anything already present as "started"

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			w.poll(out)
		}
	}
}

// poll takes one snapshot of /proc, diffs it against w.known, and
// emits Started/Exited/ContextChanged events accordingly. Processes
// excluded by w.Filter are skipped entirely — they never enter
// `known` and never generate any event.
func (w *Watcher) poll(out chan<- Event) {
	pids, err := proc.ListPIDs()
	if err != nil {
		return // transient /proc read failure; try again next tick
	}

	now := time.Now()
	seen := make(map[int]bool, len(pids))

	for _, pid := range pids {
		p, err := proc.ReadProcess(pid)
		if err != nil {
			continue // exited between ListPIDs and ReadProcess — next poll's Exited handles bookkeeping
		}

		ptype := proc.Classify(p)
		if !w.Filter.matches(p, ptype) {
			continue
		}
		seen[pid] = true

		existing, known := w.known[pid]
		if !known {
			snap := &snapshot{Process: *p, lastDeepCheck: now}
			if w.DeepCheckInterval > 0 {
				if extra, err := proc.ReadStatusExtra(pid); err == nil {
					snap.CapEff = extra.CapEff
					snap.Seccomp = extra.Seccomp
					snap.NoNewPrivs = extra.NoNewPrivs
				}
				if ns, err := proc.ReadNamespaces(pid); err == nil {
					snap.NetNS = ns["net"]
				}
			}
			w.known[pid] = snap
			out <- Event{Kind: EventStarted, Time: now, Process: p, Type: string(ptype)}
			continue
		}

		if w.DeepCheckInterval > 0 && now.Sub(existing.lastDeepCheck) >= w.DeepCheckInterval {
			changes := w.detectContextChange(existing, p, now)
			existing.lastDeepCheck = now
			if len(changes) > 0 {
				out <- Event{Kind: EventContextChanged, Time: now, Process: p, Type: string(ptype), Changes: changes}
			}
		}
		existing.Process = *p
	}

	for pid, snap := range w.known {
		if !seen[pid] {
			out <- Event{Kind: EventExited, Time: now, Process: &snap.Process, Type: string(proc.Classify(&snap.Process))}
			delete(w.known, pid)
		}
	}
}

// detectContextChange compares a tracked snapshot against a fresh
// read and returns any security-relevant differences. UID/GID/exe
// changes are cheap (already in Process); capability/namespace/
// seccomp changes require the deep StatusExtra/namespace reads,
// gated by DeepCheckInterval so we don't pay that cost on every
// single 100ms tick for every process.
func (w *Watcher) detectContextChange(old *snapshot, cur *proc.Process, now time.Time) []ContextChange {
	var changes []ContextChange

	if old.UID != cur.UID {
		changes = append(changes, ContextChange{"uid", itoa(old.UID), itoa(cur.UID)})
	}
	if old.GID != cur.GID {
		changes = append(changes, ContextChange{"gid", itoa(old.GID), itoa(cur.GID)})
	}
	if old.Exe != cur.Exe && old.Exe != "" && cur.Exe != "" {
		// exe changing under a stable PID is unusual (execve into a
		// new binary keeps the PID) — worth flagging even though the
		// common case is both sides being equal.
		changes = append(changes, ContextChange{"exe", old.Exe, cur.Exe})
	}

	if extra, err := proc.ReadStatusExtra(cur.PID); err == nil {
		if extra.CapEff != old.CapEff {
			changes = append(changes, ContextChange{
				"cap_eff",
				capHex(old.CapEff),
				capHex(extra.CapEff),
			})
			old.CapEff = extra.CapEff
		}
		if extra.Seccomp != old.Seccomp {
			changes = append(changes, ContextChange{"seccomp", seccompModeName(old.Seccomp), seccompModeName(extra.Seccomp)})
			old.Seccomp = extra.Seccomp
		}
		if extra.NoNewPrivs != old.NoNewPrivs {
			changes = append(changes, ContextChange{"no_new_privs", boolStr(old.NoNewPrivs), boolStr(extra.NoNewPrivs)})
			old.NoNewPrivs = extra.NoNewPrivs
		}
	}

	if ns, err := proc.ReadNamespaces(cur.PID); err == nil {
		if netns := ns["net"]; netns != 0 && old.NetNS != 0 && netns != old.NetNS {
			changes = append(changes, ContextChange{"netns", itoa64(old.NetNS), itoa64(netns)})
		}
		if netns := ns["net"]; netns != 0 {
			old.NetNS = netns
		}
	}

	return changes
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func seccompModeName(mode int) string {
	switch mode {
	case 0:
		return "disabled"
	case 1:
		return "strict"
	case 2:
		return "filter"
	default:
		return "unknown"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func itoa64(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func capHex(mask uint64) string {
	const hexDigits = "0123456789abcdef"
	if mask == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for mask > 0 {
		i--
		buf[i] = hexDigits[mask&0xf]
		mask >>= 4
	}
	return string(buf[i:])
}
