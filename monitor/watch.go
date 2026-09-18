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

	// Populated only for EventContextChanged: what changed and how.
	Changes []ContextChange
}

// ContextChange describes a single security-relevant field that
// changed for a still-running PID between two polls — e.g. a process
// that started as UID 1000 and is now UID 0 (a privilege escalation
// in progress), or one whose capability set grew.
type ContextChange struct {
	Field string // "uid", "gid", "cap_eff", "exe", "seccomp"
	Old   string
	New   string
}

// snapshot is the internal per-PID state a Watcher tracks between
// polls, holding just enough to detect the changes we care about
// without re-reading full StatusExtra on every single poll for every
// PID (only diffed when something cheap already looks different, or
// periodically — see Watcher.deepCheckEvery).
type snapshot struct {
	proc.Process
	CapEff        uint64
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
// emits Started/Exited/ContextChanged events accordingly.
func (w *Watcher) poll(out chan<- Event) {
	pids, err := proc.ListPIDs()
	if err != nil {
		return // transient /proc read failure; try again next tick
	}

	now := time.Now()
	seen := make(map[int]bool, len(pids))

	for _, pid := range pids {
		seen[pid] = true

		p, err := proc.ReadProcess(pid)
		if err != nil {
			continue // exited between ListPIDs and ReadProcess — next poll's Exited handles bookkeeping
		}

		existing, known := w.known[pid]
		if !known {
			snap := &snapshot{Process: *p, lastDeepCheck: now}
			if w.DeepCheckInterval > 0 {
				if extra, err := proc.ReadStatusExtra(pid); err == nil {
					snap.CapEff = extra.CapEff
				}
			}
			w.known[pid] = snap
			out <- Event{Kind: EventStarted, Time: now, Process: p}
			continue
		}

		if w.DeepCheckInterval > 0 && now.Sub(existing.lastDeepCheck) >= w.DeepCheckInterval {
			changes := w.detectContextChange(existing, p, now)
			existing.lastDeepCheck = now
			if len(changes) > 0 {
				out <- Event{Kind: EventContextChanged, Time: now, Process: p, Changes: changes}
			}
		}
		existing.Process = *p
	}

	for pid, snap := range w.known {
		if !seen[pid] {
			out <- Event{Kind: EventExited, Time: now, Process: &snap.Process}
			delete(w.known, pid)
		}
	}
}

// detectContextChange compares a tracked snapshot against a fresh
// read and returns any security-relevant differences. UID/GID/exe
// changes are cheap (already in Process); capability changes require
// the deep StatusExtra read, gated by DeepCheckInterval so we don't
// pay that cost on every single 100ms tick for every process.
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
	}

	return changes
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
