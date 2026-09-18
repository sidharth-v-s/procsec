# procsec

A Linux /proc-based process security explorer, inspired by pspy but
broader in scope. Colored terminal output, heuristic risk scoring,
live dashboards, and snapshot/baseline diffing on top of the core
/proc introspection. See procsec_outline.md for the original design doc.

## Commands

    procsec ps [--json] [--risk] [--user U] [--name S] [--state Z]
    procsec inspect <PID> [--json]
    procsec tree
    procsec top                          live security-focused dashboard
    procsec watch [--no-context] [--baseline FILE]
    procsec maps <PID>
    procsec fds <PID>
    procsec environ <PID> [--reveal]
    procsec ns <PID> [PID2]
    procsec cgroup <PID>
    procsec caps <PID>
    procsec security <PID> [--json]
    procsec system [--json]
    procsec zombies                      shortcut: Filter{State: Z}
    procsec root [--risk]                shortcut: Filter{UID: 0}
    procsec snapshot <file>              save process state for later diffing
    procsec diff <file>                  compare live state against a snapshot

Global: --no-color (also respects NO_COLOR env var). Color auto-disables
when stdout isn't a terminal (piped/redirected), same as ls/grep.

## Architecture

    proc/       — /proc readers: process, status, maps, smaps, fd, environ,
                  namespace, cgroup, tree, filter, snapshot
    security/   — capabilities, seccomp, lsm, risk (heuristic scoring)
    monitor/    — watch.go (poll-based lifecycle + context-change detection)
    output/     — color.go, tty.go, table.go, print.go, json.go, security_print.go
    cmd/procsec — CLI entrypoint/dispatch

## Build

    go build -o procsec ./cmd/procsec

No external dependencies — stdlib only, including a hand-rolled TTY
check (output/tty.go) instead of golang.org/x/term, keeping this a
single static binary with nothing to vendor.

## New in this pass

- **Color**: every command respects a consistent palette — red for
  root/danger, yellow for caution, green for confirmed-hardened,
  gray for informational/anonymous. Auto-detects TTY, respects
  NO_COLOR and --no-color.
- **Risk scoring** (security/risk.go): explainable 0-100 heuristic
  from capabilities/hardening/memory signals already collected.
  Every point traces to a human-readable reason — not a black box.
  `ps --risk`, `root --risk`, and `top` all use it.
- **`procsec top`**: live-refreshing security dashboard — process/root/
  zombie counts plus the top 10 riskiest processes, redrawn in place.
- **Filters**: `ps --user/--name/--state`, plus `zombies`/`root` shortcuts.
- **Snapshot/diff**: `procsec snapshot` saves process state keyed on
  (name, exe, uid) — stable across reboots, unlike PID. `procsec diff`
  and `watch --baseline` compare live state against it, surfacing
  what's new or missing since the snapshot was taken.
- Memory-mapping visual bar in `inspect`/`security` output (red =
  anonymous+executable, blue = file-backed, gray = other anonymous).

## Known scope gaps (unchanged from before, still honest about them)

- No eBPF/netlink — pure polling, per the design doc's scope choice.
- LSM module detection is a heuristic (no portable "which LSM" API).
- Risk scoring is a triage aid, not a vulnerability verdict — this
  is still explicitly not a vuln scanner (see design doc non-goals).
