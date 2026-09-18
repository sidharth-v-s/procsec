# procsec

**A Linux `/proc`-based process security explorer.**

`procsec` walks the `/proc` pseudo-filesystem and turns it into a security-focused view of what's actually running on a box: who owns each process, what capabilities and hardening it has (or doesn't), what its memory looks like, what it has open, and what changes about it over time.

It's inspired by [pspy](https://github.com/DominicBreuker/pspy) — the classic no-root process-monitoring tool for CTFs and pentests — but broader in scope:

> **pspy:** watch process creation/execution without needing root.
> **procsec:** watch processes *and* build a full security profile of each one — capabilities, seccomp, LSM confinement, memory permissions, namespaces, cgroups — using only `/proc` and related Linux interfaces.

Built for red teaming / CTF / Linux privilege-escalation work: fast triage of "what's running on this box and what's worth looking at first," without needing root, a package manager, or internet access on the target.

---

## Table of contents

- [Why this exists](#why-this-exists)
- [What it is *not*](#what-it-is-not)
- [Features](#features)
- [Installation](#installation)
  - [Static binary (recommended — for CTF/offline targets)](#static-binary-recommended--for-ctfoffline-targets)
  - [Build from source](#build-from-source)
- [Command reference](#command-reference)
- [Colored output](#colored-output)
- [Risk scoring — how it works](#risk-scoring--how-it-works)
- [JSON output](#json-output)
- [Snapshot / baseline diffing](#snapshot--baseline-diffing)
- [Architecture](#architecture)
- [Design principles](#design-principles)
- [Known limitations](#known-limitations)
- [Roadmap](#roadmap)
- [License](#license)

---

## Why this exists

On a CTF box or during a pentest, the honest process-inspection workflow is usually:

```
ps aux
cat /proc/<pid>/status
cat /proc/<pid>/maps
cat /proc/<pid>/environ | tr '\0' '\n'
getcap -r / 2>/dev/null
```

...repeated by hand, for every process that looks interesting, with no consistent format and no way to tell at a glance which of the 80 processes on the box actually deserve a second look.

`procsec` collapses that into one static binary that:
- reads every `/proc/<pid>/*` file relevant to security (not just `status` and `cmdline`)
- decodes the things that are normally opaque hex/bitmasks (capability bitmasks → `cap_sys_admin` etc., namespace inodes, seccomp mode)
- flags the signals that actually matter for privesc/persistence hunting (RWX memory, full capability sets, missing `no_new_privs`, anonymous executable mappings, sensitive-looking env var names)
- gives you a heuristic, *explainable* risk score to sort by, so you know where to point your attention first on a box with hundreds of processes

## What it is *not*

Scope is deliberately narrow. `procsec` is **not**:

- a vulnerability scanner
- an automated exploitation / privilege-escalation framework
- an EDR or intrusion detection system
- a credential dumper

It surfaces information. It does not decide anything for you or take any action beyond reading `/proc`. This is intentional — see [Design principles](#design-principles).

---

## Features

| Area | What it does |
|---|---|
| **Process enumeration** | Full `/proc` walk, tolerant of processes vanishing mid-scan (expected and constant on a live system) |
| **Capability decoding** | All 41 known Linux capability bits decoded from the raw hex bitmask in `status` (`CapEff`/`CapPrm`/`CapBnd`) into `cap_*` names, with a "notable" subset highlighted for privesc relevance |
| **Seccomp / hardening** | `no_new_privs`, seccomp mode (disabled/strict/filter) |
| **LSM confinement** | Best-effort AppArmor/SELinux detection from `/proc/<pid>/attr/current`, plus system-wide active-LSM listing from `/sys/kernel/security/lsm` |
| **Memory mapping analysis** | Full `maps` table plus an aggregated `smaps` summary; flags RWX (writable+executable) regions and anonymous executable memory (common shellcode/injection signal) |
| **File descriptors** | Classified by kind (socket/pipe/regular/device), with resolved symlink targets |
| **Environment variables** | Read via `/proc/<pid>/environ`; keys matching secret-like patterns (`*_TOKEN`, `*PASSWORD*`, `AWS_*`, etc.) are masked by default — `--reveal` opts in explicitly. Sensitivity is judged by **key name only**, values are never inspected to decide masking |
| **Namespaces** | Full namespace inode table per process, or a diff between two PIDs (useful for spotting container escapes / unexpected namespace sharing) |
| **Cgroups** | v1 (multi-controller) and v2 (unified hierarchy) aware |
| **Process ancestry** | Tree view (`tree`), or a direct ancestor chain for one PID (`inspect`) — spot a shell spawned by an unexpected parent (e.g. a web server spawning `bash`) |
| **Live monitoring** | `watch` polls `/proc` (default 100ms) and reports process start/exit, pspy-style — plus **security-context-change detection**: a still-running PID whose UID, GID, exe, or effective capabilities change mid-life is flagged, which start/exit-only tools like pspy don't catch |
| **Live dashboard** | `top` — auto-refreshing, security-focused (not CPU/mem-focused): process/root/zombie counts, top 10 processes by risk score |
| **Risk scoring** | Explainable 0–100 heuristic per process from capabilities, hardening, and memory signals — every point traces to a printed reason, never a black box |
| **Snapshot / diff** | Save a process baseline, compare live state against it later — keyed on `(name, exe, uid)` so it survives reboots (PIDs don't) |
| **Filtering** | `ps --user/--name/--state`, plus `zombies`/`root` shortcuts |
| **Colored output** | Auto-detects TTY, respects `NO_COLOR` and `--no-color`, never pollutes piped/scripted output |
| **JSON output** | `--json` on every command that has structured output worth scripting against |

---

## Installation

### Static binary (recommended — for CTF/offline targets)

If your target box has no internet access (the normal CTF situation), build the binary **on your attack box first**, then transfer it over — `scp`, a web server one-liner, whatever you've already got.

The critical flag is `CGO_ENABLED=0`. Go binaries are statically linked by default *only* when cgo is disabled. Some environments will silently produce a **dynamically-linked** binary if cgo auto-enables itself — which happens here because Go's standard `os/user` package calls into glibc's NSS via cgo when it's available, for `/etc/passwd` lookups. A dynamically linked binary depends on the target having a compatible glibc, dynamic linker, and NSS setup — exactly the kind of thing you can't assume on a CTF box. `CGO_ENABLED=0` forces Go's pure-Go fallback for those lookups and produces a binary with zero runtime dependencies.

```bash
git clone https://github.com/sidharth-v-s/procsec.git
cd procsec

CGO_ENABLED=0 go build -o procsec ./cmd/procsec
```

Verify it's actually static before you rely on it:

```bash
file procsec
# procsec: ELF 64-bit LSB executable, x86-64, ..., statically linked, ...
#                                                     ^^^^^^^^^^^^^^^^^ this is what you want

ldd procsec
# not a dynamic executable      <- also confirms it
```

If `file` says `dynamically linked` instead, `CGO_ENABLED=0` wasn't picked up — double check the env var is actually set for that build invocation (some shells/CI configs silently drop it).

**Optional: smaller binary.** Strip debug symbols to cut the size roughly in half — not required, just convenient when you're moving the binary over a slow reverse shell or a constrained transfer channel:

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o procsec ./cmd/procsec
```

**Cross-compiling** for a target of a different architecture (e.g. building on an x86_64 attack box for an ARM target) — Go cross-compiles natively, no toolchain gymnastics required:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o procsec-arm64 ./cmd/procsec
CGO_ENABLED=0 GOOS=linux GOARCH=386   go build -o procsec-386   ./cmd/procsec
```

Once you have the binary, getting it onto the target is the usual toolbox — `scp`, `curl`/`wget` from a python `http.server` on your attack box, `base64` through a shell if that's all you've got. Once it's there:

```bash
chmod +x procsec
./procsec ps
```

No install step, no config file, no package manager, no libraries to satisfy. That's the whole point.

### Build from source

Same command as above, without needing `CGO_ENABLED=0` if you're just running it locally on your own dev machine and don't care about portability:

```bash
go build -o procsec ./cmd/procsec
```

Requires Go 1.22+. No external Go modules — the entire project is standard library only (see [Design principles](#design-principles) for why that's a deliberate choice, not an oversight).

---

## Command reference

```
procsec ps [--json] [--risk] [--user U] [--name S] [--state Z]
```
List all processes. `--risk` adds a heuristic risk score column. `--user`/`--name`/`--state` filter (AND semantics across all three). `--name` matches against both the process name and its full cmdline, case-insensitive.

```
procsec inspect <PID> [--json]
```
The combined detail view for one process: security profile (capabilities, hardening, LSM, memory summary), ancestry chain, namespaces, cgroup membership. This is usually where you end up after `ps --risk` points you at something.

```
procsec tree
```
ASCII process ancestry tree, root-owned processes highlighted.

```
procsec top
```
Live-refreshing security dashboard. Process/root/zombie counts plus the top 10 processes by risk score, redrawn in place every second. `Ctrl+C` to exit.

```
procsec watch [--no-context] [--baseline FILE]
```
Live process monitor, pspy-style: reports every process start and exit as it happens (100ms poll interval by default). Also detects **security-context changes** on still-running PIDs — a UID/GID/exe/capability change on a process that doesn't exit and restart — gated behind a 2-second-per-PID deep-check interval so it doesn't re-read capability data on every single poll tick for every process. `--no-context` disables context-change detection entirely, for pure start/exit watching. `--baseline FILE` compares current state against a saved snapshot before entering the live loop (see [Snapshot / baseline diffing](#snapshot--baseline-diffing)).

```
procsec maps <PID>
```
Full memory mapping table plus an `smaps`-derived summary (RSS, PSS, anonymous/locked memory). RWX mappings are flagged in bold red; anonymous executable mappings in yellow.

```
procsec fds <PID>
```
File descriptor table, classified by kind (socket/pipe/regular/device), with resolved targets.

```
procsec environ <PID> [--reveal]
```
Environment variables. Keys matching secret-like naming patterns are masked by default; pass `--reveal` to see values.

```
procsec ns <PID> [PID2]
```
Namespace inode table for one PID, or a shared/differing comparison between two PIDs.

```
procsec cgroup <PID>
```
Cgroup membership — handles both v1 (per-controller lines) and v2 (unified hierarchy) transparently.

```
procsec caps <PID>
```
Just the capability decode (effective/permitted/bounding), without the rest of the security profile — useful when you specifically want capabilities and nothing else.

```
procsec security <PID> [--json]
```
The combined security profile alone (a subset of `inspect` — no ancestry/namespaces/cgroup, just capabilities + hardening + memory + sensitive env flags).

```
procsec system [--json]
```
System-wide summary: total process count, active LSMs (from `/sys/kernel/security/lsm`, if readable).

```
procsec zombies
```
Shortcut for processes in state `Z` (defunct). Zombies are a persistence/reaping-bug signal worth a dedicated one-liner.

```
procsec root [--risk]
```
Shortcut for everything running as UID 0.

```
procsec snapshot <file>
```
Save the current process state to a file for later comparison. See [Snapshot / baseline diffing](#snapshot--baseline-diffing).

```
procsec diff <file>
```
One-shot comparison of live state against a saved snapshot.

**Global flag**, valid on every command: `--no-color` — disable colored output. Also respected automatically via the `NO_COLOR` environment variable, and auto-disabled whenever stdout isn't a terminal (piped into `grep`, redirected to a file, etc.) — matching how `ls`, `grep`, and most other color-capable CLI tools behave, so scripted/piped usage never has to worry about stray ANSI codes.

---

## Colored output

Palette is consistent across every command:

- **Red** — root-owned (UID 0), missing hardening, danger signals (RWX memory, full capability sets)
- **Yellow** — caution / anomalous but not necessarily dangerous (anonymous executable memory, differing namespaces)
- **Green** — confirmed-present hardening (seccomp active, LSM confined, `no_new_privs` set)
- **Gray** — informational / anonymous / dimmed secondary text

Color is on by default when connected to a real terminal, off automatically when piped or redirected, and can be forced off with `--no-color` or the `NO_COLOR` environment variable.

---

## Risk scoring — how it works

Every process gets an additive 0–100 score built purely from signals `procsec` already reads — nothing external, nothing ML-derived, nothing opaque:

| Signal | Points |
|---|---|
| Running as root | +10 |
| Full capability set (nothing dropped) | +20 |
| Holds high-impact capabilities (`cap_setuid`, `cap_sys_admin`, `cap_sys_ptrace`, etc.) | up to +20 |
| `no_new_privs` not set | +5 |
| No seccomp filtering | +5 |
| No LSM confinement detected | +5 |
| Writable+executable (RWX) memory present | +20 |
| Anonymous executable memory present | +15 |
| Sensitive-looking environment variable names present | +5 |

Every score comes with the list of reasons that produced it, printed alongside — `ps --risk`, `root --risk`, `inspect`, `security`, and `top` all show the reasoning, not just the number. This is a **triage aid**, not a verdict: it tells you where to look first on a box with hundreds of processes, not whether something is actually exploitable. That judgment is still yours — see [What it is *not*](#what-it-is-not).

---

## JSON output

Every command that produces structured data supports `--json` for scripting/piping into `jq` or other tooling: `ps`, `inspect`, `security`, `system`. Output is indented, stable-keyed JSON — safe to diff or feed into other tools in an automated recon pipeline.

```bash
procsec ps --json | jq '.[] | select(.uid == 0) | .name'
procsec security 1337 --json | jq '.capabilities_of_interest'
```

---

## Snapshot / baseline diffing

`procsec snapshot` and `procsec diff` let you compare the live system against a known state — e.g. right after you've enumerated a freshly compromised box, to catch anything that spawns afterward without babysitting `watch` the whole time.

Snapshots are keyed on **`(process name, exe path, UID)`**, deliberately *not* PID — PIDs are meaningless across a reboot or even just process churn, so a snapshot taken today is still meaningful next week.

```bash
procsec snapshot baseline.json
# ... time passes, or you come back after establishing persistence checks ...
procsec diff baseline.json
```

```
! 2 new process type(s) not in baseline:
    + sleep (uid=0) /usr/bin/sleep
    + nc (uid=1000) /usr/bin/nc
1 baseline process type(s) no longer running:
    - kworker/0:1-virtio_vsock (uid=0)
```

You can also feed a baseline directly into `watch` to get the diff up front before the live monitor starts:

```bash
procsec watch --baseline baseline.json
```

---

## Architecture

```
cmd/procsec/    CLI entrypoint and command dispatch — the only package that
                knows about os.Args, flags, and stdout/stderr directly

proc/           /proc readers — pure data layer, no output formatting,
                no color, no knowledge of the CLI
  process.go      PID enumeration, core Process struct
  status.go       /proc/<pid>/status parser (core fields + StatusExtra)
  maps.go         /proc/<pid>/maps parser + mapping classification
  smaps.go        /proc/<pid>/smaps aggregation
  fd.go           /proc/<pid>/fd enumeration + classification
  environ.go      /proc/<pid>/environ parser + sensitive-key detection
  namespace.go    /proc/<pid>/ns/* reader + namespace comparison
  cgroup.go       /proc/<pid>/cgroup parser (v1 + v2)
  tree.go         process forest / ancestry chain builder
  filter.go       ps filtering (--user/--name/--state)
  snapshot.go     baseline save/load/diff

security/       security-domain logic — capability decoding, LSM
                heuristics, risk scoring. Depends on nothing but stdlib.
  capabilities.go   bitmask -> cap_* name decoding (all 41 known bits)
  seccomp.go        seccomp mode -> human string
  lsm.go            AppArmor/SELinux heuristic detection
  risk.go           explainable additive risk scoring

monitor/        live observation — poll-based watcher
  watch.go        process lifecycle + security-context-change detection

output/         rendering — the only package that emits ANSI codes or
                talks to a terminal
  color.go        ANSI helpers, NO_COLOR/--no-color handling
  tty.go          TTY detection (hand-rolled ioctl, no external deps)
  table.go        ps-style table rendering
  print.go        tree/maps/fds/environ/ns/cgroup/watch-event rendering
  security_print.go  the combined security profile view + risk badge
  json.go         --json serialization for every structured command
```

Dependency direction is strictly one-way: `proc` and `security` know nothing about `output` or `cmd`; `output` depends on `proc`/`security` for types but never the reverse. This keeps the data layer testable and reusable independent of how (or whether) it's ever printed to a terminal.

---

## Design principles

**No external dependencies.** The entire project is Go standard library only — including a hand-rolled terminal-detection function (`output/tty.go`) using a raw `ioctl` syscall instead of pulling in `golang.org/x/term`. Combined with `CGO_ENABLED=0`, this is what makes the "one static binary, no internet needed on target" story actually true rather than aspirational.

**Tolerant of a live, changing `/proc`.** Processes can and do disappear between listing `/proc` and reading a specific PID's files — that's the normal steady state of a running system, not an edge case. Every reader in this project treats a vanished process as an expected, silently-skipped outcome rather than a fatal error. Same for permission errors on other users' processes: `procsec` degrades to partial information rather than crashing or refusing to run without root.

**Flag, don't dump.** Sensitive-looking data (environment variable values that look like secrets) is identified and flagged by name pattern, but never displayed by default — you have to explicitly ask with `--reveal`. The tool tells you *where* to look, not everything it can see.

**Explainable over clever.** The risk score is a simple additive sum of named, printed reasons — not a trained model, not a hidden formula. You should always be able to see exactly why a process scored what it scored.

**Visibility, not automation.** `procsec` reads `/proc` and tells you what it finds. It doesn't exploit anything, doesn't chain findings into an attack path, and doesn't make decisions on your behalf. See [What it is *not*](#what-it-is-not).

---

## Known limitations

- **No eBPF/netlink.** `watch` is purely poll-based (default 100ms interval). This is a deliberate simplicity/portability tradeoff — eBPF requires kernel support and elevated privileges that aren't guaranteed on a CTF box, whereas polling `/proc` works everywhere, unprivileged, out of the box. A sufficiently fast process (spawns and exits well under 100ms) can theoretically be missed, though in practice this interval catches the overwhelming majority of short-lived processes.
- **LSM detection is a heuristic.** There is no single portable Linux API to ask "which LSM confines this specific PID" — `procsec` infers AppArmor vs SELinux from the shape of `/proc/<pid>/attr/current`, which is reliable in practice but not authoritative.
- **Risk scoring is a triage aid, not a verdict.** It tells you where to look first, not whether something is actually exploitable. See [Risk scoring](#risk-scoring--how-it-works) and [What it is *not*](#what-it-is-not).
- **No network socket correlation yet.** `fds` classifies socket file descriptors but doesn't currently cross-reference them against `/proc/net/tcp`/`udp` to show which port/connection a given fd corresponds to. On the roadmap.
- **No automated test suite yet.** The project has been verified through extensive manual testing against a live `/proc`, but doesn't yet have `_test.go` coverage for the parsers. Also on the roadmap.

---

## Roadmap

- [ ] Network socket correlation (`/proc/net/tcp[6]`/`udp[6]` inode cross-referencing with `fds`)
- [ ] Test suite for the `proc/` parsers
- [ ] Shell completion (bash/zsh)
- [ ] Risk-score threshold filter on `watch` (`--min-risk N`) to cut noise on busy systems
- [ ] Seccomp filter disassembly (beyond just mode detection)

---

## License

MIT — see [LICENSE](LICENSE).

## Author

Built by [sidharth-v-s](https://github.com/sidharth-v-s) as a Linux internals / offensive-security learning project — part of ongoing red team skill development.
