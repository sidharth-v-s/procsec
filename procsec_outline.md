# procsec — Linux `/proc` Security Explorer

## 1. Project Overview

**procsec** is a Linux process and security-introspection tool built around the `/proc` pseudo-filesystem.

The project is inspired by the process-monitoring concept of tools such as **pspy**, but the goal is broader:

> **pspy:** primarily monitor process activity without requiring root.  
> **procsec:** monitor processes and build a detailed security profile of running processes using `/proc` and related Linux interfaces.

The project should focus on **manual investigation and visibility**, not automated pentesting or exploitation.

---

## 2. Main Goals

- Understand Linux `/proc` deeply.
- Understand Linux process internals.
- Monitor process creation and termination.
- Inspect security-relevant process metadata.
- Analyze process memory mappings.
- Inspect file descriptors.
- Understand Linux namespaces.
- Understand cgroups.
- Inspect capabilities.
- Inspect seccomp state.
- Inspect LSM/security context information.
- Correlate process ancestry and security-context changes.
- Produce useful CLI output for pentesting and Linux privilege-escalation work.
- Keep the tool focused instead of turning it into a generic pentesting framework.

---

## 3. Core Concept

```text
                         /proc
                           |
             +-------------+-------------+
             |             |             |
          /proc/PID      /proc/sys    /proc/net
             |
      +------+-------+----------+-----------+
      |      |       |          |           |
    status  maps    fd/     environ       ns/
      |      |       |          |           |
      +------+-------+----------+-----------+
                     |
                     v
             Security Analysis
                     |
        +------------+------------+
        |            |            |
    Identity     Isolation      Memory
        |            |            |
     UID/GID     namespaces     mappings
     Groups      cgroups        permissions
     Caps        seccomp        RWX/RX
```

---

# 4. Major Components

## 4.1 Process Enumeration

Read `/proc` and identify numeric PID directories.

For every process, collect:

- PID
- PPID
- process name
- executable
- command line
- UID
- GID
- state
- thread count

Example:

```text
PID    USER    NAME       STATE    EXE
1      root    systemd    S        /usr/lib/systemd/systemd
812    root    sshd       S        /usr/bin/sshd
1337   zoro    bash       S        /usr/bin/bash
1421   root    backup.sh  R        /opt/backup.sh
```

Potential command:

```bash
procsec ps
```

---

# 5. Process Inspection

Command:

```bash
procsec inspect <PID>
```

The inspection view should combine information from multiple `/proc/PID/*` files.

Example conceptual output:

```text
Process: backup.sh
PID:     1421
PPID:    1337
UID:     0
GID:     0

Executable
----------
/opt/backup.sh

Command line
------------
/opt/backup.sh /home/user

Environment
-----------
PATH=/usr/local/bin:/usr/bin
HOME=/root

Memory
------
Mappings: 37
Executable regions: 4
Writable regions: 8

File descriptors
----------------
0 -> /dev/null
1 -> /tmp/backup.log
2 -> /tmp/backup.err

Namespaces
----------
PID: 4026531836
NET: 4026531840
MNT: 4026531841

Capabilities
------------
Effective: ...
```

---

# 6. `/proc/PID/status`

Parse `/proc/PID/status`.

Important fields:

- `Name`
- `State`
- `Pid`
- `PPid`
- `Uid`
- `Gid`
- `Groups`
- `Threads`
- `VmSize`
- `VmRSS`
- `VmPeak`
- `CapInh`
- `CapPrm`
- `CapEff`
- `CapBnd`
- `NoNewPrivs`
- `Seccomp`

Security-relevant example:

```text
Uid:        0
CapEff:     ...
NoNewPrivs: 0
Seccomp:    0
```

---

# 7. Executable Analysis

Inspect:

```text
/proc/PID/exe
```

Resolve the executable path.

Compare it with:

```text
/proc/PID/cmdline
/proc/PID/comm
```

This allows procsec to distinguish:

- actual executable
- process name
- command-line arguments

---

# 8. Command-Line Analysis

Inspect:

```text
/proc/PID/cmdline
```

Parse the null-separated argument vector.

Example:

```text
/usr/bin/python3
script.py
--config
/etc/app/config.yml
```

This should be available through:

```bash
procsec inspect <PID>
```

or optionally:

```bash
procsec cmdline <PID>
```

---

# 9. Environment Analysis

Inspect:

```text
/proc/PID/environ
```

Parse environment variables.

Potentially interesting variables:

```text
AWS_*
*_TOKEN
*_KEY
PASSWORD
SECRET
API_KEY
```

Do **not** dump potentially sensitive values by default.

Possible interface:

```bash
procsec environ <PID>
```

or:

```bash
procsec inspect <PID> --environment
```

Possible output:

```text
Environment readable: YES

Potential sensitive variables:
  API_KEY
  SECRET
```

The default behavior should avoid unnecessarily exposing secrets.

---

# 10. File Descriptor Analysis

Inspect:

```text
/proc/PID/fd/
```

Resolve symbolic links and classify descriptors.

Possible categories:

- STDIN
- STDOUT
- STDERR
- regular file
- socket
- pipe
- device
- other

Example:

```text
0 -> /dev/pts/2
1 -> /dev/pts/2
2 -> /dev/pts/2
3 -> /var/log/app.log
4 -> socket:[123456]
5 -> /tmp/data.db
```

Summary:

```text
Regular files: 3
Sockets:       2
Pipes:         1
Devices:       1
```

Command:

```bash
procsec fds <PID>
```

---

# 11. Memory Map Analysis

Inspect:

```text
/proc/PID/maps
```

Parse:

- start address
- end address
- permissions
- file offset
- device
- inode
- mapped path

Example:

```text
7f2a10000000-7f2a10200000 r-xp ... /usr/lib/libc.so.6
7f2a10200000-7f2a10400000 ---p ...
7f2a10400000-7f2a10410000 rw-p ...
```

Classify mappings as:

- executable
- writable
- shared
- private
- anonymous
- file-backed

Security-focused indicators:

```text
RWX mappings
Executable anonymous mappings
Writable executable regions
```

Command:

```bash
procsec maps <PID>
```

---

# 12. `/proc/PID/smaps`

Go deeper than `maps`.

Inspect:

- RSS
- PSS
- private memory
- shared memory
- anonymous memory
- huge pages
- locked memory

Possible summary:

```text
Memory Security
---------------

Executable anonymous memory: 128 KB
RWX memory:                   0 KB
Private executable memory:  1.2 MB
Shared libraries:           14.8 MB
```

This provides a binary/process-security angle without attempting exploitation.

---

# 13. Namespace Analysis

Inspect:

```text
/proc/PID/ns/
```

Relevant namespaces:

```text
cgroup
ipc
mnt
net
pid
pid_for_children
time
user
uts
```

Each namespace can be represented by its inode/identifier.

Example:

```text
Process A
---------
PID NS: 4026531836
NET NS: 4026531840
MNT NS: 4026531841

Process B
---------
PID NS: 4026531836
NET NS: 4026531840
MNT NS: 4026532910
```

Then show shared and differing namespaces:

```text
A and B share:
  PID
  NET

A and B differ:
  MNT
```

Command:

```bash
procsec ns <PID>
```

This is useful for understanding:

- containers
- isolation
- chroots
- process visibility
- network isolation

Do not treat a single namespace property as definitive proof that a process is inside a container.

---

# 14. Cgroup Analysis

Inspect:

```text
/proc/PID/cgroup
```

Display the cgroups associated with the process.

Example:

```text
CPU:     user.slice
Memory:  user.slice
PIDs:    user.slice
```

Command:

```bash
procsec cgroup <PID>
```

Combine cgroup information with namespace information to build a process execution-context profile.

---

# 15. Linux Capabilities

Use `/proc/PID/status` capability fields:

```text
CapInh
CapPrm
CapEff
CapBnd
```

Decode capability bitmasks into names.

Examples:

```text
cap_net_raw
cap_net_admin
cap_setuid
cap_dac_override
```

Possible output:

```text
Capabilities
------------

Permitted:
  cap_setuid

Effective:
  cap_setuid

Bounding:
  ...
```

Command:

```bash
procsec caps <PID>
```

This is directly relevant to Linux privilege-escalation analysis.

---

# 16. Seccomp Analysis

Inspect seccomp-related process state.

Relevant information includes:

```text
NoNewPrivs
Seccomp
```

Possible output:

```text
Security Controls
-----------------
NoNewPrivs: true
Seccomp:    filter
```

Command:

```bash
procsec security <PID>
```

Future work could inspect additional seccomp-related interfaces where appropriate.

---

# 17. LSM / Security Context

Inspect:

```text
/proc/PID/attr/
```

Where available, examine security-context information such as:

```text
/proc/PID/attr/current
```

This can expose information related to:

- SELinux
- AppArmor
- other Linux Security Module mechanisms

Example conceptual output:

```text
LSM
---
AppArmor: enforced
Profile:  example-profile
```

The implementation should gracefully handle systems where a particular LSM interface is unavailable.

---

# 18. Process Monitoring — The pspy-Inspired Component

This is the part most directly inspired by pspy.

Monitor `/proc` for process changes.

Concept:

```text
/proc
  |
  +-- scan PID directories
  |
  +-- detect new PID
  |
  +-- inspect process
  |
  +-- generate event
```

Example:

```text
[12:43:01] NEW PROCESS
PID: 1821
PPID: 1337
UID: 0
CMD: /usr/bin/backup.sh

[12:43:01] NEW PROCESS
PID: 1822
PPID: 1821
UID: 0
CMD: /usr/bin/tar ...

[12:43:05] EXIT
PID: 1822
CMD: /usr/bin/tar
```

Command:

```bash
procsec watch
```

Important design goal:

- no root required for normal monitoring where `/proc` permissions allow it
- tolerate processes appearing/disappearing while being inspected
- avoid excessive polling overhead

---

# 19. Process Tree

Build a process ancestry tree using PID/PPID relationships.

Example:

```text
systemd
|
+-- sshd
|   +-- sshd
|       +-- bash
|           +-- sudo
|               +-- backup.sh
|
+-- cron
    +-- backup.sh
        +-- tar
```

Commands:

```bash
procsec tree
```

and:

```bash
procsec tree --pid <PID>
```

This is particularly useful during privilege-escalation investigations.

---

# 20. Security Context Changes

One of the more interesting procsec features.

When monitoring a process, compare its security context with its parent or previous observation.

Example:

```text
Parent
------
UID = 1000
GID = 1000

Child
-----
UID = 0
GID = 0
```

Generate:

```text
SECURITY CONTEXT CHANGE

UID:
  1000 -> 0

GID:
  1000 -> 0

Capabilities:
  changed

NoNewPrivs:
  unchanged
```

This turns simple process monitoring into security-oriented process monitoring.

Potential changes to track:

- UID/GID
- capabilities
- namespaces
- seccomp
- executable
- parent
- command line
- cgroup

---

# 21. Security Profile

Create a combined process-security report.

Example:

```text
+--------------------------------------------------+
|          PROCESS SECURITY PROFILE                |
+--------------------------------------------------+

Process       nginx
PID           1337
Parent        systemd
User          www-data

PRIVILEGES
----------
UID           33
GID           33
Capabilities  0
NoNewPrivs     true
Seccomp        filter

ISOLATION
---------
PID NS        shared
NET NS        isolated
MNT NS        isolated
Cgroup        system.slice

MEMORY
------
Executable    4
Writable      9
Anonymous RX  0
RWX           0

FILES
-----
Regular       14
Sockets        8
Pipes         2

LSM
---
AppArmor      enforced
```

Command:

```bash
procsec inspect <PID> --security
```

This should be one of the project's flagship features.

---

# 22. Proposed CLI

```text
procsec
|
+-- ps
+-- inspect <PID>
+-- tree
+-- watch
+-- maps <PID>
+-- fds <PID>
+-- environ <PID>
+-- ns <PID>
+-- cgroup <PID>
+-- caps <PID>
+-- security <PID>
+-- system
```

Examples:

```bash
procsec ps

procsec inspect 1337

procsec inspect 1337 --security

procsec tree

procsec watch

procsec maps 1337

procsec fds 1337

procsec ns 1337

procsec cgroup 1337

procsec caps 1337

procsec security 1337
```

---

# 23. Output Formats

Human-readable terminal output should be the default.

Also support machine-readable output:

```bash
procsec inspect 1337 --json
```

Potential formats:

- terminal/table
- JSON

JSON makes it possible to integrate procsec into other tooling later without making procsec itself an automated pentesting framework.

---

# 24. Suggested Project Architecture

```text
procsec/
|
+-- cmd/
|   +-- procsec/
|
+-- proc/
|   +-- process.go
|   +-- status.go
|   +-- maps.go
|   +-- smaps.go
|   +-- fd.go
|   +-- environ.go
|   +-- namespace.go
|   +-- cgroup.go
|   +-- filesystem.go
|
+-- security/
|   +-- capabilities.go
|   +-- seccomp.go
|   +-- lsm.go
|   +-- permissions.go
|   +-- profile.go
|
+-- monitor/
|   +-- watcher.go
|   +-- process.go
|   +-- events.go
|   +-- delta.go
|
+-- output/
|   +-- table.go
|   +-- tree.go
|   +-- json.go
|
+-- internal/
|
+-- tests/
|
+-- docs/
|
+-- README.md
|
+-- LICENSE
|
+-- go.mod / Cargo.toml
```

---

# 25. Language Choice

## Go

Advantages:

- fast development
- excellent concurrency support
- easy `/proc` parsing
- easy deployment
- single static binary
- good CLI ecosystem

Good choice for the first implementation.

## Rust

Advantages:

- systems-oriented
- strong memory safety
- excellent fit for Linux internals
- good foundation for future syscall/native integrations
- single binary deployment

Good choice if the project is intended to demonstrate lower-level systems programming.

### Recommendation

Start with **Go** if the goal is to finish a polished tool quickly.

Start with **Rust** if part of the goal is specifically to demonstrate systems programming and Linux internals.

---

# 26. Development Roadmap

## v0.1 — Process Enumeration

Implement:

- `/proc` scanning
- PID discovery
- process names
- UID/GID
- PPID
- executable
- command line

```text
procsec ps
```

---

## v0.2 — Process Monitoring

Implement:

- process creation detection
- process termination detection
- timestamps
- basic event output

```text
procsec watch
```

This is the pspy-like foundation.

---

## v0.3 — Process Inspection

Implement:

- `/proc/PID/status`
- `/proc/PID/exe`
- `/proc/PID/cmdline`
- `/proc/PID/comm`
- `/proc/PID/environ`

```text
procsec inspect <PID>
```

---

## v0.4 — File + Memory Inspection

Implement:

- `/proc/PID/fd`
- `/proc/PID/maps`
- `/proc/PID/smaps`

```text
procsec fds <PID>
procsec maps <PID>
```

Add:

- mapping classification
- RWX detection
- executable anonymous memory detection

---

## v0.5 — Isolation

Implement:

- namespaces
- cgroups
- process execution context

```text
procsec ns <PID>
procsec cgroup <PID>
```

---

## v0.6 — Security Controls

Implement:

- capabilities
- `NoNewPrivs`
- seccomp
- LSM/security context

```text
procsec caps <PID>
procsec security <PID>
```

---

## v0.7 — Process Tree

Implement:

- PPID relationships
- recursive process tree
- process filtering

```text
procsec tree
```

---

## v0.8 — Security Delta

Implement:

- parent/child security-context comparison
- UID/GID changes
- capability changes
- namespace changes
- executable changes

Example:

```text
SECURITY CONTEXT CHANGE
UID: 1000 -> 0
```

---

## v0.9 — Output/API

Implement:

- JSON output
- structured events
- clean terminal UI
- stable internal data model

---

## v1.0 — Complete Security Explorer

Target:

```text
procsec
```

as a complete Linux process-security introspection utility combining:

```text
Enumeration
+
Monitoring
+
Process ancestry
+
Memory
+
File descriptors
+
Namespaces
+
Cgroups
+
Capabilities
+
Seccomp
+
LSM
+
Security-context changes
```

---

# 27. Example End-to-End Workflow

During a Linux pentest, a tester could run:

```bash
procsec watch
```

and observe:

```text
[12:43:01] NEW PROCESS
PID=1821
PPID=1337
UID=0
CMD=/opt/backup.sh
```

Then:

```bash
procsec inspect 1821 --security
```

which could show:

```text
UID:          0
GID:          0
Capabilities: ...
NoNewPrivs:   false
Seccomp:      disabled
Namespaces:   ...
Cgroup:       ...
```

Then:

```bash
procsec tree --pid 1821
```

to understand its ancestry.

Then:

```bash
procsec fds 1821
procsec maps 1821
procsec ns 1821
```

for deeper investigation.

The tool assists the tester's reasoning rather than automatically exploiting anything.

---

# 28. What procsec Is NOT

The project should deliberately avoid becoming:

- a generic vulnerability scanner
- an Nmap replacement
- an automated privilege-escalation framework
- an exploitation framework
- a credential dumping framework
- a generic EDR
- a "run everything" pentesting toolkit

The project should remain focused on:

> **Linux process visibility + `/proc` internals + security context analysis.**

---

# 29. Potential Future Features

After v1.0:

- eBPF-assisted monitoring
- syscall correlation
- `/proc/net` analysis
- socket-to-process correlation
- process network activity
- mount namespace visualization
- container-context visualization
- terminal UI (TUI)
- process filtering
- event export
- SQLite event storage
- process activity timeline
- baseline/diff mode
- remote collection
- plugin architecture

These should remain optional future directions so the initial project stays focused.

---

# 30. Core Design Philosophy

The project should follow these principles:

1. **Understand before automating.**
2. **Use Linux primitives directly where practical.**
3. **Make `/proc` the primary source of truth.**
4. **Keep security analysis explainable.**
5. **Avoid unnecessary exploitation functionality.**
6. **Prefer useful raw information over opaque "risk scores."**
7. **Handle permission errors gracefully.**
8. **Assume processes can disappear at any time.**
9. **Minimize sensitive data exposure.**
10. **Keep the project modular so future Linux security research features can be added cleanly.**

---

# 31. One-Line Project Description

> **procsec is a Linux process-security explorer that uses `/proc` and related kernel interfaces to monitor processes, inspect execution context, analyze memory and file descriptors, examine namespaces and capabilities, and identify security-context changes.**

---

# 32. Short README Pitch

```text
procsec
=======

A Linux /proc-based process security explorer inspired by
the process-monitoring capabilities of pspy.

Instead of only showing which processes are running,
procsec builds a deeper security profile around each process:

- identity and privileges
- command line and environment
- file descriptors
- memory mappings
- namespaces
- cgroups
- capabilities
- seccomp
- LSM/security context
- process ancestry
- security-context changes

Built for learning Linux internals and assisting manual
Linux privilege-escalation and red-team investigations.

procsec is intentionally not a generic automated pentesting
framework.
```
