package output

import (
	"fmt"
	"io"
	"strings"

	"procsec/proc"
	"procsec/security"
)

// PrintSecurityProfile renders a SecurityProfile as a human-readable,
// colorized report: green checkmarks for hardening that's present,
// red bangs for concerning signals, and an overall risk score banner
// at the top so the operator's eye lands on the verdict first.
// Reasons are always shown (design doc: never a black box) rather
// than gated behind a separate --explain flag.
func PrintSecurityProfile(w io.Writer, sp SecurityProfile) {
	p := sp.Process
	rs := sp.Risk

	fmt.Fprintf(w, "%s %s  %s  %s\n", Bold(fmt.Sprintf("PID %d", p.PID)), Dim("("+p.Name+")"), Dim(fmt.Sprintf("ppid=%d", p.PPID)), Dim("type="+p.Type))
	printRiskLine(w, rs)
	fmt.Fprintf(w, "  exe:     %s\n", orDash(p.Exe))
	fmt.Fprintf(w, "  cmdline: %s\n", FormatCmdline(p.Name, p.Cmdline))
	uidStr := fmt.Sprintf("uid=%d gid=%d", p.UID, p.GID)
	if p.UID == 0 {
		uidStr = Red(uidStr)
	}
	fmt.Fprint(w, "  "+uidStr)
	if len(sp.Groups) > 0 {
		fmt.Fprintf(w, " groups=%s", joinInts(sp.Groups))
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "\n  "+Bold("Capabilities:"))
	fmt.Fprintf(w, "    effective:  %s\n", joinOrNone(sp.CapEff))
	if len(sp.InterestingCap) > 0 {
		fmt.Fprintln(w, "    "+Warn("notable: "+strings.Join(sp.InterestingCap, ", ")))
	}
	if sp.FullCapSet {
		fmt.Fprintln(w, "    "+Warn("full capability set present (no capabilities dropped)"))
	}
	fmt.Fprintf(w, "    bounding:   %s\n", joinOrNone(sp.CapBnd))

	fmt.Fprintln(w, "\n  "+Bold("Hardening:"))
	printHardeningLine(w, "no_new_privs", sp.NoNewPrivs)
	if sp.Seccomp != "disabled" {
		fmt.Fprintln(w, "    "+Ok("seccomp: "+sp.Seccomp))
	} else {
		fmt.Fprintln(w, "    "+Warn("seccomp: disabled"))
	}
	if sp.LSM.Module != "" {
		fmt.Fprintln(w, "    "+Ok(fmt.Sprintf("lsm: %s (%s)", sp.LSM.Module, sp.LSM.Context)))
	} else {
		fmt.Fprintln(w, "    "+Warn("lsm: none/unavailable"))
	}

	if sp.MapSummary != nil {
		m := sp.MapSummary
		fmt.Fprintln(w, "\n  "+Bold("Memory mappings:"))
		fmt.Fprintf(w, "    %s\n", memBar(*m))
		fmt.Fprintf(w, "    total=%d executable=%d writable=%d rwx=%d anon_exec=%d\n",
			m.Total, m.Executable, m.Writable, m.RWX, m.AnonymousExec)
		if m.RWX > 0 {
			fmt.Fprintln(w, "    "+Warn("RWX mapping(s) present (writable+executable memory)"))
		}
		if m.AnonymousExec > 0 {
			fmt.Fprintln(w, "    "+Warn("anonymous executable mapping(s) present (possible injected code)"))
		}
	}

	if len(sp.SensitiveEnv) > 0 {
		fmt.Fprintln(w, "\n  "+Bold("Environment:"))
		fmt.Fprintln(w, "    "+Warn("sensitive-looking vars (names only): "+strings.Join(sp.SensitiveEnv, ", ")))
	}

	printAccessibility(w, sp.Access)
}

// printRiskLine renders the risk badge plus, if the score is
// applicable, every contributing reason with its point value —
// "never a black box" per the design doc. Kernel threads show a
// dimmed N/A line with a one-line explanation instead of a score.
func printRiskLine(w io.Writer, rs security.RiskScore) {
	if !rs.Applicable {
		fmt.Fprintln(w, "  risk: "+Dim("[N/A] kernel thread — not scored (root/full-caps is normal for kernel threads)"))
		return
	}
	fmt.Fprintf(w, "  risk: %s\n", riskBadge(rs))
	for _, r := range rs.Reasons {
		fmt.Fprintf(w, "        %s\n", Dim(fmt.Sprintf("+%-3d %s", r.Points, r.Text)))
	}
	if len(rs.Reasons) == 0 {
		fmt.Fprintln(w, "        "+Dim("no risk signals present"))
	}
}

// printAccessibility reports which /proc sources were and weren't
// readable for this process, explicitly — per the design doc's
// principle of representing inaccessibility rather than silently
// omitting sections. Only prints sources that AREN'T cleanly
// readable, so a fully-accessible process (the common case when
// running as root) doesn't clutter output with all-green noise.
func printAccessibility(w io.Writer, a proc.Accessibility) {
	type entry struct {
		label string
		state proc.AccessState
	}
	entries := []entry{
		{"environ", a.Environ}, {"maps", a.Maps}, {"smaps", a.Smaps},
		{"fds", a.FDs}, {"namespaces", a.NS}, {"cgroup", a.Cgroup},
	}
	var restricted []string
	for _, e := range entries {
		if e.state != proc.Readable {
			restricted = append(restricted, fmt.Sprintf("%s (%s)", e.label, e.state))
		}
	}
	if len(restricted) > 0 {
		fmt.Fprintln(w, "\n  "+Dim("Not fully accessible: "+strings.Join(restricted, ", ")))
	}
}

func printHardeningLine(w io.Writer, label string, on bool) {
	if on {
		fmt.Fprintln(w, "    "+Ok(label+": true"))
	} else {
		fmt.Fprintln(w, "    "+Warn(label+": false"))
	}
}

func riskBadge(rs security.RiskScore) string {
	label := rs.Label()
	if label == "-" {
		return Dim("[-]")
	}
	color := SeverityColor(rs.Score)
	return color(fmt.Sprintf("[%s %d/100]", label, rs.Score))
}

// memBar renders a compact colored bar summarizing a process's
// mapping breakdown at a glance — file-backed in blue, anonymous in
// gray, with a bold red segment for anonymous+executable (the
// combination most associated with injected/shellcode-style memory).
func memBar(m proc.MapSummary) string {
	if m.Total == 0 {
		return Dim("(no mappings)")
	}
	const width = 20
	anonExec := scaleTo(m.AnonymousExec, m.Total, width)
	fileBacked := scaleTo(m.FileBacked, m.Total, width)
	anonOther := width - anonExec - fileBacked
	if anonOther < 0 {
		anonOther = 0
	}

	var b strings.Builder
	b.WriteString(BoldRed(strings.Repeat("█", anonExec)))
	b.WriteString(Blue(strings.Repeat("█", fileBacked)))
	b.WriteString(Gray(strings.Repeat("░", anonOther)))
	return b.String()
}

func scaleTo(part, total, width int) int {
	if total == 0 {
		return 0
	}
	n := part * width / total
	if n == 0 && part > 0 {
		n = 1 // show at least one cell for a nonzero count
	}
	return n
}

func joinOrNone(ss []string) string {
	if len(ss) == 0 {
		return Dim("(none)")
	}
	return strings.Join(ss, ", ")
}

func joinInts(ns []int) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(parts, ",")
}
