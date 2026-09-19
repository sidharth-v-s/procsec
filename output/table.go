package output

import (
	"fmt"
	"os/user"
	"strconv"
	"strings"
	"text/tabwriter"

	"procsec/proc"
	"procsec/security"
)

// PrintProcessTable writes a `ps`-style aligned table of processes to w.
// Root-owned rows are highlighted (bold red PID) so a scroll through a
// long process list draws the eye to privileged processes first.
func PrintProcessTable(w *tabwriter.Writer, procs []*proc.Process) {
	fmt.Fprintln(w, Bold("PID\tUSER\tTYPE\tNAME\tSTATE\tEXE"))
	for _, p := range procs {
		exe := p.Exe
		if exe == "" {
			exe = Dim("-")
		}
		pidStr := strconv.Itoa(p.PID)
		userStr := resolveUser(p.UID)
		if p.UID == 0 {
			pidStr = BoldRed(pidStr)
			userStr = Red(userStr)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			pidStr, userStr, colorType(proc.Classify(p)), p.Name, colorState(p.State), exe)
	}
}

// PrintProcessTableWithRisk is PrintProcessTable plus a RISK column,
// for `procsec ps --risk` — computes a lightweight score per process
// from just its capabilities/hardening (no memory-map read, to keep
// a full-table pass cheap; use `inspect` for the complete picture).
// Kernel threads show N/A rather than a misleadingly high score —
// see security/risk.go's IsScorable for why.
func PrintProcessTableWithRisk(w *tabwriter.Writer, procs []*proc.Process) {
	fmt.Fprintln(w, Bold("PID\tUSER\tTYPE\tNAME\tSTATE\tRISK\tEXE"))
	for _, p := range procs {
		exe := p.Exe
		if exe == "" {
			exe = Dim("-")
		}
		pidStr := strconv.Itoa(p.PID)
		userStr := resolveUser(p.UID)
		if p.UID == 0 {
			pidStr = BoldRed(pidStr)
			userStr = Red(userStr)
		}

		ptype := proc.Classify(p)
		risk := quickRisk(p, ptype)
		riskStr := colorRiskLabel(risk)

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			pidStr, userStr, colorType(ptype), p.Name, colorState(p.State), riskStr, exe)
	}
}

// quickRisk computes a RiskScore using only cheap-to-read signals
// (status caps/hardening), skipping the memory-map scan that a full
// `inspect` does — keeps `ps --risk` fast across hundreds of PIDs.
func quickRisk(p *proc.Process, ptype proc.ProcType) security.RiskScore {
	if !security.IsScorable(string(ptype)) {
		return security.RiskScore{Applicable: false}
	}
	extra, err := proc.ReadStatusExtra(p.PID)
	if err != nil {
		return security.RiskScore{Applicable: false}
	}
	capEff := security.DecodeCapabilities(extra.CapEff)
	in := security.RiskInputs{
		ProcType:        string(ptype),
		UID:             p.UID,
		RunningAsRoot:   p.UID == 0,
		FullCapSet:      security.HasFullCapabilitySet(extra.CapEff),
		InterestingCaps: security.InterestingCapabilities(capEff),
		NoNewPrivs:      extra.NoNewPrivs,
		SeccompEnabled:  extra.Seccomp != 0,
	}
	return security.ScoreProcess(in)
}

func colorRiskLabel(rs security.RiskScore) string {
	label := rs.Label()
	if label == "-" || label == "N/A" {
		return Dim(label)
	}
	return SeverityColor(rs.Score)(label)
}

// colorType tints a process type label — kernel threads dimmed since
// they're rarely the point of an investigation, daemons/interactive
// in default color, unknown dimmed as well.
func colorType(t proc.ProcType) string {
	switch t {
	case proc.TypeKernelThread:
		return Dim(string(t))
	case proc.TypeUnknown:
		return Dim(string(t))
	default:
		return string(t)
	}
}

// colorState tints a process state letter: red for zombie (Z), green
// for running (R), default for everything else — zombies in
// particular are worth the eye's attention on a security-focused tool.
func colorState(state string) string {
	switch state {
	case "":
		return Dim("-")
	case "Z":
		return BoldRed("Z")
	case "R":
		return Green("R")
	default:
		return state
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// userCache avoids a syscall/file-read per row when many processes
// share the same UID (the common case: lots of processes as one
// service account).
var userCache = map[int]string{}

func resolveUser(uid int) string {
	if name, ok := userCache[uid]; ok {
		return name
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	name := strconv.Itoa(uid)
	if err == nil && u.Username != "" {
		name = u.Username
	}
	userCache[uid] = name
	return name
}

// FormatCmdline joins an argv slice the way a shell would display it,
// for use in `inspect` output. Empty cmdline (kernel threads) renders
// as "[name]" bracket notation, matching `ps` convention.
func FormatCmdline(name string, cmdline []string) string {
	if len(cmdline) == 0 {
		return Dim("[" + name + "]")
	}
	return strings.Join(cmdline, " ")
}
