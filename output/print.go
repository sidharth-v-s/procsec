package output

import (
	"fmt"
	"io"

	"procsec/monitor"
	"procsec/proc"
)

// PrintTree renders a process forest with ASCII branch connectors,
// coloring root-owned processes red so privilege boundaries in the
// ancestry are visible at a glance, e.g.:
//
//	systemd(1)
//	├─ sshd(842)
//	│  └─ bash(1021)
//	└─ cron(850)
func PrintTree(w io.Writer, roots []*proc.TreeNode) {
	for _, r := range roots {
		fmt.Fprintln(w, treeLabel(r.Process))
		for i, c := range r.Children {
			printTreeNode(w, c, "", i == len(r.Children)-1)
		}
	}
}

func printTreeNode(w io.Writer, n *proc.TreeNode, prefix string, last bool) {
	connector := "├─ "
	nextPrefix := prefix + "│  "
	if last {
		connector = "└─ "
		nextPrefix = prefix + "   "
	}
	fmt.Fprintf(w, "%s%s%s\n", Dim(prefix), Dim(connector), treeLabel(n.Process))
	for i, c := range n.Children {
		printTreeNode(w, c, nextPrefix, i == len(n.Children)-1)
	}
}

func treeLabel(p *proc.Process) string {
	label := fmt.Sprintf("%s(%d)", p.Name, p.PID)
	if p.UID == 0 {
		return Red(label)
	}
	return label
}

// PrintMaps renders /proc/<pid>/maps in a compact table, flagging
// RWX regions in bold red — the highest-signal line for a security
// read of memory mappings — and anonymous mappings in gray.
func PrintMaps(w io.Writer, maps []proc.Mapping) {
	fmt.Fprintln(w, Bold("ADDRESS RANGE\t\tPERMS\tPATH"))
	for _, m := range maps {
		path := m.Path
		if path == "" {
			path = Gray("[anon]")
		}
		perms := m.Perms
		line := fmt.Sprintf("%012x-%012x\t%s\t%s", m.Start, m.End, perms, path)
		if m.RWX() {
			fmt.Fprintln(w, BoldRed(line)+"  "+Warn("RWX"))
		} else if m.Executable() && m.Anonymous() {
			fmt.Fprintln(w, Yellow(line))
		} else {
			fmt.Fprintln(w, line)
		}
	}
}

// PrintFDs renders /proc/<pid>/fd with per-kind classification,
// color-coded by kind for quick scanning of large fd tables.
func PrintFDs(w io.Writer, fds []proc.FD) {
	fmt.Fprintln(w, Bold("FD\tKIND\tTARGET"))
	for _, fd := range fds {
		fmt.Fprintf(w, "%d\t%s\t%s\n", fd.Num, colorFDKind(fd.Kind), fd.Target)
	}
	s := proc.SummarizeFDs(fds)
	fmt.Fprintf(w, "\n%s total=%d regular=%d sockets=%d pipes=%d devices=%d other=%d\n",
		Dim("summary:"), len(fds), s.Regular, s.Sockets, s.Pipes, s.Devices, s.Other)
}

func colorFDKind(k proc.FDKind) string {
	switch k {
	case proc.FDSocket:
		return Cyan(string(k))
	case proc.FDPipe:
		return Blue(string(k))
	case proc.FDDevice:
		return Magenta(string(k))
	default:
		return string(k)
	}
}

// PrintEnviron renders environment variables, masking values for
// keys that look sensitive by default (design doc: flag, don't dump).
// Pass reveal=true only on an explicit user opt-in (--reveal flag).
// Sensitive keys are highlighted yellow so they stand out even when
// revealed.
func PrintEnviron(w io.Writer, vars []proc.EnvVar, reveal bool) {
	for _, v := range vars {
		if proc.IsSensitiveKey(v.Key) {
			if !reveal {
				fmt.Fprintf(w, "%s=%s\n", Yellow(v.Key), Dim("****** (sensitive, use --reveal to show)"))
				continue
			}
			fmt.Fprintf(w, "%s=%s\n", Yellow(v.Key), Yellow(v.Value))
			continue
		}
		fmt.Fprintf(w, "%s=%s\n", v.Key, v.Value)
	}
}

// PrintNamespaces renders a process's namespace inode table.
func PrintNamespaces(w io.Writer, ns proc.Namespaces) {
	fmt.Fprintln(w, Bold("TYPE\t\tID"))
	for _, t := range []string{"cgroup", "ipc", "mnt", "net", "pid", "pid_for_children", "time", "user", "uts"} {
		if id, ok := ns[t]; ok {
			fmt.Fprintf(w, "%s\t\t%d\n", t, id)
		}
	}
}

// PrintNamespaceDiff renders a comparison between two processes'
// namespaces, highlighting shared (green) vs distinct (yellow) —
// useful for spotting container escapes or unexpected namespace
// sharing.
func PrintNamespaceDiff(w io.Writer, d proc.NamespaceDiff) {
	fmt.Fprintf(w, "%s %v\n", Green("shared:"), d.Shared)
	fmt.Fprintf(w, "%s %v\n", Yellow("differ:"), d.Differ)
	if len(d.OnlyA) > 0 {
		fmt.Fprintf(w, "only in first:  %v\n", d.OnlyA)
	}
	if len(d.OnlyB) > 0 {
		fmt.Fprintf(w, "only in second: %v\n", d.OnlyB)
	}
}

// PrintCgroups renders a process's cgroup membership lines.
func PrintCgroups(w io.Writer, entries []proc.CgroupEntry) {
	v2 := proc.IsCgroupV2(entries)
	for _, e := range entries {
		if v2 {
			fmt.Fprintf(w, "%s %s\n", Dim("(v2 unified)"), e.Path)
			continue
		}
		fmt.Fprintf(w, "%s:%v:%s\n", e.ID, e.Controllers, e.Path)
	}
}

// PrintWatchEvent renders one monitor.Event line for `procsec watch`,
// color-coded by kind: green + for start, gray - for exit, bold red !
// for a security context change (the highest-signal event kind).
func PrintWatchEvent(w io.Writer, ev monitor.Event) {
	ts := Dim(ev.Time.Format("15:04:05.000"))
	p := ev.Process
	switch ev.Kind {
	case monitor.EventStarted:
		fmt.Fprintf(w, "[%s] %s PID %d started  uid=%d  %s\n",
			ts, Green("+"), p.PID, p.UID, FormatCmdline(p.Name, p.Cmdline))
	case monitor.EventExited:
		fmt.Fprintf(w, "[%s] %s PID %d exited   %s(%s)\n", ts, Gray("-"), p.PID, p.Name, orDash(p.Exe))
	case monitor.EventContextChanged:
		fmt.Fprintf(w, "[%s] %s PID %d context changed  %s\n",
			ts, BoldRed("!"), p.PID, FormatCmdline(p.Name, p.Cmdline))
		for _, c := range ev.Changes {
			fmt.Fprintf(w, "           %s: %s -> %s\n", c.Field, Dim(c.Old), Yellow(c.New))
		}
	}
}
