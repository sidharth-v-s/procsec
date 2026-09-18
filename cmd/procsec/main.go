// Command procsec is a Linux /proc-based process security explorer.
// See README.md for the full command reference and procsec_outline.md
// for the design doc this implementation follows.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"syscall"
	"text/tabwriter"
	"time"

	"procsec/monitor"
	"procsec/output"
	"procsec/proc"
	"procsec/security"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	setupColor(os.Args[1:])

	var err error
	switch os.Args[1] {
	case "ps":
		err = cmdPS(os.Args[2:])
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "tree":
		err = cmdTree(os.Args[2:])
	case "watch":
		err = cmdWatch(os.Args[2:])
	case "maps":
		err = cmdMaps(os.Args[2:])
	case "fds":
		err = cmdFDs(os.Args[2:])
	case "environ":
		err = cmdEnviron(os.Args[2:])
	case "ns":
		err = cmdNS(os.Args[2:])
	case "cgroup":
		err = cmdCgroup(os.Args[2:])
	case "caps":
		err = cmdCaps(os.Args[2:])
	case "security":
		err = cmdSecurity(os.Args[2:])
	case "system":
		err = cmdSystem(os.Args[2:])
	case "zombies":
		err = cmdZombies(os.Args[2:])
	case "root":
		err = cmdRoot(os.Args[2:])
	case "top":
		err = cmdTop(os.Args[2:])
	case "snapshot":
		err = cmdSnapshot(os.Args[2:])
	case "diff":
		err = cmdDiff(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "procsec: unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "procsec: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, output.Bold("procsec")+" — Linux /proc-based process security explorer\n\n"+`Usage:
  procsec ps [--json] [--risk]                    List all processes (--risk adds a heuristic score column)
    [--user U] [--name S] [--state Z]             Filter by owner/name-or-cmdline-substring/state letter
  procsec inspect <PID> [--json]                  Combined process detail view
  procsec tree                                    Process ancestry tree
  procsec top                                     Live auto-refreshing dashboard (like top, security-focused)
  procsec watch [--no-context] [--baseline F]     Live create/exit/context-change monitor
  procsec maps <PID>                              Memory mapping analysis
  procsec fds <PID>                                File descriptor analysis
  procsec environ <PID> [--reveal]                Environment variables (sensitive values masked by default)
  procsec ns <PID> [PID2]                          Namespace analysis (or diff two PIDs)
  procsec cgroup <PID>                             Cgroup membership
  procsec caps <PID>                               Capability decoding
  procsec security <PID> [--json]                  Combined security profile
  procsec system [--json]                          System summary (active LSMs, process count)
  procsec zombies                                  Shortcut: list zombie (defunct) processes
  procsec root [--risk]                            Shortcut: list processes running as root
  procsec snapshot <file>                          Save current process state for later comparison
  procsec diff <file>                              Compare live state against a saved snapshot

Global flags:
  --no-color                                       Disable colored output (also respects NO_COLOR env var)`)
}

func parsePID(args []string) (int, []string, error) {
	if len(args) == 0 {
		return 0, nil, fmt.Errorf("missing PID argument")
	}
	pid, err := strconv.Atoi(args[0])
	if err != nil {
		return 0, nil, fmt.Errorf("invalid PID %q: %w", args[0], err)
	}
	return pid, args[1:], nil
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

// flagValue returns the value following "--name value" in args, and
// ok=false if the flag wasn't present. Used for --user/--name/--state
// filters on `ps`.
func flagValue(args []string, name string) (string, bool) {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

// setupColor decides whether output.Enabled should be true, following
// the same convention most modern CLIs use: colors on by default when
// stdout is a real terminal, off when piped/redirected, and always
// off if --no-color is passed or NO_COLOR is set in the environment
// (https://no-color.org). Checked once at startup so every printer
// downstream just reads output.Enabled without re-deriving this.
func setupColor(args []string) {
	if hasFlag(args, "--no-color") {
		output.Enabled = false
		return
	}
	if _, set := os.LookupEnv("NO_COLOR"); set {
		output.Enabled = false
		return
	}
	output.Enabled = output.IsTerminal(os.Stdout)
}

// --- ps ---

func cmdPS(args []string) error {
	procs, err := proc.ReadAll()
	if err != nil {
		return fmt.Errorf("reading processes: %w", err)
	}

	f := proc.Filter{}
	if v, ok := flagValue(args, "--user"); ok {
		f.User = v
	}
	if v, ok := flagValue(args, "--name"); ok {
		f.Name = v
	}
	if v, ok := flagValue(args, "--state"); ok {
		f.State = v
	}
	f.ResolveUser()
	procs = f.Apply(procs)

	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })

	if hasFlag(args, "--json") {
		return output.WriteProcessListJSON(os.Stdout, procs)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	if hasFlag(args, "--risk") {
		output.PrintProcessTableWithRisk(w, procs)
	} else {
		output.PrintProcessTable(w, procs)
	}
	return w.Flush()
}

// cmdZombies is the `procsec zombies` shortcut for Filter{State: "Z"}.
func cmdZombies(args []string) error {
	procs, err := proc.ReadAll()
	if err != nil {
		return err
	}
	z := proc.Zombies(procs)
	sort.Slice(z, func(i, j int) bool { return z[i].PID < z[j].PID })
	if len(z) == 0 {
		fmt.Println(output.Ok("no zombie processes"))
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	output.PrintProcessTable(w, z)
	return w.Flush()
}

// cmdRoot is the `procsec root` shortcut for Filter{UID: 0}.
func cmdRoot(args []string) error {
	procs, err := proc.ReadAll()
	if err != nil {
		return err
	}
	r := proc.RunningAsRoot(procs)
	sort.Slice(r, func(i, j int) bool { return r[i].PID < r[j].PID })
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	if hasFlag(args, "--risk") {
		output.PrintProcessTableWithRisk(w, r)
	} else {
		output.PrintProcessTable(w, r)
	}
	return w.Flush()
}

// --- inspect ---

func cmdInspect(args []string) error {
	pid, rest, err := parsePID(args)
	if err != nil {
		return err
	}

	p, err := proc.ReadProcess(pid)
	if err != nil {
		return err
	}

	if hasFlag(rest, "--json") {
		sp := output.BuildSecurityProfile(p)
		return output.WriteSecurityProfileJSON(os.Stdout, sp)
	}

	all, _ := proc.ReadAll()
	ancestors := proc.Ancestors(all, pid)

	fmt.Printf("=== Process %d ===\n", pid)
	sp := output.BuildSecurityProfile(p)
	output.PrintSecurityProfile(os.Stdout, sp)

	if len(ancestors) > 0 {
		fmt.Println("\n  Ancestry (immediate parent first):")
		for _, a := range ancestors {
			fmt.Printf("    %d %s (uid=%d)\n", a.PID, a.Name, a.UID)
		}
	}

	if ns, err := proc.ReadNamespaces(pid); err == nil {
		fmt.Println("\n  Namespaces:")
		for t, id := range ns {
			fmt.Printf("    %-18s %d\n", t, id)
		}
	}

	if cg, err := proc.ReadCgroups(pid); err == nil && len(cg) > 0 {
		fmt.Println("\n  Cgroup:")
		output.PrintCgroups(os.Stdout, cg)
	}

	return nil
}

// --- tree ---

func cmdTree(args []string) error {
	procs, err := proc.ReadAll()
	if err != nil {
		return err
	}
	roots := proc.BuildTree(procs)
	output.PrintTree(os.Stdout, roots)
	return nil
}

// --- top ---

// cmdTop is a security-focused live dashboard: refreshes every second
// showing process count, root-owned count, zombie count, and the top
// 10 processes by heuristic risk score — a "what needs my attention
// right now" view rather than ps's raw dump or top's CPU/mem focus.
func cmdTop(args []string) error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	renderTop() // draw immediately, don't wait for first tick
	for {
		select {
		case <-sigs:
			return nil
		case <-ticker.C:
			renderTop()
		}
	}
}

func renderTop() {
	procs, err := proc.ReadAll()
	if err != nil {
		return
	}

	type scored struct {
		p    *proc.Process
		risk security.RiskScore
	}
	scoredList := make([]scored, 0, len(procs))
	rootCount, zombieCount := 0, 0
	for _, p := range procs {
		if p.UID == 0 {
			rootCount++
		}
		if p.State == "Z" {
			zombieCount++
		}
		extra, err := proc.ReadStatusExtra(p.PID)
		if err != nil {
			continue
		}
		capEff := security.DecodeCapabilities(extra.CapEff)
		rs := security.ScoreProcess(security.RiskInputs{
			UID:             p.UID,
			RunningAsRoot:   p.UID == 0,
			FullCapSet:      security.HasFullCapabilitySet(extra.CapEff),
			InterestingCaps: security.InterestingCapabilities(capEff),
			NoNewPrivs:      extra.NoNewPrivs,
			SeccompEnabled:  extra.Seccomp != 0,
		})
		if rs.Score > 0 {
			scoredList = append(scoredList, scored{p, rs})
		}
	}
	sort.Slice(scoredList, func(i, j int) bool { return scoredList[i].risk.Score > scoredList[j].risk.Score })

	// \033[H\033[2J: home cursor + clear screen, so the dashboard
	// redraws in place instead of scrolling — same trick `top` uses.
	if output.Enabled {
		fmt.Print("\033[H\033[2J")
	}
	fmt.Printf("%s  %s\n", output.Bold("procsec top"), output.Dim(time.Now().Format("15:04:05")))
	fmt.Printf("processes: %d   %s: %d   %s: %d\n\n",
		len(procs), output.Red("root-owned"), rootCount, output.BoldRed("zombies"), zombieCount)

	fmt.Println(output.Bold("Top by risk score:"))
	limit := 10
	if len(scoredList) < limit {
		limit = len(scoredList)
	}
	if limit == 0 {
		fmt.Println(output.Dim("  (nothing flagged)"))
	}
	for i := 0; i < limit; i++ {
		s := scoredList[i]
		color := output.SeverityColor(s.risk.Score)
		fmt.Printf("  %s  %-20s %s\n", color(fmt.Sprintf("[%3d]", s.risk.Score)), fmt.Sprintf("%s(%d)", s.p.Name, s.p.PID), output.Dim(joinReasons(s.risk.Reasons)))
	}
	fmt.Println(output.Dim("\nCtrl+C to exit"))
}

func joinReasons(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	out := reasons[0]
	for _, r := range reasons[1:] {
		out += "; " + r
	}
	return out
}

// --- snapshot / diff ---

// cmdSnapshot implements `procsec snapshot <file>` — saves the
// current process state (by name/exe/uid, not PID) for later
// comparison via `procsec diff` or `procsec watch --baseline`.
func cmdSnapshot(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: procsec snapshot <output-file>")
	}
	snap, err := proc.TakeSnapshot()
	if err != nil {
		return err
	}
	if err := proc.SaveSnapshot(snap, args[0]); err != nil {
		return err
	}
	fmt.Printf("%s saved snapshot of %d processes to %s\n", output.Ok(""), len(snap.Entries), args[0])
	return nil
}

// cmdDiff implements `procsec diff <baseline-file>` — one-shot
// comparison of live state against a saved snapshot.
func cmdDiff(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: procsec diff <baseline-file>")
	}
	baseline, err := proc.LoadSnapshot(args[0])
	if err != nil {
		return err
	}
	live, err := proc.ReadAll()
	if err != nil {
		return err
	}
	diff := proc.DiffAgainstSnapshot(baseline, live)
	printSnapshotDiff(diff)
	return nil
}

func printSnapshotDiff(diff proc.SnapshotDiff) {
	if len(diff.New) == 0 && len(diff.Missing) == 0 {
		fmt.Println(output.Ok("no differences from baseline"))
		return
	}
	if len(diff.New) > 0 {
		fmt.Println(output.Warn(fmt.Sprintf("%d new process type(s) not in baseline:", len(diff.New))))
		for _, e := range diff.New {
			fmt.Printf("    + %s (uid=%d) %s\n", e.Name, e.UID, output.Dim(e.Exe))
		}
	}
	if len(diff.Missing) > 0 {
		fmt.Println(output.Dim(fmt.Sprintf("%d baseline process type(s) no longer running:", len(diff.Missing))))
		for _, e := range diff.Missing {
			fmt.Printf("    - %s (uid=%d) %s\n", e.Name, e.UID, output.Dim(e.Exe))
		}
	}
}

// --- watch ---

func cmdWatch(args []string) error {
	w := monitor.NewWatcher()
	if hasFlag(args, "--no-context") {
		w.DeepCheckInterval = 0
	}

	if path, ok := flagValue(args, "--baseline"); ok {
		baseline, err := proc.LoadSnapshot(path)
		if err != nil {
			return fmt.Errorf("loading baseline: %w", err)
		}
		live, err := proc.ReadAll()
		if err != nil {
			return err
		}
		fmt.Println(output.Bold("Baseline comparison:"))
		printSnapshotDiff(proc.DiffAgainstSnapshot(baseline, live))
		fmt.Println()
	}

	events := make(chan monitor.Event, 256)
	stop := make(chan struct{})

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go w.Run(events, stop)

	fmt.Println("procsec watch — press Ctrl+C to stop")
	for {
		select {
		case ev := <-events:
			output.PrintWatchEvent(os.Stdout, ev)
		case <-sigs:
			close(stop)
			return nil
		}
	}
}

// --- maps ---

func cmdMaps(args []string) error {
	pid, _, err := parsePID(args)
	if err != nil {
		return err
	}
	maps, err := proc.ReadMaps(pid)
	if err != nil {
		return err
	}
	output.PrintMaps(os.Stdout, maps)

	if sm, err := proc.ReadSmapsSummary(pid); err == nil {
		fmt.Printf("\nSummary: rss=%dKB pss=%dKB anon=%dKB anon_exec=%dKB rwx=%dKB locked=%dKB\n",
			sm.RSS, sm.PSS, sm.AnonymousKB, sm.ExecutableAnonKB, sm.RWXKB, sm.LockedKB)
	}
	return nil
}

// --- fds ---

func cmdFDs(args []string) error {
	pid, _, err := parsePID(args)
	if err != nil {
		return err
	}
	fds, err := proc.ReadFDs(pid)
	if err != nil {
		return err
	}
	output.PrintFDs(os.Stdout, fds)
	return nil
}

// --- environ ---

func cmdEnviron(args []string) error {
	pid, rest, err := parsePID(args)
	if err != nil {
		return err
	}
	vars, err := proc.ReadEnviron(pid)
	if err != nil {
		return err
	}
	output.PrintEnviron(os.Stdout, vars, hasFlag(rest, "--reveal"))
	return nil
}

// --- ns ---

func cmdNS(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing PID argument")
	}
	pid1, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid PID %q: %w", args[0], err)
	}

	ns1, err := proc.ReadNamespaces(pid1)
	if err != nil {
		return err
	}

	if len(args) >= 2 {
		pid2, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("invalid PID %q: %w", args[1], err)
		}
		ns2, err := proc.ReadNamespaces(pid2)
		if err != nil {
			return err
		}
		diff := proc.CompareNamespaces(ns1, ns2)
		output.PrintNamespaceDiff(os.Stdout, diff)
		return nil
	}

	output.PrintNamespaces(os.Stdout, ns1)
	return nil
}

// --- cgroup ---

func cmdCgroup(args []string) error {
	pid, _, err := parsePID(args)
	if err != nil {
		return err
	}
	entries, err := proc.ReadCgroups(pid)
	if err != nil {
		return err
	}
	output.PrintCgroups(os.Stdout, entries)
	return nil
}

// --- caps ---

func cmdCaps(args []string) error {
	pid, _, err := parsePID(args)
	if err != nil {
		return err
	}
	sp := output.BuildSecurityProfile(&proc.Process{PID: pid})
	fmt.Printf("%s %v\n", output.Bold("effective:"), sp.CapEff)
	fmt.Printf("%s %v\n", output.Bold("permitted:"), sp.CapPrm)
	fmt.Printf("%s  %v\n", output.Bold("bounding:"), sp.CapBnd)
	if len(sp.InterestingCap) > 0 {
		fmt.Println(output.Warn(fmt.Sprintf("notable: %v", sp.InterestingCap)))
	}
	if sp.FullCapSet {
		fmt.Println(output.Warn("full capability set (nothing dropped)"))
	}
	return nil
}

// --- security ---

func cmdSecurity(args []string) error {
	pid, rest, err := parsePID(args)
	if err != nil {
		return err
	}
	p, err := proc.ReadProcess(pid)
	if err != nil {
		return err
	}
	sp := output.BuildSecurityProfile(p)

	if hasFlag(rest, "--json") {
		return output.WriteSecurityProfileJSON(os.Stdout, sp)
	}
	output.PrintSecurityProfile(os.Stdout, sp)
	return nil
}

// --- system ---

type systemSummary struct {
	ProcessCount int      `json:"process_count"`
	ActiveLSMs   []string `json:"active_lsms"`
}

func cmdSystem(args []string) error {
	pids, err := proc.ListPIDs()
	if err != nil {
		return err
	}

	sum := systemSummary{
		ProcessCount: len(pids),
		ActiveLSMs:   security.ActiveLSMs(),
	}

	if hasFlag(args, "--json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(sum)
	}

	fmt.Printf("%s %d\n", output.Bold("processes:"), sum.ProcessCount)
	if len(sum.ActiveLSMs) > 0 {
		fmt.Printf("%s %v\n", output.Bold("active LSMs:"), sum.ActiveLSMs)
	} else {
		fmt.Println(output.Warn("no active LSMs detected (or securityfs not readable)"))
	}
	return nil
}
