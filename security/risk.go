package security

// RiskScore is a heuristic 0-100 "worth a second look" score for a
// process, built purely from signals procsec already collects
// (capabilities, memory mappings, hardening state). It is NOT a
// vulnerability verdict — see the project's explicit non-goal of not
// being a vuln scanner. It's a triage aid: on a box with hundreds of
// processes, this says where to point `procsec inspect` first.
//
// Scoring is skipped entirely (Applicable=false) for process kinds
// where the underlying properties are structurally normal rather
// than suspicious — kernel threads in particular are root, hold a
// full capability set, and have no_new_privs/seccomp disabled as a
// matter of course, and scoring them the same way as a user process
// would just be noise that buries the processes actually worth
// looking at (this was the #1 issue flagged against the original
// scoring model: it ranked kworker threads above real candidates).
type RiskScore struct {
	Applicable bool
	Score      int
	Reasons    []Reason
}

// Reason is one line item contributing to a RiskScore: the point
// value and a human-readable explanation. Kept as a struct (rather
// than a pre-formatted string) so callers can choose how much detail
// to render — a compact `ps --risk` table wants just the label, while
// `top --explain` and `inspect` want the full reasoned breakdown.
type Reason struct {
	Points int
	Text   string
}

// RiskInputs bundles the fields RiskScore needs, so this package
// doesn't have to import proc (keeping proc/security/output as a
// clean one-way dependency chain per the architecture doc). Callers
// pass a plain string for ProcType rather than proc.ProcType to
// preserve that boundary; see output.BuildSecurityProfile for where
// the proc.ProcType -> string conversion happens.
type RiskInputs struct {
	ProcType         string // "kernel-thread" skips scoring entirely; see IsScorable
	UID              int
	RunningAsRoot    bool
	FullCapSet       bool
	InterestingCaps  []string
	NoNewPrivs       bool
	SeccompEnabled   bool
	LSMConfined      bool
	RWXMappings      int
	AnonExecMappings int
	SensitiveEnvVars int
}

// IsScorable reports whether a process type should be risk-scored at
// all. Kernel threads are excluded: root UID, full capabilities, and
// disabled seccomp/no_new_privs are their structurally normal state,
// not a security signal.
func IsScorable(procType string) bool {
	return procType != "kernel-thread"
}

// ScoreProcess computes a RiskScore from RiskInputs. Weights are
// deliberately simple and additive (not multiplicative/ML-derived)
// so the score stays explainable — every point traces to a Reason
// line the operator can read and judge for themselves. This is
// treated as a security-relevance indicator, never proof of
// maliciousness: high privilege alone (root, full caps) is completely
// normal for plenty of legitimate daemons, which is exactly why every
// point is shown with its reason rather than presented as a bare verdict.
func ScoreProcess(in RiskInputs) RiskScore {
	if !IsScorable(in.ProcType) {
		return RiskScore{Applicable: false}
	}

	rs := RiskScore{Applicable: true}
	add := func(points int, text string) {
		rs.Score += points
		rs.Reasons = append(rs.Reasons, Reason{Points: points, Text: text})
	}

	if in.RunningAsRoot {
		add(10, "privileged UID (root)")
	}
	if in.FullCapSet {
		add(20, "unrestricted capabilities (full set, nothing dropped)")
	} else if n := len(in.InterestingCaps); n > 0 {
		pts := 5 * n
		if pts > 20 {
			pts = 20
		}
		add(pts, "holds high-impact capabilities")
	}
	if !in.NoNewPrivs {
		add(5, "no_new_privs disabled")
	}
	if !in.SeccompEnabled {
		add(10, "no seccomp filtering")
	}
	if !in.LSMConfined {
		add(5, "no LSM confinement detected")
	}
	if in.RWXMappings > 0 {
		add(20, "writable+executable memory present")
	}
	if in.AnonExecMappings > 0 {
		add(15, "anonymous executable memory present")
	}
	if in.SensitiveEnvVars > 0 {
		add(5, "sensitive-looking environment variables")
	}

	if rs.Score > 100 {
		rs.Score = 100
	}
	return rs
}

// Label renders a score as a short human word for compact table
// columns ("procsec ps --risk"). Non-scorable processes (kernel
// threads) render as "N/A", distinct from a scored-but-zero "-".
func (rs RiskScore) Label() string {
	if !rs.Applicable {
		return "N/A"
	}
	switch {
	case rs.Score >= 70:
		return "HIGH"
	case rs.Score >= 30:
		return "MED"
	case rs.Score > 0:
		return "LOW"
	default:
		return "-"
	}
}

// ReasonTexts returns just the text of each reason, for callers that
// don't need per-line point values (e.g. the compact inline summary
// used in `top`'s dashboard rows).
func (rs RiskScore) ReasonTexts() []string {
	texts := make([]string, len(rs.Reasons))
	for i, r := range rs.Reasons {
		texts[i] = r.Text
	}
	return texts
}
