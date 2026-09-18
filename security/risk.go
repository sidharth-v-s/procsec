package security

// RiskScore is a heuristic 0-100 "worth a second look" score for a
// process, built purely from signals procsec already collects
// (capabilities, memory mappings, hardening state). It is NOT a
// vulnerability verdict — see the project's explicit non-goal of not
// being a vuln scanner. It's a triage aid: on a box with hundreds of
// processes, this says where to point `procsec inspect` first.
type RiskScore struct {
	Score   int
	Reasons []string
}

// RiskInputs bundles the fields RiskScore needs, so this package
// doesn't have to import proc (keeping proc/security/output as a
// clean one-way dependency chain per the architecture doc).
type RiskInputs struct {
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

// ScoreProcess computes a RiskScore from RiskInputs. Weights are
// deliberately simple and additive (not multiplicative/ML-derived)
// so the score stays explainable — every point traces to a Reason
// line the operator can read and judge for themselves.
func ScoreProcess(in RiskInputs) RiskScore {
	var rs RiskScore

	if in.RunningAsRoot {
		rs.Score += 10
		rs.Reasons = append(rs.Reasons, "running as root")
	}
	if in.FullCapSet {
		rs.Score += 20
		rs.Reasons = append(rs.Reasons, "full capability set (nothing dropped)")
	} else if n := len(in.InterestingCaps); n > 0 {
		add := 5 * n
		if add > 20 {
			add = 20
		}
		rs.Score += add
		rs.Reasons = append(rs.Reasons, "holds high-impact capabilities")
	}
	if !in.NoNewPrivs {
		rs.Score += 5
		rs.Reasons = append(rs.Reasons, "no_new_privs not set")
	}
	if !in.SeccompEnabled {
		rs.Score += 5
		rs.Reasons = append(rs.Reasons, "no seccomp filtering")
	}
	if !in.LSMConfined {
		rs.Score += 5
		rs.Reasons = append(rs.Reasons, "no LSM confinement detected")
	}
	if in.RWXMappings > 0 {
		rs.Score += 20
		rs.Reasons = append(rs.Reasons, "writable+executable memory present")
	}
	if in.AnonExecMappings > 0 {
		rs.Score += 15
		rs.Reasons = append(rs.Reasons, "anonymous executable memory present")
	}
	if in.SensitiveEnvVars > 0 {
		rs.Score += 5
		rs.Reasons = append(rs.Reasons, "sensitive-looking environment variables")
	}

	if rs.Score > 100 {
		rs.Score = 100
	}
	return rs
}

// Label renders a score as a short human word for compact table
// columns ("procsec ps --risk").
func (rs RiskScore) Label() string {
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
