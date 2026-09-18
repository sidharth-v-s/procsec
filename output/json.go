package output

import (
	"encoding/json"
	"io"

	"procsec/proc"
	"procsec/security"
)

// jsonProcess is the JSON-serializable view of a Process — kept as a
// separate type (rather than adding json tags directly to proc.Process)
// so the proc package has no output-format concerns, per the
// architecture's separation of proc/ (data) from output/ (rendering).
type jsonProcess struct {
	PID     int      `json:"pid"`
	PPID    int      `json:"ppid"`
	Name    string   `json:"name"`
	Exe     string   `json:"exe,omitempty"`
	Cmdline []string `json:"cmdline"`
	State   string   `json:"state"`
	UID     int      `json:"uid"`
	GID     int      `json:"gid"`
	Threads int      `json:"threads"`
}

func toJSONProcess(p *proc.Process) jsonProcess {
	return jsonProcess{
		PID: p.PID, PPID: p.PPID, Name: p.Name, Exe: p.Exe,
		Cmdline: p.Cmdline, State: p.State, UID: p.UID, GID: p.GID,
		Threads: p.Threads,
	}
}

// WriteProcessListJSON writes procs as a JSON array to w.
func WriteProcessListJSON(w io.Writer, procs []*proc.Process) error {
	out := make([]jsonProcess, len(procs))
	for i, p := range procs {
		out[i] = toJSONProcess(p)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// SecurityProfile is the combined per-process security view returned
// by `procsec security <PID> --json` and used internally by
// `procsec inspect <PID>` — bundling status, capabilities, LSM
// context, and a memory-mapping summary into one payload (design doc
// section: "Security Context Change Detection" / combined security
// profile).
type SecurityProfile struct {
	Process        jsonProcess         `json:"process"`
	Groups         []int               `json:"groups,omitempty"`
	CapEff         []string            `json:"cap_effective"`
	CapPrm         []string            `json:"cap_permitted"`
	CapBnd         []string            `json:"cap_bounding"`
	InterestingCap []string            `json:"capabilities_of_interest,omitempty"`
	FullCapSet     bool                `json:"full_capability_set"`
	NoNewPrivs     bool                `json:"no_new_privs"`
	Seccomp        string              `json:"seccomp_mode"`
	LSM            security.LSMContext `json:"lsm"`
	MapSummary     *proc.MapSummary    `json:"map_summary,omitempty"`
	SensitiveEnv   []string            `json:"sensitive_env_keys,omitempty"`
}

// BuildSecurityProfile assembles a SecurityProfile for pid, reading
// every relevant /proc source. Each sub-read is best-effort: a
// process we can see in ps but can't fully introspect (permission
// denied on smaps, say) still yields a partial profile rather than
// no profile at all.
func BuildSecurityProfile(p *proc.Process) SecurityProfile {
	sp := SecurityProfile{Process: toJSONProcess(p)}

	if extra, err := proc.ReadStatusExtra(p.PID); err == nil {
		sp.Groups = extra.Groups
		sp.CapEff = security.DecodeCapabilities(extra.CapEff)
		sp.CapPrm = security.DecodeCapabilities(extra.CapPrm)
		sp.CapBnd = security.DecodeCapabilities(extra.CapBnd)
		sp.InterestingCap = security.InterestingCapabilities(sp.CapEff)
		sp.FullCapSet = security.HasFullCapabilitySet(extra.CapEff)
		sp.NoNewPrivs = extra.NoNewPrivs
		sp.Seccomp = security.SeccompState(extra.Seccomp)
	}

	sp.LSM = security.ReadLSMContext(p.PID)

	if maps, err := proc.ReadMaps(p.PID); err == nil {
		summary := proc.SummarizeMaps(maps)
		sp.MapSummary = &summary
	}

	if env, err := proc.ReadEnviron(p.PID); err == nil {
		sp.SensitiveEnv = proc.SensitiveKeys(env)
	}

	return sp
}

// WriteSecurityProfileJSON writes a single SecurityProfile as JSON.
func WriteSecurityProfileJSON(w io.Writer, sp SecurityProfile) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sp)
}
