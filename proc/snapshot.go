package proc

import (
	"encoding/json"
	"fmt"
	"os"
)

// Snapshot is a saved point-in-time process listing, used by
// `procsec watch --baseline <file>` to diff the live system against
// a known-good state (e.g. right after provisioning a box) instead
// of only watching forward from "now". This is a lightweight,
// procsec-specific alternative to remembering exact PIDs — it keys
// on (Name, Exe, UID) since PIDs are meaningless across a reboot.
type Snapshot struct {
	Entries []SnapshotEntry `json:"entries"`
}

// SnapshotEntry is the subset of Process fields stable enough to
// compare across time — deliberately excludes PID (recycled/differs
// on every boot) and transient fields like State.
type SnapshotEntry struct {
	Name string `json:"name"`
	Exe  string `json:"exe"`
	UID  int    `json:"uid"`
}

func (e SnapshotEntry) key() string {
	return fmt.Sprintf("%s|%s|%d", e.Name, e.Exe, e.UID)
}

// TakeSnapshot builds a Snapshot from the current /proc state.
func TakeSnapshot() (*Snapshot, error) {
	procs, err := ReadAll()
	if err != nil {
		return nil, err
	}
	snap := &Snapshot{Entries: make([]SnapshotEntry, 0, len(procs))}
	for _, p := range procs {
		snap.Entries = append(snap.Entries, SnapshotEntry{Name: p.Name, Exe: p.Exe, UID: p.UID})
	}
	return snap, nil
}

// SaveSnapshot writes snap to path as JSON.
func SaveSnapshot(snap *Snapshot, path string) error {
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadSnapshot reads a previously saved Snapshot from path.
func LoadSnapshot(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parsing snapshot %s: %w", path, err)
	}
	return &snap, nil
}

// SnapshotDiff describes what's new or missing relative to a baseline.
type SnapshotDiff struct {
	New     []SnapshotEntry // present now, not in baseline
	Missing []SnapshotEntry // in baseline, not present now
}

// DiffAgainstSnapshot compares the current live process list against
// a baseline Snapshot, matching by (Name, Exe, UID) rather than PID.
func DiffAgainstSnapshot(baseline *Snapshot, live []*Process) SnapshotDiff {
	baseSet := make(map[string]bool, len(baseline.Entries))
	for _, e := range baseline.Entries {
		baseSet[e.key()] = true
	}

	liveSet := make(map[string]bool, len(live))
	var diff SnapshotDiff
	for _, p := range live {
		e := SnapshotEntry{Name: p.Name, Exe: p.Exe, UID: p.UID}
		liveSet[e.key()] = true
		if !baseSet[e.key()] {
			diff.New = append(diff.New, e)
		}
	}
	for _, e := range baseline.Entries {
		if !liveSet[e.key()] {
			diff.Missing = append(diff.Missing, e)
		}
	}
	return diff
}
