package security

// capNames maps Linux capability bit positions to their cap_* names,
// per include/uapi/linux/capability.h. This list is current as of
// recent kernels (up to CAP_CHECKPOINT_RESTORE = 40); unknown higher
// bits are rendered as "cap_unknown_N" rather than dropped, so a
// newer kernel doesn't silently hide capabilities from the operator.
var capNames = map[uint]string{
	0:  "cap_chown",
	1:  "cap_dac_override",
	2:  "cap_dac_read_search",
	3:  "cap_fowner",
	4:  "cap_fsetid",
	5:  "cap_kill",
	6:  "cap_setgid",
	7:  "cap_setuid",
	8:  "cap_setpcap",
	9:  "cap_linux_immutable",
	10: "cap_net_bind_service",
	11: "cap_net_broadcast",
	12: "cap_net_admin",
	13: "cap_net_raw",
	14: "cap_ipc_lock",
	15: "cap_ipc_owner",
	16: "cap_sys_module",
	17: "cap_sys_rawio",
	18: "cap_sys_chroot",
	19: "cap_sys_ptrace",
	20: "cap_sys_pacct",
	21: "cap_sys_admin",
	22: "cap_sys_boot",
	23: "cap_sys_nice",
	24: "cap_sys_resource",
	25: "cap_sys_time",
	26: "cap_sys_tty_config",
	27: "cap_mknod",
	28: "cap_lease",
	29: "cap_audit_write",
	30: "cap_audit_control",
	31: "cap_setfcap",
	32: "cap_mac_override",
	33: "cap_mac_admin",
	34: "cap_syslog",
	35: "cap_wake_alarm",
	36: "cap_block_suspend",
	37: "cap_audit_read",
	38: "cap_perfmon",
	39: "cap_bpf",
	40: "cap_checkpoint_restore",
}

// capsOfInterest lists capabilities that are especially significant
// for privilege escalation, so the "security" view can highlight
// them without printing all 40 bits every time. This is not an
// exhaustive escalation guide — it's a spotlight, not a verdict.
var capsOfInterest = []string{
	"cap_setuid",
	"cap_setgid",
	"cap_dac_override",
	"cap_dac_read_search",
	"cap_sys_admin",
	"cap_sys_ptrace",
	"cap_sys_module",
	"cap_sys_rawio",
	"cap_net_raw",
	"cap_net_admin",
	"cap_setpcap",
	"cap_mac_admin",
	"cap_mac_override",
}

// DecodeCapabilities turns a capability bitmask (as read from e.g.
// CapEff in /proc/<pid>/status) into a sorted-by-bit list of cap_*
// names. An empty/zero mask yields an empty (non-nil) slice.
func DecodeCapabilities(mask uint64) []string {
	names := make([]string, 0)
	for bit := uint(0); bit < 64; bit++ {
		if mask&(1<<bit) == 0 {
			continue
		}
		if name, ok := capNames[bit]; ok {
			names = append(names, name)
		} else {
			names = append(names, unknownCapName(bit))
		}
	}
	return names
}

// HasFullCapabilitySet reports whether mask has every currently-known
// capability bit set — the common signature of a root/CAP_SYS_ADMIN-ish
// process with no capability dropping applied at all (e.g. CapBnd on
// an unconfigured root process). Useful as a quick "nothing was
// restricted here" signal in the security view.
func HasFullCapabilitySet(mask uint64) bool {
	var full uint64
	for bit := range capNames {
		full |= 1 << bit
	}
	return mask&full == full
}

// InterestingCapabilities filters a decoded capability list down to
// the subset in capsOfInterest, preserving input order. Intended for
// the flagship `security`/`inspect --security` view so the operator
// sees the escalation-relevant caps first without hand-parsing 40
// bit names.
func InterestingCapabilities(names []string) []string {
	set := make(map[string]struct{}, len(capsOfInterest))
	for _, c := range capsOfInterest {
		set[c] = struct{}{}
	}
	out := make([]string, 0)
	for _, n := range names {
		if _, ok := set[n]; ok {
			out = append(out, n)
		}
	}
	return out
}

func unknownCapName(bit uint) string {
	return "cap_unknown_" + itoa(bit)
}

// itoa avoids importing strconv just for this one conversion path;
// kept tiny and local since it's only ever used for unknown high bits.
func itoa(n uint) string {
	if n == 0 {
		return "0"
	}
	var buf [3]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
