package security

// SeccompState renders the numeric Seccomp field from /proc/<pid>/status
// into a human-readable mode name.
func SeccompState(mode int) string {
	switch mode {
	case 0:
		return "disabled"
	case 1:
		return "strict"
	case 2:
		return "filter"
	default:
		return "unknown"
	}
}
