package proc

import "sort"

// TreeNode is a Process plus its direct children, for `procsec tree`.
type TreeNode struct {
	Process  *Process
	Children []*TreeNode
}

// BuildTree turns a flat process list into a forest of TreeNodes
// rooted at PID 1 (and any orphaned subtrees whose parent isn't in
// the list — e.g. because we raced a scan, or the parent is in a
// different PID namespace we can't see). Roots are returned sorted
// by PID for stable output.
func BuildTree(procs []*Process) []*TreeNode {
	byPID := make(map[int]*TreeNode, len(procs))
	for _, p := range procs {
		byPID[p.PID] = &TreeNode{Process: p}
	}

	var roots []*TreeNode
	for _, p := range procs {
		node := byPID[p.PID]
		parent, ok := byPID[p.PPID]
		if !ok || p.PPID == p.PID || p.PPID == 0 {
			roots = append(roots, node)
			continue
		}
		parent.Children = append(parent.Children, node)
	}

	sortTree(roots)
	return roots
}

func sortTree(nodes []*TreeNode) {
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Process.PID < nodes[j].Process.PID })
	for _, n := range nodes {
		sortTree(n.Children)
	}
}

// SubtreeAt returns the TreeNode for pid and everything beneath it,
// built from the full process list so ancestry/descendant
// relationships are correct even when pid isn't a top-level root.
// Returns nil if pid isn't present in procs (e.g. it already exited).
func SubtreeAt(procs []*Process, pid int) *TreeNode {
	byPID := make(map[int]*TreeNode, len(procs))
	for _, p := range procs {
		byPID[p.PID] = &TreeNode{Process: p}
	}
	for _, p := range procs {
		if parent, ok := byPID[p.PPID]; ok && p.PPID != p.PID {
			parent.Children = append(parent.Children, byPID[p.PID])
		}
	}
	for _, node := range byPID {
		sortTree(node.Children)
	}
	return byPID[pid]
}

// from procs, returning the chain from immediate parent to root.
// Used for `procsec inspect` to show "who spawned this and from
// where" (design doc: ancestry chain, common for spotting a shell
// spawned by an unexpected parent — e.g. a web server spawning bash).
func Ancestors(procs []*Process, pid int) []*Process {
	byPID := make(map[int]*Process, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}

	var chain []*Process
	cur, ok := byPID[pid]
	if !ok {
		return nil
	}
	seen := map[int]bool{pid: true}
	for {
		parent, ok := byPID[cur.PPID]
		if !ok || seen[parent.PID] {
			break
		}
		chain = append(chain, parent)
		seen[parent.PID] = true
		cur = parent
		if cur.PID == 1 {
			break
		}
	}
	return chain
}
