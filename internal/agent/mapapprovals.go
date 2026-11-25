package agent

import (
	"context"
	"sync"

	"entowire.com/ento/internal/api"
)

// Sign-in approvals through the network map (0.34). A quiet device (Config.Quiet, a phone) asks
// for its map with ?approvals=N, the number of approvals it knows wait for its person; the control
// node answers early when that number changes. The app around the agent waits for it here
// (WaitMapApprovals) and fetches the approvals only then, instead of keeping a long poll of its
// own open: one radio wake every long poll instead of two.

// Every network of the app keeps its own (0.60): the app waits for any of them to change.
var mapApprovals struct {
	sync.Mutex
	nets    map[string]mapApprovalState // by the network's state directory
	changed chan struct{}               // closed and replaced on every change
}

type mapApprovalState struct {
	supported bool // its control node fills Self.PendingApprovals
	count     int
}

func init() { mapApprovals.changed = make(chan struct{}) }

// noteMapApprovals records what a network's map says of pending approvals.
func noteMapApprovals(stateDir string, nm api.NetMap) {
	mapApprovals.Lock()
	defer mapApprovals.Unlock()
	want := mapApprovalState{supported: nm.Approvals, count: nm.Self.PendingApprovals}
	if old, ok := mapApprovals.nets[stateDir]; ok && old == want {
		return
	}
	if mapApprovals.nets == nil {
		mapApprovals.nets = map[string]mapApprovalState{}
	}
	mapApprovals.nets[stateDir] = want
	close(mapApprovals.changed)
	mapApprovals.changed = make(chan struct{})
}

// mapApprovalsCount is the number of approvals a network's last map said wait.
func mapApprovalsCount(stateDir string) int {
	mapApprovals.Lock()
	defer mapApprovals.Unlock()
	return mapApprovals.nets[stateDir].count
}

// dropMapApprovals forgets a network left or stopped.
func dropMapApprovals(stateDir string) {
	mapApprovals.Lock()
	defer mapApprovals.Unlock()
	if _, ok := mapApprovals.nets[stateDir]; !ok {
		return
	}
	delete(mapApprovals.nets, stateDir)
	close(mapApprovals.changed)
	mapApprovals.changed = make(chan struct{})
}

// mapApprovalsNow sums the networks: the approvals waiting in all, whether every network's control
// node reports them, and whether any map arrived; the caller holds the lock.
func mapApprovalsNow() (count int, supported, seen bool) {
	supported = true
	for _, s := range mapApprovals.nets {
		count += s.count
		supported = supported && s.supported
		seen = true
	}
	return count, supported && seen, seen
}

// WaitMapApprovals waits until what the networks' maps say of pending approvals differs from
// (last, lastSupported), or ctx ends, and returns the count in all networks, whether every
// network's control node reports it (else the app asks for approvals itself) and whether a map
// arrived yet.
func WaitMapApprovals(ctx context.Context, last int, lastSupported bool) (count int, supported, seen bool) {
	for {
		mapApprovals.Lock()
		count, supported, seen = mapApprovalsNow()
		ch := mapApprovals.changed
		mapApprovals.Unlock()
		if seen && (count != last || supported != lastSupported) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ch:
		}
	}
}
