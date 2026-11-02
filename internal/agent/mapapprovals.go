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

var mapApprovals struct {
	sync.Mutex
	seen      bool // a map arrived
	supported bool // its control node fills Self.PendingApprovals
	count     int
	changed   chan struct{} // closed and replaced on every change
}

func init() { mapApprovals.changed = make(chan struct{}) }

func mapApprovalsCount() int {
	mapApprovals.Lock()
	defer mapApprovals.Unlock()
	return mapApprovals.count
}

// noteMapApprovals records what a network map says of pending approvals.
func noteMapApprovals(nm api.NetMap) {
	mapApprovals.Lock()
	defer mapApprovals.Unlock()
	if mapApprovals.seen && mapApprovals.supported == nm.Approvals && mapApprovals.count == nm.Self.PendingApprovals {
		return
	}
	mapApprovals.seen, mapApprovals.supported, mapApprovals.count = true, nm.Approvals, nm.Self.PendingApprovals
	close(mapApprovals.changed)
	mapApprovals.changed = make(chan struct{})
}

// WaitMapApprovals waits until what the network map says of pending approvals differs from
// (last, lastSupported), or ctx ends, and returns the count, whether the control node reports it at
// all (else the app asks for approvals itself) and whether a map arrived yet.
func WaitMapApprovals(ctx context.Context, last int, lastSupported bool) (count int, supported, seen bool) {
	for {
		mapApprovals.Lock()
		count, supported, seen = mapApprovals.count, mapApprovals.supported, mapApprovals.seen
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
