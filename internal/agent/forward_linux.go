//go:build linux

package agent

import (
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/vishvananda/netns"

	"entowire.com/ento/internal/api"
)

// Services of the home network forwarded into a linked network's namespace (api.NetMap.LinkForwards).
// Each forwarded name gets a loopback address of the namespace (127.2.X.Y, from a hash of the name,
// so adding or removing a forward moves no other name's address), written into its hosts
// file; the agent listens there and carries every connection, from the home side, to one of the
// service's targets. Nothing is routed between the networks: only processes inside the namespace
// on this device can open such a connection (the namespace firewall drops anything arriving from
// the linked network), and only to the services the home network names.

const maxForwardNames = 250

// forwarder keeps the listeners of one linked namespace in line with the home network's forwards.
type forwarder struct {
	ns   netns.NsHandle
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	logf func(string, ...any)

	mu        sync.Mutex
	current   []api.Forward
	names     map[string]string       // forwarded name -> loopback address in the namespace
	listeners map[string]net.Listener // loopback address:port -> listener
	targets   map[string][]string     // loopback address:port -> targets
}

func newForwarder(ns netns.NsHandle, dial func(context.Context, string, string) (net.Conn, error), logf func(string, ...any)) *forwarder {
	return &forwarder{ns: ns, dial: dial, logf: logf, names: map[string]string{},
		listeners: map[string]net.Listener{}, targets: map[string][]string{}}
}

// validForwards keeps the forwards that name a service of the home network (targets inside it).
func validForwards(fs []api.Forward, home netip.Prefix) []api.Forward {
	var out []api.Forward
	for _, f := range fs {
		if hostLabel(f.Name) != f.Name || !slices.Contains([]byte(f.Name), '.') || f.Port < 1 || f.Port > 65535 {
			continue
		}
		g := api.Forward{Name: f.Name, Port: f.Port}
		for _, t := range f.Targets {
			if ap, err := netip.ParseAddrPort(t); err == nil && home.Contains(ap.Addr()) {
				g.Targets = append(g.Targets, ap.String())
			}
		}
		if len(g.Targets) > 0 {
			out = append(out, g)
		}
	}
	return out
}

// forwardSlots is the number of loopback addresses for forwarded names: 127.2.0.1 to 127.2.255.254.
const forwardSlots = 256 * 254

// forwardNames assigns every forwarded name a loopback address derived from the name alone (FNV-1a),
// so a browser that already resolved one keeps a valid address when other forwards come and go.
// Two names on the same address are resolved in name order: the later one takes the next free slot.
func forwardNames(fs []api.Forward) map[string]string {
	var names []string
	for _, f := range fs {
		if !slices.Contains(names, f.Name) {
			names = append(names, f.Name)
		}
	}
	slices.Sort(names)
	if len(names) > maxForwardNames {
		names = names[:maxForwardNames]
	}
	used := map[uint32]bool{}
	out := map[string]string{}
	for _, n := range names {
		h := fnv.New32a()
		h.Write([]byte(n))
		slot := h.Sum32() % forwardSlots
		for used[slot] {
			slot = (slot + 1) % forwardSlots
		}
		used[slot] = true
		out[n] = fmt.Sprintf("127.2.%d.%d", slot/254, slot%254+1)
	}
	return out
}

// apply opens and closes listeners for a new set of forwards; it reports whether the forwarded
// names changed (the hosts file must be rewritten).
func (f *forwarder) apply(fs []api.Forward) (namesChanged bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if slices.EqualFunc(fs, f.current, func(a, b api.Forward) bool {
		return a.Name == b.Name && a.Port == b.Port && slices.Equal(a.Targets, b.Targets)
	}) {
		return false
	}
	f.current = fs
	names := forwardNames(fs)
	want := map[string][]string{}
	for _, fw := range fs {
		if addr, ok := names[fw.Name]; ok {
			want[net.JoinHostPort(addr, strconv.Itoa(fw.Port))] = fw.Targets
		}
	}
	for key, l := range f.listeners {
		if _, ok := want[key]; !ok {
			l.Close()
			delete(f.listeners, key)
		}
	}
	f.targets = want
	for key := range want {
		if _, ok := f.listeners[key]; ok {
			continue
		}
		var l net.Listener
		err := inNamespace(f.ns, func() error {
			var err error
			l, err = net.Listen("tcp4", key)
			return err
		})
		if err != nil {
			f.logf("forward %s: %v", key, err)
			continue
		}
		f.listeners[key] = l
		go f.serve(l, key)
	}
	namesChanged = !mapsEqual(names, f.names)
	f.names = names
	return namesChanged
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// hostNames returns the forwarded names and their loopback addresses.
func (f *forwarder) hostNames() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]string, len(f.names))
	for k, v := range f.names {
		out[k] = v
	}
	return out
}

func (f *forwarder) serve(l net.Listener, key string) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		targets := f.targets[key]
		f.mu.Unlock()
		go f.carry(c, targets)
	}
}

// carry connects c to the first target that answers and copies both ways until either side ends.
func (f *forwarder) carry(c net.Conn, targets []string) {
	defer c.Close()
	var up net.Conn
	for _, t := range targets {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := f.dial(ctx, "tcp4", t)
		cancel()
		if err == nil {
			up = conn
			break
		}
	}
	if up == nil {
		f.logf("forward %s: no target reachable (%v)", c.LocalAddr(), targets)
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(up, c)
	go pipe(c, up)
	<-done
	<-done
}

// close stops all listeners.
func (f *forwarder) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for key, l := range f.listeners {
		l.Close()
		delete(f.listeners, key)
	}
}
