//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// Linked networks live in named network namespaces (/run/netns/<name>, usable with
// `ip netns exec <name> ...`). Their WireGuard interface is created in the agent's own namespace,
// so its UDP socket uses the host's connectivity, and then moved into the linked network's
// namespace, where its routes and addresses live.

const (
	netnsDir     = "/run/netns"
	netnsEtcDir  = "/etc/netns"
	netnsPrefix  = "ento-"
	netnsUnitFmt = "ento-netns@%s.service"
)

func nsEnv(ns netns.NsHandle) netEnv {
	return netEnv{ns: ns, listenUDP: listenUDPIn(ns), http: &http.Client{
		Timeout:   httpClient.Timeout,
		Transport: &http.Transport{DialContext: dialIn(ns)},
	}, open: func(cfg Config) (tunnel, error) {
		return OpenIfaceIn(ns, cfg.Interface, cfg.ListenPort, cfg.MTU)
	}}
}

// LinkHTTPClient returns an HTTP client whose connections are made inside a linked network's
// namespace (administering that network from this device), and a function that releases it.
func LinkHTTPClient(link string) (*http.Client, func(), error) {
	ns, err := openNamespace(link)
	if err != nil {
		return nil, nil, fmt.Errorf("linked network %s: %w", link, err)
	}
	return nsEnv(ns).http, func() { ns.Close() }, nil
}

// CreateNamespace creates the named namespace of a linked network if it does not exist.
func CreateNamespace(link string) error {
	name := NamespaceName(link)
	if h, err := netns.GetFromName(name); err == nil {
		h.Close()
		return nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		return err
	}
	defer orig.Close()
	h, err := netns.NewNamed(name) // also switches this thread into it
	if err != nil {
		return fmt.Errorf("create namespace %s: %w", name, err)
	}
	defer h.Close()
	// Loopback up, so local services and the resolver fallback behave.
	if lo, err := netlink.LinkByName("lo"); err == nil {
		_ = netlink.LinkSetUp(lo)
	}
	return netns.Set(orig)
}

// DeleteNamespace removes the named namespace of a linked network and its /etc/netns files.
func DeleteNamespace(link string) error {
	name := NamespaceName(link)
	_ = os.RemoveAll(filepath.Join(netnsEtcDir, name))
	if err := netns.DeleteNamed(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// underSystemd reports whether the agent runs as a systemd service. Its mount namespace is then
// private, so namespaces it created would be invisible to the rest of the system: they are
// created by the ento-netns@ template unit instead.
func underSystemd() bool { return os.Getenv("INVOCATION_ID") != "" }

// openNamespace makes sure a linked network's namespace exists and returns a handle to it.
func openNamespace(link string) (netns.NsHandle, error) {
	name := NamespaceName(link)
	if h, err := netns.GetFromName(name); err == nil {
		return h, nil
	}
	if underSystemd() {
		if err := systemctl("start", fmt.Sprintf(netnsUnitFmt, link)); err != nil {
			return netns.None(), err
		}
		// The bind mount made outside propagates into this service's mount namespace.
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if h, err := netns.GetFromName(name); err == nil {
				return h, nil
			}
			time.Sleep(100 * time.Millisecond)
		}
		return netns.None(), fmt.Errorf("namespace %s did not appear", name)
	}
	if err := CreateNamespace(link); err != nil {
		return netns.None(), err
	}
	return netns.GetFromName(name)
}

// closeNamespace removes a linked network's namespace (through the template unit when under
// systemd).
func closeNamespace(link string) error {
	if underSystemd() {
		_ = os.RemoveAll(filepath.Join(netnsEtcDir, NamespaceName(link)))
		return systemctl("stop", fmt.Sprintf(netnsUnitFmt, link))
	}
	return DeleteNamespace(link)
}

// inNamespace runs fn with the calling thread in namespace h. Sockets created by fn stay in h.
// netns.None() means the agent's own namespace.
func inNamespace(h netns.NsHandle, fn func() error) error {
	if !h.IsOpen() {
		return fn()
	}
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		return err
	}
	defer orig.Close()
	if err := netns.Set(h); err != nil {
		runtime.UnlockOSThread()
		return err
	}
	ferr := fn()
	if err := netns.Set(orig); err != nil {
		// Leave the thread locked: it ends with the goroutine instead of serving others in the
		// wrong namespace.
		return errors.Join(ferr, err)
	}
	runtime.UnlockOSThread()
	return ferr
}

// dialIn dials from inside namespace h.
func dialIn(h netns.NsHandle) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var c net.Conn
		err := inNamespace(h, func() error {
			var err error
			c, err = (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
			return err
		})
		return c, err
	}
}

// listenUDPIn binds a UDP socket inside namespace h.
func listenUDPIn(h netns.NsHandle) func(laddr *net.UDPAddr) (*net.UDPConn, error) {
	return func(laddr *net.UDPAddr) (*net.UDPConn, error) {
		var c *net.UDPConn
		err := inNamespace(h, func() error {
			var err error
			c, err = net.ListenUDP("udp4", laddr)
			return err
		})
		return c, err
	}
}

// writeHosts publishes the linked network's peers as /etc/netns/<ns>/hosts, which
// `ip netns exec` shows to processes as /etc/hosts. Names are reduced to hostname-safe characters.
func writeHosts(link string, entries map[string][]string) error {
	dir := filepath.Join(netnsEtcDir, NamespaceName(link))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# Written by ento: the peers of linked network " + link + ".\n")
	b.WriteString("127.0.0.1\tlocalhost\n::1\tlocalhost\n")
	// This device's own name, which tools like sudo look up.
	if self, err := os.Hostname(); err == nil && hostLabel(self) != "" {
		b.WriteString("127.0.1.1\t" + self + "\n")
	}
	for _, name := range sortedKeys(entries) {
		for _, addr := range entries[name] {
			b.WriteString(addr + "\t" + name + "\n")
		}
	}
	path := filepath.Join(dir, "hosts")
	if old, err := os.ReadFile(path); err == nil && string(old) == b.String() {
		return nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// hostLabel reduces a hostname to characters valid in /etc/hosts.
func hostLabel(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			b.WriteRune(r)
		}
	}
	return strings.Trim(b.String(), ".-")
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
