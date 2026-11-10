package agent

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Another WireGuard client holding the port: the agent takes the next free one, and says so.
func TestChooseListenPort(t *testing.T) {
	busy, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := busy.LocalAddr().(*net.UDPAddr).Port
	var logged []string
	cfg := Config{ListenPort: port, Logf: func(f string, a ...any) { logged = append(logged, f) }}
	ChooseListenPort(&cfg)
	if cfg.ListenPort == port || cfg.ListenPort > port+100 {
		t.Fatalf("kept the busy port %d or went too far: %d", port, cfg.ListenPort)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "in use") {
		t.Fatalf("not said: %q", logged)
	}
	// A free port is kept, silently.
	free := cfg.ListenPort
	logged = nil
	cfg2 := Config{ListenPort: free, Logf: cfg.Logf}
	ChooseListenPort(&cfg2)
	if cfg2.ListenPort != free || len(logged) != 0 {
		t.Fatalf("a free port was changed: %d -> %d (%q)", free, cfg2.ListenPort, logged)
	}
}

// Inside WSL the default port moves off Windows' 51830; an explicit other port stays.
func TestChooseListenPortWSL(t *testing.T) {
	old := inWSL
	defer func() { inWSL = old }()
	inWSL = func() bool { return true }
	cfg := Config{ListenPort: DefaultListenPort, Logf: func(string, ...any) {}}
	ChooseListenPort(&cfg)
	if cfg.ListenPort < WSLListenPort || cfg.ListenPort > WSLListenPort+100 {
		t.Fatalf("inside WSL: port %d, want %d (or the next free)", cfg.ListenPort, WSLListenPort)
	}
	busy, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	busy.Close()
	other := busy.LocalAddr().(*net.UDPAddr).Port
	cfg = Config{ListenPort: other, Logf: func(string, ...any) {}}
	ChooseListenPort(&cfg)
	if cfg.ListenPort != other {
		t.Fatalf("an explicit port was moved: %d -> %d", other, cfg.ListenPort)
	}
}

// A relay port held elsewhere (WSL's mirrored networking) leaves the agent running without the
// relay: relayed peers keep their direct endpoint instead of the agent stopping.
func TestRelayerPortTaken(t *testing.T) {
	var logged []string
	r, err := newRelayer(netip.MustParseAddr("127.0.0.1"), 51830, func(f string, a ...any) { logged = append(logged, f) },
		func(*net.UDPAddr) (*net.UDPConn, error) { return nil, syscall.EADDRINUSE })
	if err != nil {
		t.Fatalf("newRelayer: %v", err)
	}
	defer r.Close()
	if _, err := r.Endpoint(wgtypes.Key{}); !errors.Is(err, errNoRelay) {
		t.Fatalf("Endpoint: %v, want errNoRelay", err)
	}
	if len(logged) != 1 {
		t.Fatalf("not said: %q", logged)
	}
}
