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

// The device's own interface outlives the agent: its port is in use by it, and a restart keeps that
// port (0.62.2) instead of moving to the next free one and back at the restart after (which broke
// plain WireGuard peers' configurations). A port it could not have chosen is not kept.
func TestChooseListenPortOwnInterface(t *testing.T) {
	old := ownListenPort
	defer func() { ownListenPort = old }()
	busy, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := busy.LocalAddr().(*net.UDPAddr).Port // held by the interface itself
	quiet := func(string, ...any) {}
	for _, c := range []struct {
		own, want int
		exists    bool
	}{
		{own: port, want: port, exists: true},         // the interface holds the port asked for
		{own: port + 1, want: port + 1, exists: true}, // it moved there once: it stays
	} {
		ownListenPort = func(string) (int, bool) { return c.own, c.exists }
		cfg := Config{ListenPort: port, Interface: "ento0", Logf: quiet}
		ChooseListenPort(&cfg)
		if cfg.ListenPort != c.want {
			t.Fatalf("own interface on %d: chose %d, want %d", c.own, cfg.ListenPort, c.want)
		}
	}
	// An interface on a port this choice could not give (another --listen-port): the usual choice.
	ownListenPort = func(string) (int, bool) { return port + 500, true }
	cfg := Config{ListenPort: port, Interface: "ento0", Logf: quiet}
	ChooseListenPort(&cfg)
	if cfg.ListenPort == port+500 || cfg.ListenPort == port {
		t.Fatalf("chose %d", cfg.ListenPort)
	}
}
