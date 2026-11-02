package agent

import (
	"net"
	"strings"
	"testing"
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
