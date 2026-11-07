// Package agent runs on every device: it enrolls with a token, configures a WireGuard interface
// and keeps it in sync with the network map served by the control plane.
package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
)

// State is what an enrolled agent persists. It contains the private key and is written with
// mode 0600.
type State struct {
	PrivateKey Key           `json:"private_key"`
	Address    netip.Addr    `json:"address"`
	Network    netip.Prefix  `json:"network"`
	Controls   []api.Control `json:"controls"`
	// RecordDomain is the domain whose network record names the control nodes, from the network
	// map (moved.go).
	RecordDomain string `json:"record_domain,omitempty"`
	// KeyCreatedAt is when PrivateKey was made (zero: before 0.31): a device with a bound hardware
	// key changes it daily. NextPrivateKey is the key a change was asked for with, kept until the
	// control plane's answer is known (hwkey.go).
	KeyCreatedAt   time.Time `json:"key_created_at,omitzero"`
	NextPrivateKey *Key      `json:"next_private_key,omitempty"`
}

const stateFile = "state.json"

// Key is a WireGuard key that serialises as base64 text.
type Key wgtypes.Key

func (k Key) MarshalText() ([]byte, error) { return []byte(wgtypes.Key(k).String()), nil }

func (k *Key) UnmarshalText(b []byte) error {
	parsed, err := wgtypes.ParseKey(string(b))
	if err != nil {
		return err
	}
	*k = Key(parsed)
	return nil
}

// ErrNotEnrolled is returned when no state exists yet.
var ErrNotEnrolled = errors.New("not enrolled")

// LoadState reads the state from dir.
func LoadState(dir string) (State, error) {
	var s State
	b, err := os.ReadFile(filepath.Join(dir, stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return s, ErrNotEnrolled
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("corrupt state: %w", err)
	}
	return s, nil
}

// SaveState writes the state atomically.
func SaveState(dir string, s State) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := protectStateDir(dir); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, stateFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, stateFile))
}

// Running describes the agent process currently serving a state directory. CLI commands that hand
// work to it (linked networks) check it first.
type Running struct {
	Version string `json:"version"`
	PID     int    `json:"pid"`
	Links   bool   `json:"links"` // handles linked network requests
	// Networks: joins and leaves networks besides the first (networks.go, 0.51).
	Networks bool `json:"networks,omitempty"`
	// Interface is the home network's interface as the system names it (macOS: utunN).
	Interface string `json:"interface,omitempty"`
	// LoginRequired: the home network ended this device's SSO session; `ento agent login`.
	LoginRequired bool `json:"login_required,omitempty"`
	// HardwareKey says whether the device has a hardware-held key and whether it is bound (0.31);
	// KeyCreatedAt when its WireGuard key was made (RFC 3339).
	HardwareKey  string `json:"hardware_key,omitempty"`
	KeyCreatedAt string `json:"key_created_at,omitempty"`
	// User and UserName: the person the home network has the device bound to by single sign-on
	// (api.Self), as the control plane says; `ento agent whoami`.
	User     string `json:"user,omitempty"`
	UserName string `json:"user_name,omitempty"`
	// Routes are the routes' networks this device reaches through gateways now; Serves those it
	// forwards to as a gateway.
	Routes []string `json:"routes,omitempty"`
	Serves []string `json:"serves,omitempty"`
	// Exits are the exits offered to this device (which one is in use); ExitFor: it is an exit.
	Exits   []RunningExit `json:"exits,omitempty"`
	ExitFor bool          `json:"exit_for,omitempty"`
	// DNSDomain is the network's internal DNS domain, answered by the agent's resolver at Resolver.
	DNSDomain string `json:"dns_domain,omitempty"`
	Resolver  string `json:"resolver,omitempty"`
	// PersonActive: the person layer is open, since PersonSince (as the control plane names it).
	PersonActive bool   `json:"person_active,omitempty"`
	PersonSince  string `json:"person_since,omitempty"`
	// Posture is the device's latest posture report the home network took, at PostureReportedAt
	// (RFC 3339), and PostureFailing the checks it fails there.
	Posture           *api.Posture         `json:"posture,omitempty"`
	PostureReportedAt string               `json:"posture_reported_at,omitempty"`
	PostureFailing    []api.PostureFailure `json:"posture_failing,omitempty"`
	// FilterFailed says why the inbound filter could not be applied (0.51): until it can, the
	// device's only peers are its control nodes.
	FilterFailed string `json:"filter_failed,omitempty"`
}

const runningFile = "agent.json"

func writeRunning(cfg Config, r Running) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp := filepath.Join(cfg.StateDir, runningFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(cfg.StateDir, runningFile))
}

// RunningAgent returns the agent serving stateDir, if one is running and has announced itself.
func RunningAgent(stateDir string) (Running, bool) {
	var r Running
	b, err := os.ReadFile(filepath.Join(stateDir, runningFile))
	if err != nil || json.Unmarshal(b, &r) != nil || r.PID <= 0 {
		return r, false
	}
	return r, processAlive(r.PID)
}
