//go:build linux

// mobilehost plays a phone's ento app on plain Linux, for test/e2e-mobile-networks.sh: the agent of
// package mobile (as the Android app runs it), on a TUN interface this program creates and
// configures as Android's VpnService would (every network's address and range, the routes the
// agent asks for), created again when the networks or routes change.
//
//	mobilehost enroll STATE RECORD WORDS          the first network
//	mobilehost join STATE DOMAIN RECORD WORDS     another network
//	mobilehost run STATE                          the VPN, until killed
//	mobilehost status STATE [DOMAIN]              mobile.Status, as the running app last wrote it
//	mobilehost networks STATE                     mobile.Networks
//	mobilehost leave STATE DOMAIN                 any network ("" for the first, with run stopped)
//	mobilehost exit STATE DOMAIN CHOICE           mobile.SetExit ("" for the first network)
//	mobilehost resolve SERVER NAME                an A query to SERVER (port 53), as an app would
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"entowire.com/ento/mobile"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: mobilehost enroll|join|run|status|networks|leave|exit|resolve ...")
		os.Exit(2)
	}
	var err error
	dir := os.Args[2]
	switch os.Args[1] {
	case "enroll":
		err = mobile.EnrollWords(dir, os.Args[3], os.Args[4], "phone")
	case "join":
		err = mobile.JoinWords(dir, os.Args[3], os.Args[4], os.Args[5], "phone")
	case "status":
		d := ""
		if len(os.Args) > 3 {
			d = os.Args[3]
		}
		// The agent runs in the run process (on a phone, all of it is one app): it writes the
		// status every 2 s.
		b, rerr := os.ReadFile(statusFile(dir, d))
		if rerr != nil {
			err = rerr
			break
		}
		fmt.Println(string(b))
	case "networks":
		fmt.Println(mobile.Networks(dir))
	case "leave":
		err = mobile.Leave(dir, os.Args[3])
	case "exit":
		err = mobile.SetExit(dir, os.Args[3], os.Args[4])
	case "resolve":
		err = resolve(os.Args[2], os.Args[3])
	case "run":
		err = run(dir)
	default:
		err = fmt.Errorf("unknown command %s", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "mobilehost:", err)
		os.Exit(1)
	}
}

func statusFile(dir, domain string) string {
	if domain == "" {
		domain = "first"
	}
	return dir + ".status." + domain + ".json"
}

// writeStatus writes every network's status for `mobilehost status`.
func writeStatus(dir string) {
	var nets []struct {
		Domain string `json:"domain"`
		First  bool   `json:"first"`
	}
	_ = json.Unmarshal([]byte(mobile.Networks(dir)), &nets)
	for _, n := range nets {
		d := n.Domain
		if n.First {
			d = ""
		}
		_ = os.WriteFile(statusFile(dir, d)+".tmp", []byte(mobile.Status(dir, d)), 0o600)
		_ = os.Rename(statusFile(dir, d)+".tmp", statusFile(dir, d))
	}
}

func resolve(server, name string) error {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(ctx, name)
	if err != nil {
		return err
	}
	fmt.Println(strings.Join(addrs, " "))
	return nil
}

type vpnNetwork struct {
	Address    string `json:"address"`
	PrefixBits int    `json:"prefix_bits"`
	Network    string `json:"network"`
}

// vpn is what the VPN is created with: the networks' addresses and ranges, the routes.
type vpn struct {
	nets   []vpnNetwork
	routes []string
}

func (v vpn) key() string {
	b, _ := json.Marshal(v.nets)
	return string(b) + strings.Join(v.routes, ",")
}

func current(dir string, routes []string) (vpn, error) {
	var n struct {
		Networks []vpnNetwork `json:"networks"`
	}
	text := mobile.Network(dir)
	if text == "" {
		return vpn{}, fmt.Errorf("not enrolled")
	}
	if err := json.Unmarshal([]byte(text), &n); err != nil {
		return vpn{}, err
	}
	return vpn{nets: n.Networks, routes: routes}, nil
}

func ip(args ...string) {
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// create makes tun0 as Android's VpnService.Builder would and returns its file descriptor.
func create(v vpn) (int, error) {
	ip("link", "del", "tun0")
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var req [unix.IFNAMSIZ + 64]byte
	copy(req[:], "tun0")
	*(*uint16)(unsafe.Pointer(&req[unix.IFNAMSIZ])) = unix.IFF_TUN | unix.IFF_NO_PI
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req[0]))); e != 0 {
		unix.Close(fd)
		return -1, e
	}
	ip("link", "set", "tun0", "mtu", "1380", "up")
	for _, n := range v.nets {
		ip("addr", "add", fmt.Sprintf("%s/%d", n.Address, n.PrefixBits), "dev", "tun0")
	}
	for _, r := range v.routes {
		ip("route", "replace", r, "dev", "tun0")
	}
	return fd, nil
}

func run(dir string) error {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	mobile.SetUpstreamDNS("10.200.0.1")
	var have vpn
	running := false
	for {
		var routes []string
		if running {
			var s struct {
				Routes []string `json:"routes"`
			}
			_ = json.Unmarshal([]byte(mobile.Status(dir, "")), &s)
			routes = s.Routes
		} else {
			routes = have.routes
		}
		want, err := current(dir, routes)
		if err != nil {
			return err
		}
		if !running || want.key() != have.key() {
			if running {
				fmt.Printf("networks or routes now %s: creating the VPN again\n", want.key())
				mobile.Stop()
			}
			fd, err := create(want)
			if err != nil {
				return err
			}
			if err := mobile.Start(dir, int32(fd), "phone", nil); err != nil {
				return err
			}
			have, running = want, true
			fmt.Printf("VPN up: %s\n", want.key())
		}
		writeStatus(dir)
		select {
		case <-stop:
			mobile.Stop()
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}
