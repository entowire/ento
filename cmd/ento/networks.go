package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"entowire.com/ento/internal/agent"
	"entowire.com/ento/internal/token"
)

// Several networks on one device (0.51, Linux): `ento agent join DOMAIN` and `leave DOMAIN`, and
// --network DOMAIN on the commands that act for one network (internal/agent/networks.go).

// networkFlag adds --network to a command that acts for one of the device's networks.
func networkFlag(fs *flag.FlagSet) *string {
	return fs.String("network", "", "the network this is for, by its domain, on a device in several (default: the first; ento agent status lists them)")
}

// useNetwork points cfg at the network with domain ("" for the first): its state directory and, for
// a joined network, its interface and port.
func useNetwork(cfg *agent.Config, domain string) error {
	dir, err := agent.NetworkStateDir(cfg.StateDir, domain)
	if err != nil {
		return err
	}
	if dir == cfg.StateDir {
		return nil
	}
	m, err := agent.LoadMembership(cfg.StateDir, strings.ToLower(strings.TrimSuffix(domain, ".")))
	if err != nil {
		return err
	}
	cfg.StateDir, cfg.Interface, cfg.ListenPort = dir, m.Interface, m.ListenPort
	return nil
}

// networkName is the domain the device knows a network by, for what a command says ("" for none).
func networkName(cfg *agent.Config, domain string) string {
	if domain != "" {
		return strings.ToLower(strings.TrimSuffix(domain, "."))
	}
	return agent.FirstDomain(cfg.StateDir)
}

// severalNetworks reports whether the device is in more than one network (joined, not linked).
func severalNetworks(stateDir string) bool { return len(agent.Networks(stateDir)) > 0 }

func joinCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("agent join", flag.ExitOnError)
	cfg := agentFlags(fs)
	record := fs.String("record", "", "the network record's text itself, not looked up in DNS")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: ento agent join DOMAIN (asks for the words an administrator of that network reads out)")
	}
	domain := strings.ToLower(strings.TrimSuffix(fs.Arg(0), "."))
	if !agent.ValidDomain(domain) {
		return fmt.Errorf("%q is not a network's domain", fs.Arg(0))
	}
	if os.Geteuid() != 0 {
		return errors.New("join must run as root (sudo): the agent's state is root's")
	}
	r, ok := agent.RunningAgent(cfg.StateDir)
	switch {
	case !ok:
		if _, err := agent.LoadState(cfg.StateDir); err != nil {
			return errors.New("this device is in no network yet: join the first with `ento agent install --join " + domain + "`")
		}
		return errors.New("the agent is not running: `ento agent up` first")
	case !r.Networks:
		return fmt.Errorf("the running agent (%s) joins no more networks: restart it on this release (sudo systemctl restart ento-agent) and try again", r.Version)
	}
	firstPort := cfg.ListenPort
	j := joinFlags{domain: &domain, record: record}
	tok, rec, err := joinTokenChecked(ctx, j, func(rec token.Record) error {
		return agent.CheckJoin(cfg.StateDir, domain, rec.Network)
	})
	if err != nil {
		return err
	}
	m, err := agent.RequestJoin(cfg.StateDir, domain, rec.Network, tok, r.Interface, firstPort)
	if err != nil {
		return err
	}
	dir := agent.NetworkDir(cfg.StateDir, domain)
	fmt.Printf("joining %s on %s", domain, m.Interface)
	for i := 0; i < 180 && ctx.Err() == nil; i++ {
		if st, err := agent.LoadState(dir); err == nil {
			fmt.Printf("\n\njoined %s as %s on %s\n", domain, st.Address, m.Interface)
			fmt.Printf("commands for it take --network %s, e.g. sudo ento agent login --network %s\n", domain, domain)
			return nil
		}
		if e := agent.JoinError(cfg.StateDir, domain); e != "" {
			fmt.Println()
			// The words are used up or wrong: nothing to retry with.
			_ = os.RemoveAll(dir)
			return fmt.Errorf("joining %s failed: %s", domain, e)
		}
		fmt.Print(".")
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("\nthe agent has not joined %s yet: it keeps trying (ento agent status shows it; ento agent leave %s gives up)", domain, domain)
}

func leaveCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("agent leave", flag.ExitOnError)
	cfg := agentFlags(fs)
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: ento agent leave DOMAIN")
	}
	domain := strings.ToLower(strings.TrimSuffix(fs.Arg(0), "."))
	if err := agent.RequestLeave(cfg.StateDir, domain); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return errors.New("leave must run as root (sudo)")
		}
		return err
	}
	if _, ok := agent.RunningAgent(cfg.StateDir); !ok {
		// Nobody acts on the request: the agent does when it starts.
		fmt.Printf("the agent is not running: it leaves %s when it starts\n", domain)
		return nil
	}
	for i := 0; i < 60 && ctx.Err() == nil; i++ {
		if _, err := os.Stat(agent.NetworkDir(cfg.StateDir, domain)); errors.Is(err, os.ErrNotExist) {
			fmt.Printf("left %s on this device; it stays in that network's list until an administrator there deletes it\n", domain)
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("the agent did not act on the request (ento agent status, and the service's log)")
}

// networksStatus lists the device's networks when it is in more than one, for `ento agent status`.
func networksStatus(stateDir string, shown string) error {
	domains := agent.Networks(stateDir)
	if len(domains) == 0 {
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "\nNETWORK\tINTERFACE\tADDRESS\tSTATE")
	row := func(domain, dir, iface string) {
		mark := ""
		if domain == shown {
			mark = " (shown above)"
		}
		st, err := agent.LoadState(dir)
		r, running := agent.RunningAgent(dir)
		if running && r.Interface != "" {
			iface = r.Interface
		}
		switch {
		case err == nil && running && r.LoginRequired:
			fmt.Fprintf(w, "%s\t%s\t%s\tsession ended: ento agent login --network %s%s\n", cell(domain), iface, st.Address, domain, mark)
		case err == nil && running:
			fmt.Fprintf(w, "%s\t%s\t%s\tup%s\n", cell(domain), iface, st.Address, mark)
		case err == nil:
			fmt.Fprintf(w, "%s\t%s\t%s\tnot running%s\n", cell(domain), iface, st.Address, mark)
		case agent.JoinError(stateDir, domain) != "":
			fmt.Fprintf(w, "%s\t%s\t-\tjoin failed: %s\n", cell(domain), iface, cell(agent.JoinError(stateDir, domain)))
		default:
			fmt.Fprintf(w, "%s\t%s\t-\tjoining\n", cell(domain), iface)
		}
	}
	first := agent.FirstDomain(stateDir)
	if first == "" {
		first = "(first)"
	}
	row(first, stateDir, "-")
	for _, d := range domains {
		m, err := agent.LoadMembership(stateDir, d)
		if err != nil {
			continue
		}
		row(d, agent.NetworkDir(stateDir, d), m.Interface)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Println("(the first network's exits and releases are the device's; ento agent status --network DOMAIN shows another)")
	return nil
}

// approvalsEveryNetwork lists the sign-ins waiting for the person's approval in each of the
// device's networks, each under its network's name.
func approvalsEveryNetwork(ctx context.Context, cfg agent.Config, wait time.Duration) error {
	base := cfg.StateDir
	domains := append([]string{""}, agent.Networks(base)...)
	found := false
	for _, d := range domains {
		c := cfg
		if err := useNetwork(&c, d); err != nil {
			continue
		}
		name := networkName(&agent.Config{StateDir: base}, d)
		list, err := agent.PendingApprovals(ctx, c, wait)
		if err != nil {
			fmt.Printf("%s: %v\n", name, err)
			continue
		}
		for _, a := range list {
			found = true
			flag := ""
			if d != "" {
				flag = " --network " + d
			}
			fmt.Printf("%s: %s  %s on %s (%s), numbers %v, until %s (answer%s)\n", name, a.ID, a.User, a.Device, a.Service, a.Choices, a.ExpiresAt, flag)
		}
	}
	if !found {
		fmt.Println("no sign-in waits for your approval")
		return nil
	}
	fmt.Println("answer with: ento agent approvals answer [--network DOMAIN] ID NUMBER (the number the device shows; answer --deny ID NUMBER refuses)")
	return nil
}
