//go:build linux && !android

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"entowire.com/ento/internal/api"
)

// collectPlatform finds out the posture of a Linux system: kernel release and distribution, whether
// the root file system is on dm-crypt (LUKS), whether the input path is filtered (nftables, or
// legacy iptables), Secure Boot from its EFI variable, and whether a known real-time anti-malware
// scanner runs (unknown when none does). Screen lock stays unknown.
func collectPlatform(ctx context.Context) api.Posture {
	p := linuxFacts("/")
	p.Firewall = linuxFirewall(ctx)
	return p
}

// linuxFacts reads what the files under root (/ but for tests) say.
func linuxFacts(root string) api.Posture {
	p := api.Posture{OS: "linux"}
	if b, err := os.ReadFile(filepath.Join(root, "proc/sys/kernel/osrelease")); err == nil {
		p.OSVersion = strings.TrimSpace(string(b))
	}
	for _, f := range []string{"etc/os-release", "usr/lib/os-release"} {
		if b, err := os.ReadFile(filepath.Join(root, f)); err == nil {
			p.Distribution = parseOSRelease(string(b))
			break
		}
	}
	p.DiskEncryption = rootEncrypted(root)
	p.SecureBoot = linuxSecureBoot(root)
	p.Antimalware = linuxAntimalware(processNames(root))
	return p
}

// processNames lists the names of the running processes (/proc/<pid>/comm).
func processNames(root string) []string {
	entries, err := os.ReadDir(filepath.Join(root, "proc"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.Name() == "" || e.Name()[0] < '0' || e.Name()[0] > '9' {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(root, "proc", e.Name(), "comm")); err == nil {
			out = append(out, strings.TrimSpace(string(b)))
		}
	}
	return out
}

// secureBootVar is the EFI global variable holding the Secure Boot state.
const secureBootVar = "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

// linuxSecureBoot reads the SecureBoot EFI variable: 4 bytes of attributes, then 1 when on. A system
// without EFI has no Secure Boot; without readable variables it is unknown.
func linuxSecureBoot(root string) *bool {
	efi := filepath.Join(root, "sys/firmware/efi")
	if _, err := os.Stat(efi); os.IsNotExist(err) {
		return boolPtr(false)
	}
	vars := filepath.Join(efi, "efivars")
	entries, err := os.ReadDir(vars)
	if err != nil || len(entries) == 0 {
		return nil // efivarfs not mounted, or not readable
	}
	b, err := os.ReadFile(filepath.Join(vars, secureBootVar))
	switch {
	case os.IsNotExist(err):
		return boolPtr(false)
	case err != nil || len(b) < 5:
		return nil
	}
	return boolPtr(b[4] == 1)
}

// rootEncrypted reports whether the file system mounted at / is on a dm-crypt device, directly or
// through other device-mapper layers (LVM on LUKS). False when it is on a block device without one;
// unknown when it is not on a block device this can follow (ZFS, overlay, network).
func rootEncrypted(root string) *bool {
	b, err := os.ReadFile(filepath.Join(root, "proc/self/mountinfo"))
	if err != nil {
		return nil
	}
	dev := mountDevice(root, string(b), "/")
	if dev == "" {
		// ostree systems (Fedora Silverblue and Kinoite, Fedora CoreOS, ...): / is a composefs
		// overlay on no block device; the real root file system is mounted at /sysroot.
		dev = mountDevice(root, string(b), "/sysroot")
	}
	if dev == "" {
		return nil
	}
	return boolPtr(cryptBelow(root, dev, 0))
}

// mountDevice finds the sysfs directory of the block device mounted at mountPoint ("" when there is
// none: an overlay, tmpfs, a container's root).
func mountDevice(root, mountinfo, mountPoint string) string {
	var devID, source string
	for _, line := range strings.Split(mountinfo, "\n") {
		// 36 35 98:0 / / rw,noatime master:1 - ext4 /dev/mapper/root rw
		pre, post, ok := strings.Cut(line, " - ")
		f, g := strings.Fields(pre), strings.Fields(post)
		if !ok || len(f) < 5 || len(g) < 2 || f[4] != mountPoint {
			continue
		}
		devID, source = f[2], g[1] // the last mount at the point is the one in use
	}
	dev := ""
	if devID != "" && !strings.HasPrefix(devID, "0:") {
		dev = resolve(root, filepath.Join("sys/dev/block", devID))
	}
	if dev == "" && strings.HasPrefix(source, "/dev/") {
		// Btrfs (and other file systems on anonymous device numbers) name their device instead.
		dev = blockDevice(root, source)
	}
	return dev
}

// resolve follows the symbolic links of rel under root, staying under it; "" when it does not exist.
func resolve(root, rel string) string {
	p, err := filepath.EvalSymlinks(filepath.Join(root, rel))
	if err != nil {
		return ""
	}
	if r, err := filepath.Rel(root, p); err != nil || strings.HasPrefix(r, "..") {
		return ""
	}
	return p
}

// blockDevice finds the sysfs directory of a device node: /dev/mapper/NAME by the device-mapper
// name, any other by its kernel name (after its links, like /dev/disk/by-uuid/...).
func blockDevice(root, node string) string {
	if name, ok := strings.CutPrefix(node, "/dev/mapper/"); ok {
		dms, _ := filepath.Glob(filepath.Join(root, "sys/block/dm-*"))
		for _, d := range dms {
			if b, err := os.ReadFile(filepath.Join(d, "dm/name")); err == nil && strings.TrimSpace(string(b)) == name {
				return resolve(root, strings.TrimPrefix(d, root))
			}
		}
		return ""
	}
	name := filepath.Base(node)
	if p := resolve(root, strings.TrimPrefix(node, "/")); p != "" {
		name = filepath.Base(p)
	}
	return resolve(root, filepath.Join("sys/class/block", name))
}

// encryptingCrypt are the prefixes libcryptsetup gives the device-mapper UUIDs of the devices it
// activates that encrypt. It gives "CRYPT-" to others too, which protect integrity only and keep
// the data readable: dm-verity (CRYPT-VERITY-), standalone dm-integrity (CRYPT-INTEGRITY-), and the
// integrity layer under an authenticated LUKS2 device (CRYPT-SUBDEV-).
var encryptingCrypt = []string{"CRYPT-LUKS1-", "CRYPT-LUKS2-", "CRYPT-PLAIN-", "CRYPT-LOOPAES-", "CRYPT-TCRYPT-",
	"CRYPT-BITLK-", "CRYPT-FVAULT2-"}

// cryptBelow reports whether the block device at dir (sysfs), or one it is made of, is dm-crypt.
func cryptBelow(root, dir string, depth int) bool {
	if depth > 8 {
		return false
	}
	if b, err := os.ReadFile(filepath.Join(dir, "dm/uuid")); err == nil {
		uuid := strings.TrimSpace(string(b))
		if slices.ContainsFunc(encryptingCrypt, func(p string) bool { return strings.HasPrefix(uuid, p) }) {
			return true
		}
	}
	slaves, _ := os.ReadDir(filepath.Join(dir, "slaves"))
	for _, s := range slaves {
		rel, err := filepath.Rel(root, filepath.Join(dir, "slaves", s.Name()))
		if err != nil {
			continue
		}
		if p := resolve(root, rel); p != "" && cryptBelow(root, p, depth+1) {
			return true
		}
	}
	return false
}

// linuxFirewall reports whether the input path is filtered: nftables (which iptables-nft, firewalld
// and ufw use), else the legacy iptables backend.
func linuxFirewall(ctx context.Context) *bool {
	chains, listed, note := nftInputChains(ctx)
	notePosture("firewall", note)
	on := linuxFirewallOn(chains, listed)
	if on != nil && *on {
		return on
	}
	if b, err := os.ReadFile("/proc/net/ip_tables_names"); err == nil && strings.Contains(string(b), "filter") {
		for _, bin := range []string{"/usr/sbin/iptables-legacy", "/sbin/iptables-legacy", "/usr/sbin/iptables", "/sbin/iptables"} {
			if _, err := os.Stat(bin); err != nil {
				continue
			}
			if out, err := runFixed(ctx, bin, "-S", "INPUT"); err == nil {
				if legacy := parseIptablesInput(out); legacy != nil {
					return legacy
				}
			}
			break
		}
	}
	return on
}

// dropsAll reports whether a rule drops or rejects everything that reaches it: its only other
// expressions count or log. A rule with a match (an address, a set, a connection state) drops some
// packets only, which a chain that accepts the rest does not make a firewall (fail2ban's chain, or
// "ct state invalid drop").
func dropsAll(exprs []expr.Any) bool {
	verdict := false
	for _, e := range exprs {
		switch v := e.(type) {
		case *expr.Counter, *expr.Log:
		case *expr.Verdict:
			if v.Kind != expr.VerdictDrop {
				return false
			}
			verdict = true
		case *expr.Reject:
			verdict = true
		case *expr.Target: // iptables-nft's REJECT
			if v.Name != "REJECT" {
				return false
			}
			verdict = true
		default:
			return false
		}
	}
	return verdict
}

// nftInputChains lists the nftables base chains of IPv4 and IPv6 traffic in the agent's network
// namespace (the host's). note says how a chain had to be read, or why none could be.
func nftInputChains(ctx context.Context) ([]nftChain, bool, string) {
	c, err := nftables.New()
	if err != nil {
		return nil, false, "nftables: " + err.Error()
	}
	all, err := c.ListChains()
	if err != nil {
		return nil, false, "nftables chains: " + err.Error()
	}
	var notes []string
	var out []nftChain
	for _, ch := range all {
		switch ch.Table.Family {
		case nftables.TableFamilyINet, nftables.TableFamilyIPv4, nftables.TableFamilyIPv6:
		default:
			continue
		}
		if ch.Hooknum == nil || *ch.Hooknum != *nftables.ChainHookInput || ch.Type != nftables.ChainTypeFilter {
			continue
		}
		info := nftChain{InputHook: true, PolicyDrop: ch.Policy != nil && *ch.Policy == nftables.ChainPolicyDrop}
		if !info.PolicyDrop {
			rules, err := c.GetRules(ch.Table, ch)
			switch {
			case err == nil:
				if len(rules) > 0 {
					info.EndsInDrop = dropsAll(rules[len(rules)-1].Exprs)
				}
			default:
				// google/nftables fails on some rules the kernel holds (conntrack's direction, as in
				// firewalld's rich rules with a port: `ct original proto-dst 22`); nft reads them.
				ends, jerr := nftChainByCommand(ctx, ch)
				name := familyName(ch.Table.Family) + " " + ch.Table.Name + " " + ch.Name
				if jerr != nil {
					return nil, false, fmt.Sprintf("chain %s: %v; nft -j: %v", name, err, jerr)
				}
				info.EndsInDrop = ends
				notes = append(notes, fmt.Sprintf("chain %s read with nft -j (%v)", name, err))
			}
		}
		out = append(out, info)
	}
	return out, true, strings.Join(notes, "; ")
}

func familyName(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	}
	return "inet"
}

// nftChainByCommand reads a chain with `nft -j` (see parseNftChainJSON).
func nftChainByCommand(ctx context.Context, ch *nftables.Chain) (bool, error) {
	for _, bin := range []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"} {
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		out, err := runFixed(ctx, bin, "-j", "list", "chain", familyName(ch.Table.Family), ch.Table.Name, ch.Name)
		if err != nil {
			return false, err
		}
		return parseNftChainJSON(out)
	}
	return false, errors.New("no nft command")
}
