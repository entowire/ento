//go:build linux && !android

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/nftables/expr"
)

// fakeRoot builds a tree of /proc, /sys and /etc files under a temporary directory.
type fakeRoot struct {
	t    *testing.T
	root string
}

func (f fakeRoot) file(rel, content string) {
	f.t.Helper()
	p := filepath.Join(f.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// link makes rel a symbolic link to target (relative to rel's directory), as sysfs does.
func (f fakeRoot) link(rel, target string) {
	f.t.Helper()
	p := filepath.Join(f.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		f.t.Fatal(err)
	}
}

// dm adds a device-mapper device dm-N with its uuid and name, made of slaves.
func (f fakeRoot) dm(n, majmin, uuid, name string, slaves ...string) {
	dir := "sys/devices/virtual/block/dm-" + n
	f.file(dir+"/dm/uuid", uuid+"\n")
	f.file(dir+"/dm/name", name+"\n")
	if err := os.MkdirAll(filepath.Join(f.root, dir, "slaves"), 0o755); err != nil {
		f.t.Fatal(err)
	}
	for _, s := range slaves {
		f.link(dir+"/slaves/"+s, "../../"+s)
	}
	f.link("sys/block/dm-"+n, "../devices/virtual/block/dm-"+n)
	f.link("sys/class/block/dm-"+n, "../../devices/virtual/block/dm-"+n)
	f.link("sys/dev/block/"+majmin, "../../devices/virtual/block/dm-"+n)
}

// disk adds a partition of an NVMe disk.
func (f fakeRoot) partition(name, majmin string) {
	dir := "sys/devices/pci0000:00/0000:00:1d.0/nvme/nvme0/nvme0n1/" + name
	f.file(dir+"/partition", "1\n")
	f.link("sys/class/block/"+name, "../../devices/pci0000:00/0000:00:1d.0/nvme/nvme0/nvme0n1/"+name)
	f.link("sys/dev/block/"+majmin, "../../devices/pci0000:00/0000:00:1d.0/nvme/nvme0/nvme0n1/"+name)
}

func newFakeRoot(t *testing.T, mountinfo string) fakeRoot {
	f := fakeRoot{t: t, root: t.TempDir()}
	f.file("proc/self/mountinfo", mountinfo)
	f.file("proc/sys/kernel/osrelease", "6.8.0-142-generic\n")
	f.file("etc/os-release", "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n")
	return f
}

const mountinfoTail = "\n25 1 0:23 / /sys rw,nosuid shared:7 - sysfs sysfs rw\n26 1 0:24 / /proc rw shared:13 - proc proc rw\n"

func TestLinuxRootEncryption(t *testing.T) {
	t.Run("LUKS", func(t *testing.T) {
		f := newFakeRoot(t, "1 0 252:0 / / rw,relatime shared:1 - ext4 /dev/mapper/root rw"+mountinfoTail)
		f.partition("nvme0n1p3", "259:3")
		f.dm("0", "252:0", "CRYPT-LUKS2-0f1e2d3c4b5a69788796a5b4c3d2e1f0-root", "root", "nvme0n1p3")
		p := linuxFacts(f.root)
		if tri(p.DiskEncryption) != "on" || p.OSVersion != "6.8.0-142-generic" || p.Distribution != "ubuntu 24.04" || p.OS != "linux" {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("LVM on LUKS", func(t *testing.T) {
		f := newFakeRoot(t, "1 0 252:1 / / rw,relatime shared:1 - ext4 /dev/mapper/vg-root rw"+mountinfoTail)
		f.partition("nvme0n1p3", "259:3")
		f.dm("0", "252:0", "CRYPT-LUKS2-aaaa-nvme0n1p3_crypt", "nvme0n1p3_crypt", "nvme0n1p3")
		f.dm("1", "252:1", "LVM-Xb7gq0abcdefghijklmnopqrstuvwx", "vg-root", "dm-0")
		if p := linuxFacts(f.root); tri(p.DiskEncryption) != "on" {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("LVM without encryption", func(t *testing.T) {
		f := newFakeRoot(t, "1 0 252:1 / / rw,relatime shared:1 - xfs /dev/mapper/vg-root rw"+mountinfoTail)
		f.partition("nvme0n1p3", "259:3")
		f.dm("1", "252:1", "LVM-Xb7gq0abcdefghijklmnopqrstuvwx", "vg-root", "nvme0n1p3")
		if p := linuxFacts(f.root); tri(p.DiskEncryption) != "off" {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("plain partition", func(t *testing.T) {
		f := newFakeRoot(t, "1 0 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw"+mountinfoTail)
		f.partition("nvme0n1p2", "259:2")
		if p := linuxFacts(f.root); tri(p.DiskEncryption) != "off" {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("btrfs on LUKS", func(t *testing.T) {
		// Btrfs shows an anonymous device number: the device is found by the mount's source.
		f := newFakeRoot(t, "1 0 0:31 /@ / rw,relatime shared:1 - btrfs /dev/mapper/luks-5d2c rw,subvol=/@"+mountinfoTail)
		f.partition("nvme0n1p3", "259:3")
		f.dm("0", "252:0", "CRYPT-LUKS2-5d2c-luks-5d2c", "luks-5d2c", "nvme0n1p3")
		if p := linuxFacts(f.root); tri(p.DiskEncryption) != "on" {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("btrfs by uuid", func(t *testing.T) {
		f := newFakeRoot(t, "1 0 0:31 /@ / rw shared:1 - btrfs /dev/disk/by-uuid/1234 rw"+mountinfoTail)
		f.partition("nvme0n1p2", "259:2")
		f.file("dev/nvme0n1p2", "")
		f.link("dev/disk/by-uuid/1234", "../../nvme0n1p2")
		if p := linuxFacts(f.root); tri(p.DiskEncryption) != "off" {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("composefs root (ostree), LUKS under /sysroot", func(t *testing.T) {
		// Fedora Silverblue: / is a composefs overlay, the real root is btrfs on LUKS at /sysroot.
		f := newFakeRoot(t, "1 0 0:33 / / ro,relatime shared:1 - overlay composefs ro,lowerdir+=/run/ostree/.private/cfsroot-lower\n"+
			"2 1 0:35 /root /sysroot ro,relatime shared:4 - btrfs /dev/mapper/luks-7e4f rw,subvol=/root"+mountinfoTail)
		f.partition("nvme0n1p3", "259:3")
		f.dm("0", "252:0", "CRYPT-LUKS2-7e4f-luks-7e4f", "luks-7e4f", "nvme0n1p3")
		if p := linuxFacts(f.root); tri(p.DiskEncryption) != "on" {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("composefs root (ostree), plain /sysroot", func(t *testing.T) {
		f := newFakeRoot(t, "1 0 0:33 / / ro,relatime shared:1 - overlay composefs ro\n"+
			"2 1 259:3 /root /sysroot ro,relatime shared:4 - xfs /dev/nvme0n1p3 rw"+mountinfoTail)
		f.partition("nvme0n1p3", "259:3")
		if p := linuxFacts(f.root); tri(p.DiskEncryption) != "off" {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("overlay root without /sysroot (a container)", func(t *testing.T) {
		f := newFakeRoot(t, "1 0 0:33 / / rw,relatime - overlay overlay rw,lowerdir=/x"+mountinfoTail)
		if p := linuxFacts(f.root); p.DiskEncryption != nil {
			t.Fatalf("a container's root reported as %v", *p.DiskEncryption)
		}
	})
	t.Run("overmounted root", func(t *testing.T) {
		// The last mount at / is the one in use.
		f := newFakeRoot(t, "1 0 259:2 / / rw shared:1 - ext4 /dev/nvme0n1p2 rw\n40 1 252:0 / / rw shared:2 - ext4 /dev/mapper/root rw"+mountinfoTail)
		f.partition("nvme0n1p2", "259:2")
		f.dm("0", "252:0", "CRYPT-LUKS2-0f1e-root", "root", "nvme0n1p2")
		if p := linuxFacts(f.root); tri(p.DiskEncryption) != "on" {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("dm-verity root", func(t *testing.T) {
		// Integrity only: the data stays readable.
		f := newFakeRoot(t, "1 0 252:0 / / ro shared:1 - erofs /dev/mapper/root ro"+mountinfoTail)
		f.partition("nvme0n1p2", "259:2")
		f.partition("nvme0n1p3", "259:3")
		f.dm("0", "252:0", "CRYPT-VERITY-0f1e2d3c4b5a69788796a5b4c3d2e1f0-root", "root", "nvme0n1p2", "nvme0n1p3")
		if p := linuxFacts(f.root); tri(p.DiskEncryption) != "off" {
			t.Fatalf("verity counted as encryption: %+v", p)
		}
	})
	t.Run("dm-integrity root", func(t *testing.T) {
		f := newFakeRoot(t, "1 0 252:0 / / rw shared:1 - ext4 /dev/mapper/root rw"+mountinfoTail)
		f.partition("nvme0n1p2", "259:2")
		f.dm("0", "252:0", "CRYPT-INTEGRITY-0f1e-root", "root", "nvme0n1p2")
		if p := linuxFacts(f.root); tri(p.DiskEncryption) != "off" {
			t.Fatalf("integrity counted as encryption: %+v", p)
		}
	})
	t.Run("authenticated LUKS2 (integrity below)", func(t *testing.T) {
		f := newFakeRoot(t, "1 0 252:1 / / rw shared:1 - ext4 /dev/mapper/root rw"+mountinfoTail)
		f.partition("nvme0n1p2", "259:2")
		f.dm("0", "252:0", "CRYPT-SUBDEV-0f1e-root_dif", "root_dif", "nvme0n1p2")
		f.dm("1", "252:1", "CRYPT-LUKS2-0f1e-root", "root", "dm-0")
		if p := linuxFacts(f.root); tri(p.DiskEncryption) != "on" {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("LUKS under integrity", func(t *testing.T) {
		// Integrity layered on an encrypted device: still encrypted (the slaves are followed).
		f := newFakeRoot(t, "1 0 252:1 / / rw shared:1 - ext4 /dev/mapper/root rw"+mountinfoTail)
		f.partition("nvme0n1p2", "259:2")
		f.dm("0", "252:0", "CRYPT-LUKS2-0f1e-crypt", "crypt", "nvme0n1p2")
		f.dm("1", "252:1", "CRYPT-INTEGRITY-0f1e-root", "root", "dm-0")
		if p := linuxFacts(f.root); tri(p.DiskEncryption) != "on" {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("ZFS", func(t *testing.T) {
		f := newFakeRoot(t, "1 0 0:27 / / rw shared:1 - zfs rpool/ROOT/ubuntu rw,xattr"+mountinfoTail)
		if p := linuxFacts(f.root); p.DiskEncryption != nil {
			t.Fatalf("ZFS is not followed: %+v", p)
		}
	})
	t.Run("no mountinfo", func(t *testing.T) {
		if p := linuxFacts(t.TempDir()); p.DiskEncryption != nil || p.OSVersion != "" || p.Distribution != "" {
			t.Fatalf("%+v", p)
		}
	})
}

func TestLinuxSecureBoot(t *testing.T) {
	efivar := "sys/firmware/efi/efivars/" + secureBootVar
	cases := []struct {
		name  string
		setup func(f fakeRoot)
		want  string
	}{
		{"on", func(f fakeRoot) { f.file(efivar, "\x06\x00\x00\x00\x01") }, "on"},
		{"off", func(f fakeRoot) { f.file(efivar, "\x06\x00\x00\x00\x00") }, "off"},
		{"no variable", func(f fakeRoot) {
			f.file("sys/firmware/efi/efivars/Boot0000-8be4df61-93ca-11d2-aa0d-00e098032b8c", "x")
		}, "off"},
		{"efivars not mounted", func(f fakeRoot) { f.file("sys/firmware/efi/systab", "x") }, "unknown"},
		{"short variable", func(f fakeRoot) { f.file(efivar, "\x06\x00") }, "unknown"},
		{"no EFI", func(f fakeRoot) { f.file("sys/firmware/acpi/x", "") }, "off"},
	}
	for _, c := range cases {
		f := fakeRoot{t: t, root: t.TempDir()}
		c.setup(f)
		if got := tri(linuxSecureBoot(f.root)); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// A known real-time scanner among the running processes means anti-malware on; none, unknown.
func TestLinuxAntimalwareProcesses(t *testing.T) {
	f := fakeRoot{t: t, root: t.TempDir()}
	f.file("proc/1/comm", "systemd\n")
	f.file("proc/self/comm", "ento\n")
	if got := tri(linuxFacts(f.root).Antimalware); got != "unknown" {
		t.Errorf("without a scanner: %s", got)
	}
	f.file("proc/4242/comm", "wdavdaemon\n")
	if got := tri(linuxFacts(f.root).Antimalware); got != "on" {
		t.Errorf("with Defender for Endpoint: %s", got)
	}
}

func TestNftDropsAll(t *testing.T) {
	drop := &expr.Verdict{Kind: expr.VerdictDrop}
	cases := []struct {
		name  string
		exprs []expr.Any
		want  bool
	}{
		{"drop", []expr.Any{drop}, true},
		{"counter drop", []expr.Any{&expr.Counter{}, drop}, true},
		{"log reject (firewalld)", []expr.Any{&expr.Log{}, &expr.Reject{}}, true},
		{"iptables-nft REJECT", []expr.Any{&expr.Counter{}, &expr.Target{Name: "REJECT"}}, true},
		{"accept", []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}, false},
		{"jump", []expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: "x"}}, false},
		{"ct state invalid drop", []expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}}, drop}, false},
		{"fail2ban: saddr in a set, reject", []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Lookup{SourceRegister: 1, SetName: "addr-set-sshd"}, &expr.Reject{}}, false},
		{"empty", nil, false},
	}
	for _, c := range cases {
		if got := dropsAll(c.exprs); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
