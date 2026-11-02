package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDownMark(t *testing.T) {
	dir := t.TempDir()
	if IsDown(dir) {
		t.Fatal("down before Down")
	}
	if err := setDown(dir, true); err != nil {
		t.Fatal(err)
	}
	if !IsDown(dir) {
		t.Fatal("not down after Down")
	}
	if fi, err := os.Stat(filepath.Join(dir, downFile)); err != nil {
		t.Fatal(err)
	} else if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("mark has mode %v", fi.Mode().Perm())
	}
	for range 2 { // clearing twice is fine
		if err := setDown(dir, false); err != nil {
			t.Fatal(err)
		}
	}
	if IsDown(dir) {
		t.Fatal("still down after Up")
	}
}

func TestStateDirArg(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"/usr/local/bin/ento", "agent", "run", "--state-dir", "/var/lib/ento", "--mtu", "1380"}, "/var/lib/ento"},
		{[]string{"ento", "agent", "up", "-state-dir=/srv/ento"}, "/srv/ento"},
		{[]string{"ento", "agent", "up", "--token-file", "/var/lib/ento/enroll.token"}, ""},
		{[]string{"ento", "agent", "run", "--state-dir"}, ""},
	} {
		if got := stateDirArg(c.args); got != c.want {
			t.Errorf("stateDirArg(%q) = %q, want %q", c.args, got, c.want)
		}
	}
}

func TestIsAgentCommand(t *testing.T) {
	for _, c := range []struct {
		args []string
		want bool
	}{
		{[]string{"/usr/local/bin/ento", "agent", "run", "--state-dir", "/var/lib/ento"}, true},
		{[]string{"/opt/ento/bin/ento", "agent", "up", "--token-file", "t"}, true},
		{[]string{"ento", "agent", "status"}, false},
		{[]string{"bash", "-c", "ento agent run"}, false},
		{nil, false},
	} {
		if got := isAgentCommand(c.args); got != c.want {
			t.Errorf("isAgentCommand(%q) = %v", c.args, got)
		}
	}
}

func TestSameDir(t *testing.T) {
	dir := t.TempDir()
	if !sameDir(dir, dir+string(filepath.Separator)+".") {
		t.Error("a directory is not itself")
	}
	if sameDir(dir, t.TempDir()) || sameDir(dir, "") || sameDir(dir, filepath.Join(dir, "missing")) {
		t.Error("different directories are the same")
	}
}
