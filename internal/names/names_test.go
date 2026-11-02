package names

import (
	"strings"
	"testing"
)

func TestLabel(t *testing.T) {
	for in, want := range map[string]string{
		"Mariuss-MacBook-Pro.local": "mariuss-macbook-pro",
		"Pixel 7":                   "pixel-7",
		"DESKTOP-4F7K2QX":           "desktop-4f7k2qx",
		"  --web__01--  ":           "web-01",
		"id.example.com":            "id",
		"ünïcödé":                   "n-c-d",
		"a\nb\x1b[31mc":             "a-b-31mc",
		"...":                       "",
		"":                          "",
	} {
		if got := Label(in); got != want {
			t.Errorf("Label(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBase(t *testing.T) {
	for in, want := range map[string]string{
		"arrakis":   "arrakis",
		"z-arrakis": "arrakis", // a home network's self-named device, admitted elsewhere
		"Z-Z-Box":   "box",
		"z":         "z",
		"???":       "device",
	} {
		if got := Base(in); got != want {
			t.Errorf("Base(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCandidate(t *testing.T) {
	if got := Candidate(SelfPrefix, "laptop", 0); got != "z-laptop" {
		t.Errorf("first candidate %q", got)
	}
	if got := Candidate(SelfPrefix, "laptop", 2); got != "z-laptop-2" {
		t.Errorf("third candidate %q", got)
	}
	long := strings.Repeat("abcdefgh-", 6) // 54 characters
	for _, n := range []int{0, 1, 12, 1234} {
		c := Candidate("acme-", long, n)
		if len(c) > MaxLen || !strings.HasPrefix(c, "acme-") || strings.Contains(c, "--") {
			t.Errorf("candidate %d of a long name: %q", n, c)
		}
	}
	if got := Candidate("", strings.Repeat("abcdefg-", 5), 0); got != "abcdefg-abcdefg-abcdefg-abcdefg" {
		t.Errorf("cut at a dash: %q", got)
	}
}

func TestFree(t *testing.T) {
	used := map[string]bool{"z-laptop": true, "z-laptop-1": true, "z-laptop-3": true}
	got, err := Free(SelfPrefix, "laptop", func(n string) (bool, error) { return used[n], nil })
	if err != nil || got != "z-laptop-2" {
		t.Errorf("Free = %q, %v", got, err)
	}
}

func TestCheck(t *testing.T) {
	for _, ok := range []string{"node-a", "acme-core-witness", "a", "123", strings.Repeat("a", MaxLen)} {
		if err := Check(ok); err != nil {
			t.Errorf("Check(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"", "z-node", "Node-A", "node_a", "-node", "node-", "a--b", "id.example.com",
		"with space", strings.Repeat("a", MaxLen+1)} {
		if Check(bad) == nil {
			t.Errorf("Check(%q) accepted", bad)
		}
	}
	if FromReported("Mariuss-MacBook-Pro.local") != "mariuss-macbook-pro" || Check(FromReported("z-z-x")) != nil {
		t.Error("confirmed names")
	}
}

func TestReported(t *testing.T) {
	if got := Reported("Pixel\n7\x1b]52;c;aGk=\x07"); got != "Pixel?7?]52;c;aGk=?" {
		t.Errorf("Reported kept control characters: %q", got)
	}
	if got := Reported(strings.Repeat("x", 100)); len(got) != 64 {
		t.Errorf("Reported length %d", len(got))
	}
}
