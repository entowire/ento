package agent

import "testing"

func TestSafeLink(t *testing.T) {
	for link, want := range map[string]bool{
		"https://id.example.com/realms/x/device?user_code=ABCD-EFGH": true,
		"https://net.example.com":                                    true,
		"http://id.example.com/device":                               false,
		"file:///etc/passwd":                                         false,
		"javascript:alert(1)":                                        false,
		"ms-settings:":                                               false,
		"https://user:pass@id.example.com/":                          false,
		"https:///nohost":                                            false,
		"https://id.example.com/\x1b[2J":                             false,
		"https://id.example.com/ x":                                  false,
		"https://id.exämple.com/":                                    false,
		"":                                                           false,
	} {
		if got := SafeLink(link); got != want {
			t.Errorf("SafeLink(%q) = %v, want %v", link, got, want)
		}
	}
}

func TestPrintable(t *testing.T) {
	if got := Printable("ana\x1b]0;owned\x07‮ moc\r\n"); got != "ana]0;owned moc" {
		t.Fatalf("Printable: %q", got)
	}
	if got := Printable("Mărius"); got != "Mărius" {
		t.Fatalf("Printable dropped letters: %q", got)
	}
}
