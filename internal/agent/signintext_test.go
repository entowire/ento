package agent

import (
	"strings"
	"testing"
)

func TestSignInText(t *testing.T) {
	setup := signInText("https://id.example.com/setup#s3cret", "https://id.example.com/setup#s3cret", "ABCD-EFGH", false)
	if strings.Contains(setup, "Code:") || !strings.Contains(setup, "set up your account") {
		t.Fatalf("setup link: %q", setup)
	}
	device := signInText("https://id.example.com/device", "https://id.example.com/device", "ABCD-EFGH", true)
	if !strings.Contains(device, "Code: ABCD-EFGH") || !strings.Contains(device, "just opened") {
		t.Fatalf("device page: %q", device)
	}
	here := signInText("https://id.example.com:4443/here", "https://id.example.com:4443/here", "", true)
	if strings.Contains(here, "Code:") || !strings.Contains(here, "on this device") {
		t.Fatalf("device's own sign-in: %q", here)
	}
	if !onDeviceOnly("https://id.example.com:4443/here") || !onDeviceOnly("https://id.example.com:4443/setup#s") ||
		onDeviceOnly("https://id.example.com/setup#s") || onDeviceOnly("https://id.example.com/device") {
		t.Fatal("onDeviceOnly")
	}
}
