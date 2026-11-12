//go:build !windows

// ento-tray is Windows-only: elsewhere the person signs in with sudo ento login (Linux
// laptops also from the login screen, approved on their phone).
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "ento-tray runs on Windows only")
	os.Exit(1)
}
