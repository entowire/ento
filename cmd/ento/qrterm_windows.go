//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableTerminalColors turns on the console's handling of ANSI colour sequences, which the QR code
// is drawn with: Windows 10's console shows them as text unless a program asks for them.
func enableTerminalColors(f *os.File) {
	h := windows.Handle(f.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) == nil {
		_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	}
}
