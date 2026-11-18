//go:build linux || darwin

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// noEcho turns the terminal's echo off until the returned function turns it on again (a secret
// typed at a prompt is not shown).
func noEcho(f *os.File) func() {
	t, err := unix.IoctlGetTermios(int(f.Fd()), getTermios)
	if err != nil {
		return func() {}
	}
	quiet := *t
	quiet.Lflag &^= unix.ECHO
	if unix.IoctlSetTermios(int(f.Fd()), setTermios, &quiet) != nil {
		return func() {}
	}
	return func() { _ = unix.IoctlSetTermios(int(f.Fd()), setTermios, t) }
}
