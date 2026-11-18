//go:build !linux && !darwin

package main

import "os"

// noEcho: elsewhere a secret typed at a prompt shows (piping it in does not).
func noEcho(*os.File) func() { return func() {} }
