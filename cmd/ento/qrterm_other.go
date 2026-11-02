//go:build !windows

package main

import "os"

// enableTerminalColors: terminals elsewhere handle ANSI colour sequences already.
func enableTerminalColors(*os.File) {}
