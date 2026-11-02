//go:build windows

package main

// cliAudit: control nodes run on Linux; on Windows there is nothing to record it in.
func cliAudit([]string, error) {}
