//go:build windows

package agent

// DefaultStateDir is where the agent keeps its identity and state (only SYSTEM and
// Administrators may read it: see install_windows.go).
const DefaultStateDir = `C:\ProgramData\ento`
