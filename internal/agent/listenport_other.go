//go:build !linux

package agent

// ownListenPort: only Linux's kernel interface outlives the agent.
var ownListenPort = func(string) (int, bool) { return 0, false }
