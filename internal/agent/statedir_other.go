//go:build !windows

package agent

// protectStateDir: elsewhere the directory's mode (0700, owned by root) already keeps the key from
// other users.
func protectStateDir(string) error { return nil }
