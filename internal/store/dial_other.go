//go:build !linux

package store

import "syscall"

// setUserTimeout: TCP_USER_TIMEOUT is Linux only; elsewhere keepalives alone (see dialDB).
func setUserTimeout(network, address string, c syscall.RawConn) error { return nil }
