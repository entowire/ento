//go:build !((linux && !android) || (darwin && !ios))

package agent

import (
	"context"

	"entowire.com/ento/internal/api"
)

// Self-updates on Windows (a running service's binary is replaced through the service manager) and
// phones (an app is replaced only with the person's consent) come later: see selfupdate.go.

func CheckPendingUpdate(stateDir, version string, logf func(string, ...any)) {}

func (a *runner) confirmUpdate() {}

func (a *runner) maybeUpdate(ctx context.Context, ctl api.Control, u *api.Update) {}
