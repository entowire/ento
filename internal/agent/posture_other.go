//go:build android || ios || !(linux || darwin || windows)

package agent

import (
	"context"

	"entowire.com/ento/internal/api"
)

// collectPlatform knows nothing of systems it cannot inspect from inside an app: there the app
// provides the facts (SetExternalPosture).
func collectPlatform(context.Context) api.Posture { return api.Posture{} }
