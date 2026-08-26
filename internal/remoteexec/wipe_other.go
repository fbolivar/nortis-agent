//go:build !windows

package remoteexec

import (
	"context"
	"errors"
)

// EjecutarWipe solo existe en Windows.
func EjecutarWipe(_ context.Context, _ WipePayload) (int, string, error) {
	return -1, "", errors.New("wipe solo esta disponible en Windows")
}
