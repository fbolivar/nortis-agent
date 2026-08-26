//go:build !windows

package remoteexec

import (
	"context"
	"errors"
)

// EjecutarRestart solo existe en Windows.
func EjecutarRestart(_ context.Context) (int, string, error) {
	return -1, "", errors.New("restart solo esta disponible en Windows")
}
