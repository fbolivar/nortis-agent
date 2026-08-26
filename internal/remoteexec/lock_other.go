//go:build !windows

package remoteexec

import (
	"context"
	"errors"
)

// EjecutarLock solo existe en Windows.
func EjecutarLock(_ context.Context) (int, string, error) {
	return -1, "", errors.New("lock solo esta disponible en Windows")
}
