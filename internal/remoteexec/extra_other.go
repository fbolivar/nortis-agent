//go:build !windows

package remoteexec

import (
	"context"
	"errors"
)

// EjecutarMensaje solo existe en Windows.
func EjecutarMensaje(_ context.Context, _ MessagePayload) (int, string, error) {
	return -1, "", errors.New("message solo esta disponible en Windows")
}

// EjecutarKill solo existe en Windows.
func EjecutarKill(_ context.Context, _ KillPayload) (int, string, error) {
	return -1, "", errors.New("kill solo esta disponible en Windows")
}

// EjecutarUninstall solo existe en Windows.
func EjecutarUninstall(_ context.Context, _ UninstallPayload) (int, string, error) {
	return -1, "", errors.New("uninstall solo esta disponible en Windows")
}
