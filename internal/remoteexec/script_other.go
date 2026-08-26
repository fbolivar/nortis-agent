//go:build !windows

package remoteexec

import (
	"context"
	"errors"
)

// EjecutarRunScript solo existe en Windows. El stub permite compilar y testear
// la verificacion de firma en cualquier plataforma de CI.
func EjecutarRunScript(_ context.Context, _ RunScriptPayload) (int, string, error) {
	return -1, "", errors.New("run_script solo esta disponible en Windows")
}
