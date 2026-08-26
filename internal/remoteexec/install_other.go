//go:build !windows

package remoteexec

import (
	"context"
	"errors"
)

// EjecutarInstallMSI solo existe en Windows. El stub permite compilar y testear
// la verificacion de firma en cualquier plataforma de CI.
func EjecutarInstallMSI(_ context.Context, _ InstallMSIPayload) (int, string, error) {
	return -1, "", errors.New("install_msi solo esta disponible en Windows")
}
