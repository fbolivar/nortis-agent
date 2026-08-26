//go:build !windows

package remoteexec

import (
	"context"
	"errors"
)

// EjecutarScan solo existe en Windows (Defender). El stub permite compilar y
// testear en cualquier plataforma de CI.
func EjecutarScan(_ context.Context, _ ScanPayload) (int, string, error) {
	return -1, "", errors.New("scan_av solo esta disponible en Windows")
}
