//go:build !windows

package capture

import (
	"context"
	"errors"
)

// Capturar solo existe en Windows.
func Capturar(_ context.Context) ([]byte, error) {
	return nil, errors.New("la captura de pantalla solo esta disponible en Windows")
}
