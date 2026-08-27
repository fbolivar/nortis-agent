//go:build !windows

package inventory

import (
	"context"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// Recolectar en plataformas no Windows no tiene fuente de inventario: se devuelve
// vacio para que el binario compile en CI/desarrollo sin tocar el flujo real.
func Recolectar(_ context.Context, _ []string) (map[string]any, []contract.SoftwareItem) {
	return map[string]any{}, nil
}
