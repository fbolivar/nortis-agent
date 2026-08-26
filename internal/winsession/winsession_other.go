//go:build !windows

package winsession

import "errors"

// TokenUsuarioActivo solo existe en Windows. El tipo de retorno es uintptr en
// lugar de windows.Token para no arrastrar el paquete windows fuera de Windows;
// los llamantes reales son todos _windows.go.
func TokenUsuarioActivo() (uintptr, uint32, error) {
	return 0, 0, errors.New("solo disponible en Windows")
}
