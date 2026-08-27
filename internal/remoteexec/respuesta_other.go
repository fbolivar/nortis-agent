//go:build !windows

package remoteexec

import (
	"context"
	"errors"
)

// Estas acciones solo existen en Windows. Los stubs dejan compilar y testear la
// verificacion de firma en cualquier plataforma de CI.

func EjecutarAccountAction(_ context.Context, _ AccountActionPayload) (int, string, error) {
	return -1, "", errors.New("account_action solo esta disponible en Windows")
}

func EjecutarHarden(_ context.Context, _ HardenPayload) (int, string, error) {
	return -1, "", errors.New("harden solo esta disponible en Windows")
}

func EjecutarAislamiento(_ context.Context, _ IsolatePayload) (int, string, error) {
	return -1, "", errors.New("network_isolate solo esta disponible en Windows")
}
