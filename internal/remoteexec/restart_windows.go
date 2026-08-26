//go:build windows

package remoteexec

import (
	"context"
	"fmt"
	"os/exec"
)

// EjecutarRestart programa un reinicio del equipo con 60 segundos de aviso, para
// que el usuario alcance a guardar. El mensaje aparece en pantalla. No es un
// apagado sorpresa: un reinioc inmediato en la maquina de alguien es inaceptable.
func EjecutarRestart(ctx context.Context) (int, string, error) {
	cmd := exec.CommandContext(ctx, "shutdown.exe", "/r", "/t", "60",
		"/c", "Nortis: su equipo se reiniciara en 60 segundos por una tarea administrativa.")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return -1, string(out), fmt.Errorf("no se pudo programar el reinicio: %w", err)
	}
	return 0, "reinicio programado en 60 segundos", nil
}
