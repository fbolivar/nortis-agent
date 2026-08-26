//go:build windows

package remoteexec

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// EjecutarInstallMSI descarga el MSI (verificando su sha256), lo instala en
// silencio con msiexec y devuelve el exit code y la salida combinada. El binario
// se borra al terminar. No verifica la firma: eso lo hace el ciclo del servicio
// ANTES de llamar aqui — a esta funcion solo llega lo ya autorizado.
func EjecutarInstallMSI(ctx context.Context, p InstallMSIPayload) (int, string, error) {
	ruta, err := descargarVerificado(ctx, p.URL, p.SHA256, ".msi")
	if err != nil {
		return -1, "", err
	}
	defer func() { _ = os.Remove(ruta) }()

	// /qn: sin interfaz. /norestart: no reiniciar el equipo por su cuenta —un
	// reinicio sorpresa en la maquina de un usuario es inaceptable; si hace falta,
	// se encarga una tarea `restart` explicita.
	args := []string{"/i", ruta, "/qn", "/norestart"}
	if strings.TrimSpace(p.Args) != "" {
		args = append(args, strings.Fields(p.Args)...)
	}

	cmd := exec.CommandContext(ctx, "msiexec.exe", args...)
	out, runErr := cmd.CombinedOutput()

	if cmd.ProcessState == nil {
		return -1, string(out), fmt.Errorf("no se pudo ejecutar msiexec: %w", runErr)
	}
	code := cmd.ProcessState.ExitCode()

	// 0 = ok; 3010 = ok pero requiere reinicio. Cualquier otro codigo es fallo.
	if code != 0 && code != 3010 {
		if runErr == nil {
			runErr = fmt.Errorf("msiexec devolvio codigo %d", code)
		}
		return code, string(out), runErr
	}
	return code, string(out), nil
}
