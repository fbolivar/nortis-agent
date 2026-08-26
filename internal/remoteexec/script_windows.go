//go:build windows

package remoteexec

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// EjecutarRunScript escribe el script firmado a un archivo temporal y lo corre
// con el interprete indicado, devolviendo exit code y salida combinada. El
// archivo se borra al terminar. La firma ya se verifico en el servicio; a aqui
// solo llega lo autorizado por la consola (admin + MFA + Ed25519).
func EjecutarRunScript(ctx context.Context, p RunScriptPayload) (int, string, error) {
	ext := ".ps1"
	if p.Interpreter == "cmd" {
		ext = ".cmd"
	}
	f, err := os.CreateTemp("", "nortis-script-*"+ext)
	if err != nil {
		return -1, "", err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.WriteString(p.Script); err != nil {
		_ = f.Close()
		return -1, "", err
	}
	if err := f.Close(); err != nil {
		return -1, "", err
	}

	var cmd *exec.Cmd
	if p.Interpreter == "cmd" {
		cmd = exec.CommandContext(ctx, "cmd.exe", "/c", tmp)
	} else {
		// -ExecutionPolicy Bypass para este proceso: el script viene firmado por la
		// consola, no de un origen arbitrario del disco. -NonInteractive para que
		// un prompt no cuelgue la tarea para siempre.
		cmd = exec.CommandContext(ctx, "powershell.exe",
			"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", tmp)
	}

	out, runErr := cmd.CombinedOutput()
	code := 0
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	} else if runErr != nil {
		code = -1
	}
	if code != 0 {
		if runErr == nil {
			runErr = fmt.Errorf("el script devolvio codigo %d", code)
		}
		return code, string(out), runErr
	}
	return code, string(out), nil
}
