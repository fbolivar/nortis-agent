//go:build windows

package remoteexec

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/fbolivar/nortis-agent/internal/winsession"
)

// EjecutarLock bloquea la estacion: muestra la pantalla de bloqueo y exige la
// contrasena para volver, sin cerrar la sesion (no se pierde trabajo).
//
// Ejecuta LockWorkStation EN LA SESION DEL USUARIO ACTIVO (consola o RDP): el
// agente corre como SYSTEM en la sesion 0, donde LockWorkStation no afectaria a
// nadie. Si no hay ningun usuario con sesion, el equipo ya esta en la pantalla de
// inicio —el estado bloqueado— y se reporta como exito.
func EjecutarLock(ctx context.Context) (int, string, error) {
	token, sesion, err := winsession.TokenUsuarioActivo()
	if err != nil {
		return 0, "no hay usuario con sesion activa; el equipo ya esta en la pantalla de inicio", nil
	}
	defer token.Close()

	cmd := exec.CommandContext(ctx, "rundll32.exe", "user32.dll,LockWorkStation")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token:         syscall.Token(token),
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
	if err := cmd.Run(); err != nil {
		return -1, "", fmt.Errorf("no se pudo bloquear la estacion: %w", err)
	}
	return 0, fmt.Sprintf("estacion bloqueada (sesion %d)", sesion), nil
}
