//go:build windows

package remoteexec

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procWTSQueryUserToken = windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSQueryUserToken")

// EjecutarLock bloquea la estacion: muestra la pantalla de bloqueo y exige la
// contrasena para volver. La sesion NO se cierra (los programas siguen), asi que
// no se pierde trabajo; es el "bloquea esto ahora" para un equipo perdido.
//
// Se hace ejecutando LockWorkStation EN LA SESION DEL USUARIO: el agente corre
// como SYSTEM en la sesion 0, donde LockWorkStation no afectaria al usuario. Se
// obtiene el token de la sesion de consola activa y se lanza rundll32 con el, la
// misma tecnica que usa la captura de pantalla. (WTSDisconnectSession no sirve:
// desconecta sesiones RDP, pero no bloquea la consola fisica local.)
func EjecutarLock(ctx context.Context) (int, string, error) {
	sesion := windows.WTSGetActiveConsoleSessionId()
	if sesion == 0xFFFFFFFF {
		return -1, "", fmt.Errorf("no hay una sesion de consola activa que bloquear")
	}
	var token windows.Token
	r, _, err := procWTSQueryUserToken.Call(uintptr(sesion), uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		// Sin token de usuario = no hay nadie con sesion iniciada: el equipo ya
		// esta en la pantalla de inicio, que es justo el estado "bloqueado". No es
		// un fallo que reportar en rojo; el objetivo ya se cumple.
		return 0, fmt.Sprintf("no hay usuario con sesion iniciada; el equipo ya esta en la pantalla de inicio (%v)", err), nil
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
