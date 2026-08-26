//go:build windows

package remoteexec

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows"
)

var procWTSDisconnectSession = windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSDisconnectSession")

// EjecutarLock bloquea el equipo desconectando la sesion interactiva activa: el
// usuario queda en la pantalla de inicio de sesion y debe volver a autenticarse.
// La sesion NO se cierra (los programas siguen abiertos), asi que no se pierde
// trabajo; es el "bloquea esto ahora" para un equipo perdido o robado.
//
// Se hace por WTSDisconnectSession y no por LockWorkStation porque el agente
// corre como SYSTEM en la sesion 0: LockWorkStation bloquearia una sesion sin
// escritorio y no la del usuario. Disconnect sobre la sesion de consola activa si
// afecta a la persona que esta usando el equipo.
func EjecutarLock(_ context.Context) (int, string, error) {
	sesion := windows.WTSGetActiveConsoleSessionId()
	if sesion == 0xFFFFFFFF {
		return -1, "", fmt.Errorf("no hay una sesion de consola activa que bloquear")
	}
	// WTSDisconnectSession(WTS_CURRENT_SERVER_HANDLE = 0, sessionId, bWait = TRUE).
	r, _, err := procWTSDisconnectSession.Call(0, uintptr(sesion), 1)
	if r == 0 {
		return -1, "", fmt.Errorf("no se pudo bloquear la sesion: %w", err)
	}
	return 0, fmt.Sprintf("sesion %d bloqueada (desconectada)", sesion), nil
}
