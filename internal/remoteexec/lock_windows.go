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

var (
	wtsapi32                 = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSEnumerateSessions = wtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSFreeMemory        = wtsapi32.NewProc("WTSFreeMemory")
	procWTSQueryUserToken    = wtsapi32.NewProc("WTSQueryUserToken")
)

// wtsSessionInfo refleja WTS_SESSION_INFOW.
type wtsSessionInfo struct {
	SessionID      uint32
	WinStationName *uint16
	State          uint32 // WTS_CONNECTSTATE_CLASS
}

// wtsActive es WTSActive: sesion con un usuario conectado e interactuando (sea la
// consola fisica o una sesion RDP).
const wtsActive = 0

// tokenUsuarioActivo devuelve el token de la sesion de usuario ACTIVA y su id.
//
// Enumera TODAS las sesiones en vez de mirar solo la consola fisica
// (WTSGetActiveConsoleSessionId): en un equipo al que se entra por Escritorio
// remoto, el usuario no esta en la consola sino en una sesion RDP, y mirar solo
// la consola devolvia "sin usuario" aunque hubiera alguien trabajando.
func tokenUsuarioActivo() (windows.Token, uint32, error) {
	// pSessions se declara como puntero TIPADO (no uintptr) para que el manejo del
	// arreglo use unsafe.Slice en vez de aritmetica de punteros, que `go vet`
	// marca como posible mal uso de unsafe.Pointer.
	var pSessions *wtsSessionInfo
	var count uint32
	r, _, err := procWTSEnumerateSessions.Call(0, 0, 1,
		uintptr(unsafe.Pointer(&pSessions)), uintptr(unsafe.Pointer(&count)))
	if r == 0 {
		return 0, 0, fmt.Errorf("no se pudieron enumerar las sesiones: %w", err)
	}
	defer func() { _, _, _ = procWTSFreeMemory.Call(uintptr(unsafe.Pointer(pSessions))) }()

	sesiones := unsafe.Slice(pSessions, count)
	for i := range sesiones {
		if sesiones[i].State != wtsActive {
			continue
		}
		var token windows.Token
		ok, _, _ := procWTSQueryUserToken.Call(uintptr(sesiones[i].SessionID), uintptr(unsafe.Pointer(&token)))
		if ok != 0 {
			return token, sesiones[i].SessionID, nil
		}
	}
	return 0, 0, fmt.Errorf("no hay una sesion de usuario activa")
}

// EjecutarLock bloquea la estacion: muestra la pantalla de bloqueo y exige la
// contrasena para volver, sin cerrar la sesion (no se pierde trabajo).
//
// Ejecuta LockWorkStation EN LA SESION DEL USUARIO ACTIVO (consola o RDP): el
// agente corre como SYSTEM en la sesion 0, donde LockWorkStation no afectaria a
// nadie. Si no hay ningun usuario con sesion, el equipo ya esta en la pantalla de
// inicio —el estado bloqueado— y se reporta como exito.
func EjecutarLock(ctx context.Context) (int, string, error) {
	token, sesion, err := tokenUsuarioActivo()
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
