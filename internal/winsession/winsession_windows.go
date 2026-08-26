//go:build windows

// Package winsession resuelve el token del usuario que esta usando el equipo.
//
// El agente corre como SYSTEM en la sesion 0, donde no hay escritorio de usuario.
// Para actuar sobre la sesion de la persona (bloquear, capturar, avisar) hace
// falta su token. NO sirve WTSGetActiveConsoleSessionId: solo ve la consola
// fisica y en un equipo por Escritorio remoto (RDP) el usuario esta en otra
// sesion. Aqui se ENUMERAN todas y se toma la primera activa con token.
package winsession

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wtsapi32                 = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSEnumerateSessions = wtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSFreeMemory        = wtsapi32.NewProc("WTSFreeMemory")
	procWTSQueryUserToken    = wtsapi32.NewProc("WTSQueryUserToken")
)

// sessionInfo refleja WTS_SESSION_INFOW.
type sessionInfo struct {
	SessionID      uint32
	WinStationName *uint16
	State          uint32 // WTS_CONNECTSTATE_CLASS
}

// wtsActive es WTSActive: sesion con usuario conectado e interactuando.
const wtsActive = 0

// TokenUsuarioActivo devuelve el token de la sesion de usuario activa (consola o
// RDP) y su id. El llamante debe cerrar el token.
func TokenUsuarioActivo() (windows.Token, uint32, error) {
	var pSessions *sessionInfo
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
