//go:build windows

package collector

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Enlace con la API de Terminal Services (WTS).
//
// POR QUE WTS Y NO GetLastInputInfo: el agente corre como servicio en la sesion
// 0, aislada de la del usuario desde Windows Vista. GetLastInputInfo devolveria
// la inactividad de la sesion 0 —que no tiene teclado ni raton— y reportaria
// que el equipo lleva horas inactivo mientras alguien trabaja delante. WTS es la
// unica via por la que un servicio puede observar la sesion interactiva real.
var (
	wtsapi32                       = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSEnumerateSessionsW      = wtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSQuerySessionInformation = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory              = wtsapi32.NewProc("WTSFreeMemory")
)

// Clases de informacion que se consultan.
const (
	wtsUserName    = 5
	wtsSessionInfo = 24
)

type wtsSessionInfoW struct {
	SessionID       uint32
	pWinStationName *uint16
	State           wtsConnectState
}

// wtsInfoW es el WTSINFOW de Windows. Solo interesan LastInputTime y LogonTime,
// pero la estructura tiene que declararse completa: el resto de campos
// determinan el desplazamiento de los que si se leen.
type wtsInfoW struct {
	State                   wtsConnectState
	SessionID               uint32
	IncomingBytes           uint32
	OutgoingBytes           uint32
	IncomingFrames          uint32
	OutgoingFrames          uint32
	IncomingCompressedBytes uint32
	OutgoingCompressedBytes uint32
	WinStationName          [32]uint16
	Domain                  [17]uint16
	UserName                [21]uint16
	ConnectTime             int64
	DisconnectTime          int64
	LastInputTime           int64
	LogonTime               int64
	CurrentTime             int64
}

// enumerarSesiones devuelve las sesiones interactivas con usuario.
//
// La sesion 0 se descarta siempre: es la de los servicios, no tiene usuario
// delante y reportarla como actividad seria inventar presencia humana donde no
// la hay.
func enumerarSesiones() ([]sesion, error) {
	var (
		pinfo *wtsSessionInfoW
		count uint32
	)

	r, _, err := procWTSEnumerateSessionsW.Call(
		0, // WTS_CURRENT_SERVER_HANDLE
		0, // reservado
		1, // version
		uintptr(unsafe.Pointer(&pinfo)),
		uintptr(unsafe.Pointer(&count)),
	)
	if r == 0 {
		return nil, fmt.Errorf("WTSEnumerateSessions: %w", err)
	}
	defer liberar(unsafe.Pointer(pinfo))

	lista := unsafe.Slice(pinfo, count)
	out := make([]sesion, 0, count)

	for _, s := range lista {
		if s.SessionID == 0 {
			continue
		}

		usuario := consultarCadena(s.SessionID, wtsUserName)
		if usuario == "" {
			// Sesion sin usuario: una pantalla de inicio de sesion, o una
			// sesion en proceso de cierre. No es actividad de nadie.
			continue
		}

		ses := sesion{ID: s.SessionID, Usuario: usuario, Estado: s.State}

		if info, ok := consultarInfo(s.SessionID); ok {
			// Los tiempos vienen como FILETIME (100 ns desde 1601). Se comparan
			// entre si —CurrentTime menos LastInputTime— en vez de convertir a
			// hora local: asi la inactividad no depende de la zona horaria ni de
			// que el reloj del equipo este bien puesto.
			if info.CurrentTime > info.LastInputTime && info.LastInputTime > 0 {
				ses.Inactivo = time.Duration(info.CurrentTime-info.LastInputTime) * 100 * time.Nanosecond
			}
			if info.LogonTime > 0 {
				ses.LogonTime = time.Unix(0, (info.LogonTime-116444736000000000)*100)
			}
		}

		out = append(out, ses)
	}

	return out, nil
}

func consultarCadena(sessionID uint32, clase uint32) string {
	var (
		buf   *uint16
		bytes uint32
	)

	r, _, _ := procWTSQuerySessionInformation.Call(
		0,
		uintptr(sessionID),
		uintptr(clase),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&bytes)),
	)
	if r == 0 || buf == nil {
		return ""
	}
	defer liberar(unsafe.Pointer(buf))

	return windows.UTF16PtrToString(buf)
}

func consultarInfo(sessionID uint32) (wtsInfoW, bool) {
	var (
		buf   *wtsInfoW
		bytes uint32
	)

	r, _, _ := procWTSQuerySessionInformation.Call(
		0,
		uintptr(sessionID),
		uintptr(wtsSessionInfo),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&bytes)),
	)
	if r == 0 || buf == nil {
		return wtsInfoW{}, false
	}
	defer liberar(unsafe.Pointer(buf))

	return *buf, true
}

// liberar devuelve a Windows la memoria que reservo la propia API.
//
// WTSFreeMemory es void: lo que devuelve Call no es un error suyo sino el
// GetLastError que quedara de antes, asi que comprobarlo daria falsos positivos.
// Se descarta aqui, en un solo sitio y a la vista, en vez de callarlo en la
// configuracion del linter.
func liberar(p unsafe.Pointer) {
	_, _, _ = procWTSFreeMemory.Call(uintptr(p))
}
