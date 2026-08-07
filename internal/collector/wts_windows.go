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
	wtsUserName = 5
	// wtsSessionInfoEx (25) en vez de wtsSessionInfo (24): la clase basica no
	// trae el estado de bloqueo, que es de donde sale la presencia real. Ver
	// consultarInfo.
	wtsSessionInfoEx = 25
)

// Estado de bloqueo que reporta SessionFlags.
const (
	wtsSessionStateLock   int32 = 0
	wtsSessionStateUnlock int32 = 1
)

type wtsSessionInfoW struct {
	SessionID       uint32
	pWinStationName *uint16
	State           wtsConnectState
}

// wtsInfoExLevel1W es el WTSINFOEX_LEVEL1_W de Windows.
//
// Se declara completa aunque solo interesen cuatro campos: el resto determina el
// desplazamiento de los que si se leen, y un desplazamiento mal calculado no da
// error — devuelve basura con pinta de dato.
type wtsInfoExLevel1W struct {
	SessionID    uint32
	SessionState wtsConnectState
	// SessionFlags dice si la pantalla esta bloqueada. Es el unico indicador de
	// presencia que un servicio puede leer de la sesion de consola.
	SessionFlags            int32
	WinStationName          [33]uint16
	UserName                [21]uint16
	DomainName              [18]uint16
	LogonTime               int64
	ConnectTime             int64
	DisconnectTime          int64
	LastInputTime           int64
	CurrentTime             int64
	IncomingBytes           uint32
	OutgoingBytes           uint32
	IncomingFrames          uint32
	OutgoingFrames          uint32
	IncomingCompressedBytes uint32
	OutgoingCompressedBytes uint32
}

type wtsInfoExW struct {
	Level uint32
	Data  wtsInfoExLevel1W
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
			ses.Bloqueada = info.SessionFlags == wtsSessionStateLock

			// Los tiempos vienen como FILETIME (100 ns desde 1601). LastInputTime
			// se compara contra CurrentTime del propio Windows en vez de contra el
			// reloj del proceso: asi la inactividad no depende de la zona horaria
			// ni de que el reloj del equipo este bien puesto.
			//
			// Windows deja LastInputTime en cero para las sesiones de consola —
			// solo lo rellena en sesiones remotas—, y por eso la presencia se
			// decide por el bloqueo de pantalla. Aqui se aprovecha cuando SI viene.
			if info.LastInputTime > 0 && info.CurrentTime > info.LastInputTime {
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

// consultarInfo devuelve la informacion extendida de una sesion.
//
// Se pide la clase EXTENDIDA (25) y no la basica (24) por una razon concreta y
// comprobada en maquina: la basica no trae SessionFlags, y su LastInputTime vale
// cero en las sesiones de consola. Con la clase basica, un PC de escritorio —el
// caso normal en la oficina de un cliente— nunca habria reportado inactividad.
func consultarInfo(sessionID uint32) (wtsInfoExLevel1W, bool) {
	var (
		buf   *wtsInfoExW
		bytes uint32
	)

	r, _, _ := procWTSQuerySessionInformation.Call(
		0,
		uintptr(sessionID),
		uintptr(wtsSessionInfoEx),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&bytes)),
	)
	if r == 0 || buf == nil {
		return wtsInfoExLevel1W{}, false
	}
	defer liberar(unsafe.Pointer(buf))

	// Level 1 es el unico formato definido. Si Windows devolviera otro, los
	// campos estarian en otro sitio y se leeria basura: mejor no devolver nada.
	if buf.Level != 1 {
		return wtsInfoExLevel1W{}, false
	}
	return buf.Data, true
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
