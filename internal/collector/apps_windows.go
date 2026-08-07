//go:build windows

package collector

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"
)

// IntervaloApps es cada cuanto se enumeran los procesos.
//
// Un minuto: enumerar procesos es mas caro que enumerar sesiones y el dato que
// se busca —que programas usa la gente— no cambia de un segundo a otro. Una app
// abierta y cerrada dentro del mismo minuto se pierde; a cambio, el agente no se
// nota en un equipo modesto, que es la condicion de que nunca estorbe al usuario.
const IntervaloApps = time.Minute

var procProcessIdToSessionId = windows.NewLazySystemDLL("kernel32.dll").NewProc("ProcessIdToSessionId")

// AppsCollector reporta que aplicaciones abre cada usuario.
type AppsCollector struct {
	log     zerolog.Logger
	maquina *maquinaApps
}

func NewAppsCollector(log zerolog.Logger) *AppsCollector {
	return &AppsCollector{
		log:     log.With().Str("recolector", "apps").Logger(),
		maquina: nuevaMaquinaApps(),
	}
}

func (c *AppsCollector) Name() string { return "apps" }

func (c *AppsCollector) Run(ctx context.Context, emit Emit) {
	ticker := time.NewTicker(IntervaloApps)
	defer ticker.Stop()

	// Igual que en sesiones: el primer sondeo solo siembra. Sin esto, reiniciar
	// el agente reportaria como recien abierto todo lo que ya estaba abierto.
	c.sondear(nil)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.sondear(emit)
		}
	}
}

// sondear enumera y emite. Con emit nil solo actualiza el estado (siembra).
func (c *AppsCollector) sondear(emit Emit) {
	procesos, err := c.enumerar()
	if err != nil {
		c.log.Warn().Err(err).Msg("no se pudieron enumerar los procesos")
		return
	}

	eventos, descartados := c.maquina.observar(procesos, time.Now().UTC())
	if descartados > 0 {
		c.log.Warn().Int("descartados", descartados).Int("tope", MaxAppsPorSondeo).
			Msg("se alcanzo el tope de aplicaciones por sondeo")
	}
	if emit == nil {
		c.log.Debug().Int("procesos", len(procesos)).Msg("estado inicial de aplicaciones registrado")
		return
	}
	for _, e := range eventos {
		emit(e)
	}
}

// enumerar devuelve los procesos de las sesiones interactivas.
func (c *AppsCollector) enumerar() ([]proceso, error) {
	// Usuario por sesion: el proceso solo sabe en que sesion corre, y sin el
	// nombre el reporte diria "se abrio Excel" sin decir quien.
	usuarios := map[uint32]string{}
	if sesiones, err := enumerarSesiones(); err == nil {
		for _, s := range sesiones {
			usuarios[s.ID] = s.Usuario
		}
	} else {
		c.log.Debug().Err(err).Msg("sin nombres de usuario para este sondeo")
	}

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snap, &entry); err != nil {
		return nil, fmt.Errorf("Process32First: %w", err)
	}

	var out []proceso
	for {
		exe := windows.UTF16ToString(entry.ExeFile[:])
		pid := entry.ProcessID

		if sesion, ok := sesionDe(pid); ok && sesion != 0 && !esRuidoDelSistema(exe) {
			p := proceso{PID: pid, Exe: exe, SessionID: sesion, Usuario: usuarios[sesion]}
			// La ruta solo se resuelve la primera vez que se ve la app en esa
			// sesion: abrir cada proceso en cada sondeo, para un dato que no
			// cambia, seria gasto puro.
			if !c.maquina.conocido(sesion, exe) {
				p.Ruta = rutaEjecutable(pid)
			}
			out = append(out, p)
		}

		if err := windows.Process32Next(snap, &entry); err != nil {
			// ERROR_NO_MORE_FILES es el final normal del recorrido.
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return nil, fmt.Errorf("Process32Next: %w", err)
		}
	}

	return out, nil
}

func sesionDe(pid uint32) (uint32, bool) {
	var sesion uint32
	r, _, _ := procProcessIdToSessionId.Call(uintptr(pid), uintptr(unsafe.Pointer(&sesion)))
	return sesion, r != 0
}

// rutaEjecutable devuelve la ruta del binario, o cadena vacia si no se puede.
//
// Se pide PROCESS_QUERY_LIMITED_INFORMATION, el permiso mas debil que sirve:
// basta para preguntar el nombre de la imagen y no da acceso a la memoria del
// proceso. Que falle es normal y no es un error a reportar —procesos protegidos
// del sistema, o que murieron entre la enumeracion y la consulta—: el evento se
// emite igual, solo sin ruta.
func rutaEjecutable(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer func() { _ = windows.CloseHandle(h) }()

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}
