//go:build windows

package collector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// IntervaloApps es cada cuanto se enumeran los procesos.
//
// Un minuto: enumerar procesos es mas caro que enumerar sesiones y el dato que
// se busca —que programas usa la gente— no cambia de un segundo a otro. Una app
// abierta y cerrada dentro del mismo minuto se pierde; a cambio, el agente no se
// nota en un equipo modesto, que es la condicion de que nunca estorbe al usuario.
const IntervaloApps = time.Minute

var procProcessIdToSessionId = windows.NewLazySystemDLL("kernel32.dll").NewProc("ProcessIdToSessionId")

// AppsCollector reporta que aplicaciones abre cada usuario y, si la politica lo
// pide, controla (alerta o termina) las de la lista de bloqueo.
type AppsCollector struct {
	log      zerolog.Logger
	maquina  *maquinaApps
	politica func() *contract.Policy
}

func NewAppsCollector(log zerolog.Logger, politica func() *contract.Policy) *AppsCollector {
	return &AppsCollector{
		log:      log.With().Str("recolector", "apps").Logger(),
		maquina:  nuevaMaquinaApps(),
		politica: politica,
	}
}

// controlApp devuelve el modo de control para una app ("" si no se controla).
// Nombre exacto del ejecutable, insensible a mayusculas.
// protegidoDeAllowlist son ejecutables que el modo lista blanca NUNCA cierra,
// aunque no esten en la lista: cerrarlos dejaria el equipo inutilizable. El resto
// de procesos criticos del sistema ya se filtran en `enumerar` (esRuidoDelSistema
// + solo sesiones interactivas), pero explorer.exe —el escritorio— si llega hasta
// aqui y hay que blindarlo explicitamente.
var protegidoDeAllowlist = map[string]bool{
	"explorer.exe": true,
}

// coincide indica si el identificador `id` de una lista (por .exe, por SHA-256 o
// por editor firmante) casa con la app: su ejecutable, su hash o su editor.
func coincide(id, exe, hash, editor string) bool {
	n := normalizar(id)
	if n == normalizar(exe) {
		return true
	}
	if hash != "" && strings.EqualFold(id, hash) {
		return true
	}
	if editor != "" && strings.EqualFold(strings.TrimSpace(id), strings.TrimSpace(editor)) {
		return true
	}
	return false
}

// controlApp decide el modo de control de una app, pudiendo casar por nombre,
// hash o editor, y aplicando "bloquear sin firmar". `firmada` nil = desconocido.
func (c *AppsCollector) controlApp(exe, hash, editor string, firmada *bool) contract.AppsMode {
	if c.politica == nil {
		return ""
	}
	p := c.politica()
	if p == nil || p.Apps.Mode == "" || p.Apps.Mode == contract.AppsAllow {
		return ""
	}

	// Modo lista blanca: se controla TODO lo que no este permitido.
	if p.Apps.Mode == contract.AppsAllowlist {
		if protegidoDeAllowlist[normalizar(exe)] {
			return ""
		}
		for _, a := range p.Apps.Allowlist {
			if coincide(a, exe, hash, editor) {
				return ""
			}
		}
		if p.Apps.AllowlistEnforce {
			return contract.AppsBlock
		}
		return contract.AppsAlert
	}

	// Modos alert/block: se controla lo que este en la lista negra o, si se
	// activo, lo que no tenga firma valida.
	for _, b := range p.Apps.Blocklist {
		if coincide(b, exe, hash, editor) {
			return p.Apps.Mode
		}
	}
	if p.Apps.BlockUnsigned && firmada != nil && !*firmada && !protegidoDeAllowlist[normalizar(exe)] {
		return p.Apps.Mode
	}
	return ""
}

// terminarApp mata todos los procesos cuyo ejecutable coincide con `exe`.
// Devuelve cuantos cerro. El agente corre como SYSTEM, asi que puede terminar
// procesos de la sesion del usuario.
func (c *AppsCollector) terminarApp(procesos []proceso, exe string) int {
	n := normalizar(exe)
	muertos := 0
	for _, p := range procesos {
		if normalizar(p.Exe) != n {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, p.PID)
		if err != nil {
			continue
		}
		if windows.TerminateProcess(h, 1) == nil {
			muertos++
		}
		_ = windows.CloseHandle(h)
	}
	return muertos
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

	for i := range eventos {
		app, _ := eventos[i].Payload["app"].(string)

		// Hash y firma SOLO para apps recien abiertas (las que traen la ruta): se
		// calculan aqui, al emitir, no en el sondeo de siembra ni en cada ciclo.
		var hash, editor string
		var firmada *bool
		if ruta, ok := eventos[i].Payload["executable_path"].(string); ok && ruta != "" {
			hash = sha256Archivo(ruta)
			editor, firmada = firmaAuthenticode(ruta)
			if hash != "" {
				eventos[i].Payload["sha256"] = hash
			}
			if editor != "" {
				eventos[i].Payload["publisher"] = editor
			}
			if firmada != nil {
				eventos[i].Payload["signed"] = *firmada
			}
		}

		modo := c.controlApp(app, hash, editor, firmada)
		if modo == "" {
			continue
		}
		if modo == contract.AppsBlock {
			muertos := c.terminarApp(procesos, app)
			eventos[i].Payload["enforcement"] = "terminated"
			c.log.Warn().Str("app", app).Int("procesos", muertos).
				Msg("aplicacion no autorizada: terminada")
		} else {
			eventos[i].Payload["enforcement"] = "alert"
			c.log.Info().Str("app", app).Msg("aplicacion no autorizada: alertada")
		}
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
