package collector

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// VentanaRepeticion es cuanto se ignora una repeticion sobre el MISMO archivo.
//
// Guardar un documento de Word no produce una escritura: produce media docena
// —archivo temporal, renombrado, actualizacion de metadatos—. Sin esta ventana,
// una jornada normal de ofimatica llenaria la cola de eventos que describen el
// mismo hecho, y el analista veria cuarenta lineas donde hubo un guardado.
const VentanaRepeticion = 5 * time.Second

// MaxEventosArchivoPorMinuto acota lo que un solo equipo puede generar.
//
// Descomprimir un ZIP grande o sincronizar una carpeta de red produce miles de
// escrituras legitimas en segundos. Sin tope, ese pico se come el limite de tasa
// del equipo y deja fuera la telemetria que si importa. Lo descartado se
// registra en el log: un recorte silencioso se leeria como "no paso nada".
const MaxEventosArchivoPorMinuto = 300

// operacionArchivo es lo que ocurrio con el archivo.
type operacionArchivo int

const (
	archivoCreado operacionArchivo = iota
	archivoModificado
	archivoEliminado
	archivoRenombrado
)

func (o operacionArchivo) tipoEvento() contract.EventType {
	switch o {
	case archivoCreado:
		return contract.EventFileCreated
	case archivoEliminado:
		return contract.EventFileDeleted
	default:
		// Un renombrado es una modificacion con ruta anterior: no existe un
		// event_type propio en el contrato y crear uno obligaria a tocar el enum
		// de Postgres para no ganar nada — `previous_path` ya dice lo que paso.
		return contract.EventFileModified
	}
}

/* ------------------------------------------------------------ Filtrado --- */

// carpetasIgnoradas son segmentos de ruta que nunca interesan.
//
// No es una lista de comodidad: sin ella el agente reporta el churn del propio
// Windows —cache de navegadores, indices, archivos de sesion— y ahoga la señal.
// El criterio para entrar aqui es que NINGUNA fuga de informacion se
// materializa ahi: un archivo en la cache de Chrome no es un archivo que alguien
// se lleve.
var carpetasIgnoradas = map[string]bool{
	"appdata":                  true,
	"temp":                     true,
	"tmp":                      true,
	"$recycle.bin":             true,
	"system volume information": true,
	"windows":                  true,
	"programdata":              true,
	"program files":            true,
	"program files (x86)":      true,
	"node_modules":             true,
	".git":                     true,
	".cache":                   true,
	"__pycache__":              true,
}

// extensionesIgnoradas son archivos de trabajo intermedios. Nadie exfiltra un
// .tmp: es el rastro de otra operacion que ya se reporta por si misma.
var extensionesIgnoradas = map[string]bool{
	".tmp": true, ".temp": true, ".log": true, ".lock": true, ".swp": true,
	".crdownload": true, ".part": true, ".partial": true, ".download": true,
	".ldb": true, ".etl": true, ".dmp": true, ".pyc": true, ".obj": true,
}

// esRuido decide si una ruta no merece un evento.
func esRuido(ruta string) bool {
	if ruta == "" {
		return true
	}

	base := strings.ToLower(filepath.Base(ruta))

	// Archivos de bloqueo de Office: "~$informe.docx". Se crean y borran en cada
	// apertura y no representan ningun movimiento de informacion.
	if strings.HasPrefix(base, "~$") || strings.HasPrefix(base, ".~lock.") {
		return true
	}

	if extensionesIgnoradas[strings.ToLower(filepath.Ext(base))] {
		return true
	}

	for _, seg := range strings.Split(strings.ToLower(filepath.ToSlash(ruta)), "/") {
		if carpetasIgnoradas[seg] {
			return true
		}
	}
	return false
}

/* ------------------------------------------------- Maquina de estado --- */

// cambioArchivo es un cambio crudo, tal como lo entrega el sistema.
type cambioArchivo struct {
	Ruta         string
	RutaAnterior string
	Operacion    operacionArchivo
	Extraible    bool
	Usuario      string
	TamanoByte   int64
}

// maquinaArchivos filtra ruido, agrupa repeticiones y acota el caudal.
//
// Pura y sin tocar el disco: el filtrado y la agrupacion son donde estan los
// errores que inundan la cola, y aqui se pueden probar con rutas inventadas.
type maquinaArchivos struct {
	visto map[string]time.Time

	// Ventana de caudal.
	inicioVentana time.Time
	enVentana     int
}

func nuevaMaquinaArchivos() *maquinaArchivos {
	return &maquinaArchivos{visto: map[string]time.Time{}}
}

// observar convierte un cambio en evento, o lo descarta.
//
// El segundo retorno dice si se descarto por caudal, para que el llamador pueda
// registrarlo. Lo que se tira tiene que ser visible en algun sitio.
func (m *maquinaArchivos) observar(c cambioArchivo, ahora time.Time) (*contract.Event, bool) {
	if esRuido(c.Ruta) {
		return nil, false
	}

	// Repeticion sobre el mismo archivo dentro de la ventana.
	clave := strings.ToLower(c.Ruta)
	if ultimo, ok := m.visto[clave]; ok && ahora.Sub(ultimo) < VentanaRepeticion {
		return nil, false
	}

	// Ventana de caudal. Se reinicia cada minuto.
	if ahora.Sub(m.inicioVentana) >= time.Minute {
		m.inicioVentana = ahora
		m.enVentana = 0
	}
	if m.enVentana >= MaxEventosArchivoPorMinuto {
		return nil, true
	}
	m.enVentana++

	m.visto[clave] = ahora
	m.limpiar(ahora)

	payload := map[string]any{
		"path":      c.Ruta,
		"extension": strings.ToLower(filepath.Ext(c.Ruta)),
	}
	if c.RutaAnterior != "" {
		payload["previous_path"] = c.RutaAnterior
	}
	if c.Usuario != "" {
		payload["user"] = c.Usuario
	}
	if c.TamanoByte > 0 {
		payload["size_bytes"] = c.TamanoByte
	}
	// `is_removable` es la señal fuerte: un archivo que aparece en una unidad
	// extraible es informacion saliendo del perimetro, no un guardado cualquiera.
	if c.Extraible {
		payload["is_removable"] = true
	}

	return &contract.Event{
		Type:       c.Operacion.tipoEvento(),
		OccurredAt: ahora,
		Payload:    payload,
	}, false
}

// limpiar descarta rutas viejas del mapa de repeticiones.
//
// Sin esto el mapa crece con cada archivo tocado en toda la vida del servicio, y
// un agente que lleva semanas encendido acaba con cientos de miles de rutas en
// memoria — una fuga de memoria lenta en un proceso que corre como SYSTEM.
func (m *maquinaArchivos) limpiar(ahora time.Time) {
	if len(m.visto) < 4096 {
		return
	}
	for k, t := range m.visto {
		if ahora.Sub(t) > VentanaRepeticion {
			delete(m.visto, k)
		}
	}
}
