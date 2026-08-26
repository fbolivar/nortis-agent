//go:build windows

package collector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"

	"github.com/fbolivar/nortis-agent/internal/enforce"
)

// FilesCollector vigila la creacion, modificacion y borrado de archivos.
//
// Alimenta las dos reglas de `storage` del motor DLP: carpeta no autorizada y
// extension prohibida. Sin este recolector esas reglas nunca disparan y la
// mitad del valor del producto no existe.
//
// # QUE SE VIGILA Y POR QUE NO TODO EL DISCO
//
// Vigilar C:\ entero es tecnicamente trivial y operativamente ruinoso: Windows
// escribe permanentemente en sus propias carpetas y el agente pasaria el dia
// reportando su propio sistema operativo. Se vigilan los sitios donde de verdad
// aterriza la informacion de una persona —escritorio, documentos, descargas— y
// las unidades extraibles, que es por donde sale.
//
// DETECCION Y REMEDIACION. Prevenir un guardado en el instante exacto exige un
// driver minifilter en modo kernel. En modo usuario se hace lo siguiente mejor:
// el archivo llega a escribirse y el agente lo RETIRA enseguida a cuarentena si
// cae fuera de las carpetas permitidas (regla `storage.allowed_paths`). Queda una
// ventana de milisegundos, pero el documento no persiste donde no debe. La
// decision es conservadora —solo documentos, nunca rutas del sistema— y
// recuperable —cuarentena, no borrado— (ver internal/enforce/storage.go).
type FilesCollector struct {
	log     zerolog.Logger
	maquina *maquinaArchivos

	// rutasExtra son carpetas de la politica (allowed_paths, confidential_paths)
	// que interesa vigilar aunque esten fuera del perfil del usuario.
	rutasExtra func() []string

	// allowed son las carpetas permitidas (storage.allowed_paths). Si esta vacia,
	// no se remedia nada: "sin carpeta seleccionada" no es "prohibido en todas
	// partes".
	allowed func() []string
	// dirCuarentena es donde se retiran los archivos remediados.
	dirCuarentena string

	// clasificar etiqueta el archivo por su contenido (Fase B). Nulo si no hay
	// clasificacion por contenido configurada (o sin consentimiento). Devuelve la
	// etiqueta, nunca el contenido.
	clasificar func(ruta string) string
}

// UsarClasificador conecta la clasificacion de contenido: el colector añadira la
// etiqueta a cada evento de archivo cuando la funcion devuelva una.
func (c *FilesCollector) UsarClasificador(fn func(ruta string) string) {
	c.clasificar = fn
}

func NewFilesCollector(log zerolog.Logger, rutasExtra, allowed func() []string, dirCuarentena string) *FilesCollector {
	return &FilesCollector{
		log:           log.With().Str("recolector", "archivos").Logger(),
		maquina:       nuevaMaquinaArchivos(),
		rutasExtra:    rutasExtra,
		allowed:       allowed,
		dirCuarentena: dirCuarentena,
	}
}

// rutasPermitidas devuelve las carpetas permitidas, tolerando un accesor nulo.
func (c *FilesCollector) rutasPermitidas() []string {
	if c.allowed == nil {
		return nil
	}
	return c.allowed()
}

func (c *FilesCollector) Name() string { return "archivos" }

// IntervaloRevisionRaices es cada cuanto se revisa si hay carpetas nuevas que
// vigilar: una memoria USB recien conectada, o una ruta que la politica acaba de
// añadir.
const IntervaloRevisionRaices = 15 * time.Second

func (c *FilesCollector) Run(ctx context.Context, emit Emit) {
	var (
		mu        sync.Mutex
		vigiladas = map[string]context.CancelFunc{}
	)

	// Al salir se detienen todas las vigilancias. Sin esto, cada reinicio del
	// servicio dejaria goroutines bloqueadas en ReadDirectoryChangesW con un
	// manejador abierto sobre el volumen, y desmontar un USB fallaria.
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, cancel := range vigiladas {
			cancel()
		}
	}()

	revisar := func() {
		mu.Lock()
		defer mu.Unlock()

		deseadas := map[string]bool{}
		for _, r := range c.raices() {
			deseadas[r] = true
		}

		// Alta de carpetas nuevas.
		for r := range deseadas {
			if _, ya := vigiladas[r]; ya {
				continue
			}
			hijo, cancel := context.WithCancel(ctx)
			vigiladas[r] = cancel
			go c.vigilar(hijo, r, emit)
			c.log.Info().Str("ruta", r).Msg("vigilando carpeta")
		}

		// Baja de las que desaparecieron: una memoria USB retirada, sobre todo.
		for r, cancel := range vigiladas {
			if !deseadas[r] {
				cancel()
				delete(vigiladas, r)
				c.log.Info().Str("ruta", r).Msg("se dejo de vigilar la carpeta")
			}
		}
	}

	revisar()

	t := time.NewTicker(IntervaloRevisionRaices)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			revisar()
		}
	}
}

// raices son las carpetas a vigilar en este momento.
func (c *FilesCollector) raices() []string {
	var out []string

	añadir := func(p string) {
		if p == "" {
			return
		}
		if st, err := os.Stat(p); err != nil || !st.IsDir() {
			return
		}
		out = append(out, filepath.Clean(p))
	}

	// Perfiles de usuario. Se recorre C:\Users en vez de usar la variable de
	// entorno del proceso porque el agente corre como SYSTEM: su USERPROFILE es
	// el del servicio, no el de la persona que usa el equipo.
	if usuarios := unidadSistema() + `\Users`; usuarios != "" {
		entradas, err := os.ReadDir(usuarios)
		if err == nil {
			for _, e := range entradas {
				if !e.IsDir() {
					continue
				}
				switch e.Name() {
				// Perfiles de plantilla y de servicio: no hay ninguna persona
				// detras, solo escrituras del sistema.
				case "Public", "Default", "Default User", "All Users":
					continue
				}
				perfil := filepath.Join(usuarios, e.Name())
				c.carpetasDeDocumentos(perfil, añadir)
			}
		}
	}

	// Unidades extraibles: la via de salida por excelencia.
	for _, letra := range unidadesExtraibles() {
		añadir(letra + `\`)
	}

	if c.rutasExtra != nil {
		for _, r := range c.rutasExtra() {
			añadir(r)
		}
	}
	return out
}

// carpetasDeDocumentos añade, para un perfil de usuario, las carpetas donde
// aterrizan sus documentos: Escritorio, Documentos y Descargas.
//
// EN MAQUINAS CORPORATIVAS CON ONEDRIVE, estas carpetas suelen estar REDIRIGIDAS
// (Known Folder Move): el Escritorio real no es C:\Users\x\Desktop sino
// C:\Users\x\OneDrive - Empresa\Escritorio. Vigilar solo las clasicas dejaria
// ciega la mitad del equipo. Por eso se recorren tambien las carpetas OneDrive
// del perfil, en español y en ingles.
func (c *FilesCollector) carpetasDeDocumentos(perfil string, añadir func(string)) {
	// Nombres de las carpetas, en los dos idiomas en que Windows las crea.
	subcarpetas := []string{
		"Desktop", "Documents", "Downloads",
		"Escritorio", "Documentos", "Descargas",
	}

	raicesUsuario := []string{perfil}

	// Cualquier carpeta del perfil que empiece por "OneDrive" es una raiz de
	// sincronizacion (OneDrive personal, o "OneDrive - <Empresa>").
	if entradas, err := os.ReadDir(perfil); err == nil {
		for _, e := range entradas {
			if e.IsDir() && strings.HasPrefix(strings.ToLower(e.Name()), "onedrive") {
				raicesUsuario = append(raicesUsuario, filepath.Join(perfil, e.Name()))
			}
		}
	}

	for _, raiz := range raicesUsuario {
		for _, sub := range subcarpetas {
			añadir(filepath.Join(raiz, sub))
		}
	}
}

func unidadSistema() string {
	if d := os.Getenv("SystemDrive"); d != "" {
		return d
	}
	return "C:"
}

func unidadesExtraibles() []string {
	mascara, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var out []string
	for i := uint(0); i < 26; i++ {
		if mascara&(1<<i) == 0 {
			continue
		}
		letra := string(rune('A'+i)) + ":"
		p, err := windows.UTF16PtrFromString(letra + `\`)
		if err != nil {
			continue
		}
		if windows.GetDriveType(p) == windows.DRIVE_REMOVABLE {
			out = append(out, letra)
		}
	}
	return out
}

/* --------------------------------------------- Vigilancia de una carpeta --- */

// Acciones que devuelve ReadDirectoryChangesW.
const (
	fileActionAdded = iota + 1
	fileActionRemoved
	fileActionModified
	fileActionRenamedOldName
	fileActionRenamedNewName
)

// fileNotifyInformation es la cabecera de cada cambio. El nombre va justo
// detras, en UTF-16 y SIN terminador, con la longitud en bytes.
type fileNotifyInformation struct {
	NextEntryOffset uint32
	Action          uint32
	FileNameLength  uint32
	// FileName sigue aqui, de longitud variable.
}

func (c *FilesCollector) vigilar(ctx context.Context, raiz string, emit Emit) {
	defer func() {
		// Un panico vigilando una carpeta no puede llevarse el recolector
		// entero: una memoria retirada a mitad de lectura es un caso normal.
		if r := recover(); r != nil {
			c.log.Error().Interface("panico", r).Str("ruta", raiz).
				Msg("vigilancia detenida tras un panico; el resto sigue")
		}
	}()

	rutaPtr, err := windows.UTF16PtrFromString(raiz)
	if err != nil {
		return
	}

	// FILE_FLAG_BACKUP_SEMANTICS es obligatorio para abrir un directorio.
	// FILE_SHARE_DELETE permite que el usuario borre o expulse la carpeta
	// mientras la vigilamos: sin el, el agente impediria desmontar un USB, que
	// es justo el tipo de estorbo que no puede causar.
	h, err := windows.CreateFile(
		rutaPtr,
		windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		c.log.Debug().Err(err).Str("ruta", raiz).Msg("no se pudo abrir la carpeta para vigilarla")
		return
	}

	// El cierre del manejador desbloquea la llamada pendiente. Es lo que hace que
	// cancelar el contexto termine de verdad esta goroutine.
	go func() {
		<-ctx.Done()
		_ = windows.CloseHandle(h)
	}()
	defer windows.CloseHandle(h)

	extraible := esExtraible(raiz)
	buf := make([]byte, 64*1024)
	var pendienteRenombrado string

	for {
		if ctx.Err() != nil {
			return
		}

		var devueltos uint32
		err := windows.ReadDirectoryChanges(
			h, &buf[0], uint32(len(buf)),
			true, // recursivo
			windows.FILE_NOTIFY_CHANGE_FILE_NAME|
				windows.FILE_NOTIFY_CHANGE_DIR_NAME|
				windows.FILE_NOTIFY_CHANGE_SIZE|
				windows.FILE_NOTIFY_CHANGE_LAST_WRITE,
			&devueltos, nil, 0,
		)
		if err != nil {
			// Ocurre al cerrar el manejador (parada) o al retirar el volumen.
			return
		}
		if devueltos == 0 {
			// El bufer se desbordo: hubo tantos cambios que Windows no pudo
			// contarlos. Se pierden esos, no el recolector — y se deja
			// constancia, porque un hueco silencioso en la evidencia es peor que
			// un hueco anotado.
			c.log.Warn().Str("ruta", raiz).
				Msg("desbordamiento de notificaciones; se perdieron cambios en esta carpeta")
			continue
		}

		usuario := usuarioDeSesionActiva()
		ahora := time.Now().UTC()

		off := uint32(0)
		for {
			info := (*fileNotifyInformation)(unsafe.Pointer(&buf[off]))

			inicio := off + uint32(unsafe.Sizeof(fileNotifyInformation{}))
			fin := inicio + info.FileNameLength
			if fin > devueltos {
				break
			}

			nombre := windows.UTF16ToString(
				unsafe.Slice((*uint16)(unsafe.Pointer(&buf[inicio])), info.FileNameLength/2),
			)
			completa := filepath.Join(raiz, nombre)

			cambio := cambioArchivo{
				Ruta:      completa,
				Extraible: extraible,
				Usuario:   usuario,
			}

			switch info.Action {
			case fileActionAdded:
				cambio.Operacion = archivoCreado
			case fileActionRemoved:
				cambio.Operacion = archivoEliminado
			case fileActionModified:
				cambio.Operacion = archivoModificado
			case fileActionRenamedOldName:
				// Se guarda y se espera al nombre nuevo: por separado, un
				// renombrado se veria como un borrado seguido de una creacion, y
				// se perderia el vinculo entre los dos — que es justo el dato que
				// prueba que un archivo se movio.
				pendienteRenombrado = completa
				goto siguiente
			case fileActionRenamedNewName:
				cambio.Operacion = archivoRenombrado
				cambio.RutaAnterior = pendienteRenombrado
				pendienteRenombrado = ""
			default:
				goto siguiente
			}

			// El tamaño se consulta solo para lo que no se borro; en un borrado
			// el archivo ya no esta y la llamada solo gastaria una operacion de
			// disco por evento.
			if cambio.Operacion != archivoEliminado {
				if st, err := os.Stat(completa); err == nil {
					if st.IsDir() {
						goto siguiente // los directorios no son movimiento de informacion
					}
					cambio.TamanoByte = st.Size()
				}
			}

			// DIAGNOSTICO: se registra cada cambio detectado, para poder ver en el
			// log que el vigilante esta vivo y que rutas ve (util para confirmar,
			// p. ej., que las carpetas de OneDrive se estan vigilando).
			c.log.Debug().
				Str("ruta", cambio.Ruta).Int("operacion", int(cambio.Operacion)).
				Msg("cambio de archivo detectado")

			if ev, recortado := c.maquina.observar(cambio, ahora); ev != nil {
				// REMEDIACION: un documento escrito fuera de las carpetas
				// permitidas se retira a cuarentena. Solo lo que no es un borrado
				// (el archivo tiene que existir para moverlo) y solo si la regla
				// aplica —la decision, conservadora, vive en enforce—.
				permitidas := c.rutasPermitidas()
				debe := cambio.Operacion != archivoEliminado &&
					enforce.DebeCuarentenar(cambio.Ruta, permitidas)
				c.log.Debug().
					Str("ruta", cambio.Ruta).
					Strs("permitidas", permitidas).
					Bool("cuarentenar", debe).
					Msg("decision de cuarentena")
				if debe {
					if dest, err := enforce.Cuarentenar(cambio.Ruta, c.dirCuarentena); err == nil {
						ev.Payload["enforcement"] = "quarantine"
						// quarantine_id es el nombre del archivo dentro de la carpeta
						// de cuarentena. Es lo que la consola necesita para poder
						// mandar despues "restaura esto" o "borralo": identifica el
						// archivo retirado sin revelar su contenido.
						ev.Payload["quarantine_id"] = filepath.Base(dest)
						c.log.Warn().
							Str("ruta", cambio.Ruta).Str("cuarentena", dest).
							Msg("documento fuera de carpeta permitida: retirado a cuarentena")
					} else {
						c.log.Error().Err(err).Str("ruta", cambio.Ruta).
							Msg("no se pudo retirar a cuarentena el documento fuera de carpeta permitida")
					}
				}

				// Clasificacion por contenido (Fase B): solo lo que existe (no un
				// borrado). Se añade la etiqueta al evento; el contenido nunca sale.
				if c.clasificar != nil && cambio.Operacion != archivoEliminado {
					if etiqueta := c.clasificar(cambio.Ruta); etiqueta != "" {
						ev.Payload["classification"] = etiqueta
					}
				}

				emit(*ev)
			} else if recortado {
				c.log.Warn().Str("ruta", raiz).
					Msg("caudal de eventos de archivo recortado; se descartan cambios de este minuto")
			}

		siguiente:
			if info.NextEntryOffset == 0 {
				break
			}
			off += info.NextEntryOffset
			if off >= devueltos {
				break
			}
		}
	}
}

func esExtraible(ruta string) bool {
	vol := filepath.VolumeName(ruta)
	if vol == "" {
		return false
	}
	p, err := windows.UTF16PtrFromString(vol + `\`)
	if err != nil {
		return false
	}
	return windows.GetDriveType(p) == windows.DRIVE_REMOVABLE
}
