//go:build windows

// Package clipwatch observa el portapapeles DENTRO de la sesion del usuario.
//
// Es el proceso auxiliar que lanza el servicio, no parte del servicio. Existe
// porque el portapapeles pertenece a la estacion de ventana y cada sesion de
// Windows tiene la suya: desde la sesion 0, donde corren los servicios, el
// portapapeles del usuario es inalcanzable. No es una limitacion de la API sino
// una barrera del sistema operativo, y no hay forma de rodearla desde el
// servicio.
//
// Este proceso corre CON LOS PERMISOS DEL USUARIO, no como SYSTEM. Es
// deliberado: solo necesita leer metadatos de su propio portapapeles, y darle
// mas privilegios de los que necesita seria regalar una superficie de ataque a
// cambio de nada.
package clipwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Aviso es lo que este proceso envia al servicio por cada copia.
//
// NUNCA LLEVA EL CONTENIDO. Solo describe la copia: de donde salio, de que
// tamaño y de que tipo. Si algun dia alguien añade aqui un campo con el texto
// copiado, el producto pasa de probar movimientos de informacion a almacenarla,
// y deja de ser defendible ante el trabajador vigilado.
type Aviso struct {
	AplicacionOrigen string `json:"source_app"`
	Bytes            int64  `json:"bytes"`
	Formato          string `json:"format"`
	// Enforcement es lo que el agente HIZO de verdad, no lo que la politica
	// pedia. Si el vaciado se intento y fallo, aqui pone "alert": un incidente
	// que diga "bloqueado" sobre contenido que sigue en el portapapeles es peor
	// que uno que admita que solo se alerto.
	Enforcement string    `json:"enforcement"`
	Usuario     string    `json:"user"`
	Momento     time.Time `json:"at"`
}

/* -------------------------------------------------- API de Windows --- */

var (
	user32                            = windows.NewLazySystemDLL("user32.dll")
	procAddClipboardFormatListener    = user32.NewProc("AddClipboardFormatListener")
	procRemoveClipboardFormatListener = user32.NewProc("RemoveClipboardFormatListener")
	procCreateWindowExW               = user32.NewProc("CreateWindowExW")
	procDestroyWindow                 = user32.NewProc("DestroyWindow")
	procDefWindowProcW                = user32.NewProc("DefWindowProcW")
	procRegisterClassExW              = user32.NewProc("RegisterClassExW")
	procGetMessageW                   = user32.NewProc("GetMessageW")
	procTranslateMessage              = user32.NewProc("TranslateMessage")
	procDispatchMessageW              = user32.NewProc("DispatchMessageW")
	procPostQuitMessage               = user32.NewProc("PostQuitMessage")
	procGetClipboardOwner             = user32.NewProc("GetClipboardOwner")
	procGetWindowThreadProcessId      = user32.NewProc("GetWindowThreadProcessId")
	procOpenClipboard                 = user32.NewProc("OpenClipboard")
	procCloseClipboard                = user32.NewProc("CloseClipboard")
	procGetClipboardData              = user32.NewProc("GetClipboardData")
	procEmptyClipboard                = user32.NewProc("EmptyClipboard")
	procIsClipboardFormatAvailable    = user32.NewProc("IsClipboardFormatAvailable")

	kernel32       = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalSize = kernel32.NewProc("GlobalSize")
)

const (
	wmClipboardUpdate = 0x031D
	wmDestroy         = 0x0002
	hwndMessage       = ^uintptr(2) // HWND_MESSAGE == -3

	cfText        = 1
	cfBitmap      = 2
	cfUnicodeText = 13
	cfHDrop       = 15
)

type wndClassExW struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type msg struct {
	Hwnd    windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

/* ------------------------------------------------------------ Vigilancia --- */

// Opciones son las reglas que este proceso aplica.
//
// Viajan como argumentos al lanzarlo, no por un canal en caliente: la politica
// cambia cada muchos minutos y relanzar el auxiliar es instantaneo, mientras que
// mantener un canal bidireccional abierto solo para eso añadiria un protocolo
// —y sus fallos— a cambio de nada.
type Opciones struct {
	// Modo es allow, alert o block.
	Modo string
	// FuentesProtegidas son los procesos cuyo contenido se considera sensible.
	// Vacio significa que el modo aplica a TODO, no que no aplique a nada.
	FuentesProtegidas []string
}

// debeVaciar decide si hay que borrar lo que se acaba de copiar.
func (o Opciones) debeVaciar(app string) bool {
	if o.Modo != "block" {
		return false
	}
	if len(o.FuentesProtegidas) == 0 {
		return true
	}
	app = strings.ToLower(strings.TrimSpace(app))
	for _, f := range o.FuentesProtegidas {
		if strings.ToLower(strings.TrimSpace(f)) == app {
			return true
		}
	}
	return false
}

// Ejecutar observa el portapapeles, aplica el modo y escribe un Aviso por cada
// cambio.
//
// `salida` recibe una linea JSON por copia. Bloquea hasta que el contexto se
// cancele o la ventana se destruya.
func Ejecutar(ctx context.Context, salida io.Writer, op Opciones) error {
	usuario := usuarioActualCorto()
	codificador := json.NewEncoder(salida)

	// El bucle de mensajes DEBE vivir en un solo hilo del sistema operativo: los
	// mensajes de ventana se entregan al hilo que la creo, y sin fijar la
	// goroutine el planificador de Go la movera de hilo y los mensajes dejaran
	// de llegar sin ningun error visible.
	hecho := make(chan error, 1)
	go func() {
		hecho <- bucleMensajes(ctx, op, func(a Aviso) {
			a.Usuario = usuario
			_ = codificador.Encode(a)
		})
	}()

	select {
	case err := <-hecho:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func bucleMensajes(ctx context.Context, op Opciones, alCopiar func(Aviso)) error {
	// runtime.LockOSThread lo hace el llamador de esta funcion en main; aqui se
	// asume ya fijado.
	nombreClase, err := windows.UTF16PtrFromString("NortisClipWatch")
	if err != nil {
		return err
	}

	var hwnd windows.Handle

	// EL MANEJADOR NO TOCA EL PORTAPAPELES. Solo anota quien fue dueño y pasa el
	// aviso a otra goroutine, que mide un instante despues.
	//
	// La primera version medía aqui mismo, dentro de WM_CLIPBOARDUPDATE, y
	// rompia la copia del usuario: al llegar la notificacion la aplicacion que
	// esta copiando TODAVIA no ha terminado, y abrirle el portapapeles en ese
	// momento le devuelve un error. Se comprobo con un Set-Clipboard de
	// PowerShell, que fallo con "Requested Clipboard operation did not succeed".
	//
	// Un agente de seguridad que rompe el copiar y pegar dura exactamente un dia
	// en el equipo de un cliente. Y de paso, medir aqui bloqueaba el bucle de
	// mensajes hasta cien milisegundos por copia.
	pendientes := make(chan pendiente, 32)

	wndProc := windows.NewCallback(func(h windows.Handle, m uint32, w, l uintptr) uintptr {
		switch m {
		case wmClipboardUpdate:
			// GetClipboardOwner NO requiere abrir el portapapeles: se puede
			// llamar aqui sin estorbar a nadie.
			app := aplicacionDuenna()
			if app != "" {
				select {
				case pendientes <- pendiente{App: app, Momento: time.Now().UTC()}:
				default:
					// Canal lleno: una rafaga de copias. Se descarta esta en vez
					// de bloquear el bucle de mensajes, que dejaria de atender
					// al sistema entero.
				}
			}
			return 0
		case wmDestroy:
			procPostQuitMessage.Call(0)
			return 0
		}
		r, _, _ := procDefWindowProcW.Call(uintptr(h), uintptr(m), w, l)
		return r
	})

	go medir(ctx, op, pendientes, alCopiar)

	clase := wndClassExW{
		Size:      uint32(unsafe.Sizeof(wndClassExW{})),
		WndProc:   wndProc,
		ClassName: nombreClase,
	}
	if atom, _, e := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&clase))); atom == 0 {
		return fmt.Errorf("registrando la clase de ventana: %w", e)
	}

	// HWND_MESSAGE: ventana SOLO DE MENSAJES. No se dibuja, no aparece en la
	// barra de tareas y no se puede enfocar. El usuario no ve absolutamente
	// nada; lo contrario seria una ventana fantasma en el escritorio de cada
	// empleado.
	h, _, e := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(nombreClase)),
		0, 0, 0, 0, 0, 0,
		hwndMessage,
		0, 0, 0,
	)
	if h == 0 {
		return fmt.Errorf("creando la ventana de mensajes: %w", e)
	}
	hwnd = windows.Handle(h)
	defer procDestroyWindow.Call(uintptr(hwnd))

	if r, _, e := procAddClipboardFormatListener.Call(uintptr(hwnd)); r == 0 {
		return fmt.Errorf("suscribiendo al portapapeles: %w", e)
	}
	defer procRemoveClipboardFormatListener.Call(uintptr(hwnd))

	// La cancelacion se atiende destruyendo la ventana, que hace que GetMessage
	// devuelva 0 y el bucle termine. Sin esto, GetMessage bloquea para siempre y
	// el proceso auxiliar sobrevive al servicio que lo lanzo.
	go func() {
		<-ctx.Done()
		procDestroyWindow.Call(uintptr(hwnd))
	}()

	var m msg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		switch int32(r) {
		case 0: // WM_QUIT
			return nil
		case -1:
			return fmt.Errorf("fallo en el bucle de mensajes")
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// pendiente es una copia detectada a la espera de que se mida.
type pendiente struct {
	App     string
	Momento time.Time
}

// EsperaAntesDeMedir es cuanto se aguarda antes de tocar el portapapeles.
//
// No es un numero al azar: es el tiempo que se le concede a la aplicacion que
// esta copiando para que TERMINE. Medir de inmediato le arrebata el
// portapapeles a media operacion y le devuelve un error — se comprobo rompiendo
// un Set-Clipboard de PowerShell.
const EsperaAntesDeMedir = 250 * time.Millisecond

// medir toma el tamaño y el formato un instante despues de la copia, y aplica
// el modo de la politica.
func medir(ctx context.Context, op Opciones, pendientes <-chan pendiente, alCopiar func(Aviso)) {
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-pendientes:
			select {
			case <-ctx.Done():
				return
			case <-time.After(EsperaAntesDeMedir):
			}

			vaciar := op.debeVaciar(p.App)
			formato, bytes, vaciado := describirContenido(vaciar)

			aplicado := op.Modo
			if vaciar && !vaciado {
				// Se intento y no se pudo. Se reporta lo que REALMENTE paso: un
				// incidente que diga "bloqueado" sobre contenido que sigue en el
				// portapapeles es peor que uno que diga "alertado".
				aplicado = "alert"
			}

			alCopiar(Aviso{
				AplicacionOrigen: p.App,
				Formato:          formato,
				Bytes:            bytes,
				Enforcement:      aplicado,
				// La marca de tiempo es la de la COPIA, no la de la medicion:
				// el cuarto de segundo de espera no puede desplazar el momento
				// del hecho en la linea de tiempo del analista.
				Momento: p.Momento,
			})
		}
	}
}

// aplicacionDuenna devuelve el proceso que puso el contenido en el portapapeles.
//
// Es de donde sale `source_app`, que es contra lo que compara la regla DLP de
// origen protegido. GetClipboardOwner NO exige abrir el portapapeles, asi que se
// puede llamar desde el manejador de mensajes sin estorbar a la aplicacion que
// esta copiando.
func aplicacionDuenna() string {
	duenno, _, _ := procGetClipboardOwner.Call()
	if duenno == 0 {
		return ""
	}
	var pid uint32
	procGetWindowThreadProcessId.Call(duenno, uintptr(unsafe.Pointer(&pid)))
	if pid == 0 {
		return ""
	}
	return nombreProceso(pid)
}

// describirContenido dice DE QUE TIPO y DE QUE TAMAÑO fue la copia, sin leerla.
//
// GlobalSize devuelve el tamaño del bloque de memoria; en ningun momento se
// accede a lo que hay dentro. Esa distincion es la que separa este producto de
// un registrador de teclas, y el comentario esta aqui porque este es
// exactamente el sitio donde alguien, con la mejor intencion, añadiria un
// GlobalLock para "enriquecer" el evento.
//
// LAS DOS COSAS SE AVERIGUAN EN LA MISMA APERTURA. Consultarlas por separado
// hacia que el formato se leyera antes de que la aplicacion soltara el
// portapapeles y saliera "other" casi siempre, aunque fuera texto: la
// aplicacion que acaba de copiar todavia lo tiene tomado cuando llega la
// notificacion.
//
// El reintento es CORTO y acotado a proposito: insistir mas tiempo bloquearia el
// portapapeles del usuario, y ningun dato de telemetria justifica estorbar a la
// persona que esta trabajando.
// Si `vaciar` es cierto, ADEMAS borra el contenido en la misma apertura.
//
// Hacerlo aqui y no en una segunda pasada es lo que reduce la ventana de
// exposicion: cada apertura extra son milisegundos mas en los que otra
// aplicacion puede pegar lo copiado.
//
// SOBRE LLAMAR A ESTO "BLOQUEAR": no lo es del todo, y conviene no engañarse.
// Windows no ofrece forma soportada de IMPEDIR una copia; lo unico posible es
// borrarla justo despues. Entre el Ctrl+C y el vaciado hay un cuarto de segundo
// en el que un Ctrl+V es mas rapido que nosotros. Corta el caso normal —copiar
// aqui y pegar alla— pero no detiene a quien lo intenta a proposito.
func describirContenido(vaciar bool) (formato string, bytes int64, vaciado bool) {
	const intentos = 5

	for i := 0; i < intentos; i++ {
		if r, _, _ := procOpenClipboard.Call(0); r == 0 {
			time.Sleep(20 * time.Millisecond)
			continue
		}

		formato, handle := formatoAbierto()
		if handle != 0 {
			if h, _, _ := procGetClipboardData.Call(handle); h != 0 {
				if n, _, _ := procGlobalSize.Call(h); n > 0 {
					bytes = int64(n)
				}
			}
		}

		if vaciar {
			// EmptyClipboard exige tener el portapapeles abierto, que es el caso.
			if r, _, _ := procEmptyClipboard.Call(); r != 0 {
				vaciado = true
			}
		}

		procCloseClipboard.Call()
		return formato, bytes, vaciado
	}

	// Sin poder abrirlo el evento sigue siendo util: la regla DLP compara la
	// aplicacion de origen, no el formato ni cuantos bytes salieron.
	return "other", 0, false
}

// formatoAbierto clasifica el contenido. Exige el portapapeles ya abierto.
//
// El orden importa: una copia de archivos desde el Explorador ofrece ADEMAS su
// representacion como texto, asi que comprobar texto primero clasificaria como
// "text" lo que en realidad es una lista de archivos — que es el caso que mas
// interesa a un analista de fuga de informacion.
func formatoAbierto() (string, uintptr) {
	if r, _, _ := procIsClipboardFormatAvailable.Call(cfHDrop); r != 0 {
		return "file_list", cfHDrop
	}
	if r, _, _ := procIsClipboardFormatAvailable.Call(cfBitmap); r != 0 {
		return "image", cfBitmap
	}
	if r, _, _ := procIsClipboardFormatAvailable.Call(cfUnicodeText); r != 0 {
		return "text", cfUnicodeText
	}
	if r, _, _ := procIsClipboardFormatAvailable.Call(cfText); r != 0 {
		return "text", cfText
	}
	return "other", 0
}

func nombreProceso(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return filepath.Base(windows.UTF16ToString(buf[:n]))
}

func usuarioActualCorto() string {
	// Aqui SI vale os/user: este proceso corre como el usuario, no como SYSTEM.
	// Es la diferencia con el servicio, donde habria devuelto la cuenta de
	// servicio y habria atribuido cada copia a SYSTEM.
	nombre := os.Getenv("USERNAME")
	if i := strings.LastIndex(nombre, `\`); i >= 0 {
		nombre = nombre[i+1:]
	}
	return nombre
}
