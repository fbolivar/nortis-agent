//go:build windows

package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"

	"github.com/fbolivar/nortis-agent/internal/clipwatch"
	"github.com/fbolivar/nortis-agent/internal/contract"
)

// ClipboardCollector reporta las copias al portapapeles.
//
// Enciende la regla clipboard.copia_desde_origen_protegido (severidad ALTA), que
// es la que detecta la extraccion desde un ERP o una nomina hacia el navegador.
//
// FUNCIONA DE DOS MANERAS SEGUN DONDE CORRA EL AGENTE:
//
//   - Como SERVICIO (sesion 0): lanza `nortis-agent clipboard-watch` dentro de la
//     sesion del usuario y lee lo que reporta por su salida estandar. Es
//     obligatorio: el portapapeles pertenece a la estacion de ventana y la de la
//     sesion 0 no es la que usa ninguna persona.
//   - En PRIMER PLANO (sesion del usuario, `nortis-agent run`): observa
//     directamente, sin proceso auxiliar, porque ya esta donde tiene que estar.
//
// POR QUE UN PROCESO HIJO CON SALIDA REDIRIGIDA Y NO UNA TUBERIA CON NOMBRE: una
// tuberia con nombre es alcanzable por cualquier proceso del equipo, y habria
// que protegerla con una lista de control de acceso y aun asi decidir si se
// confia en quien escribe. Un hijo con su salida redirigida solo lo puede
// escribir el proceso que el servicio creo: el canal no existe para nadie mas.
type ClipboardCollector struct {
	log      zerolog.Logger
	politica func() *contract.Policy
	maquina  *maquinaPortapapeles
}

func NewClipboardCollector(log zerolog.Logger, politica func() *contract.Policy) *ClipboardCollector {
	return &ClipboardCollector{
		log:      log.With().Str("recolector", "portapapeles").Logger(),
		politica: politica,
		maquina:  nuevaMaquinaPortapapeles(),
	}
}

func (c *ClipboardCollector) Name() string { return "portapapeles" }

// opciones traduce la politica vigente a las reglas del vigilante.
func (c *ClipboardCollector) opciones() clipwatch.Opciones {
	if c.politica == nil {
		return clipwatch.Opciones{Modo: string(contract.ClipboardAllow)}
	}
	p := c.politica()
	if p == nil || p.Clipboard.Mode == "" {
		return clipwatch.Opciones{Modo: string(contract.ClipboardAllow)}
	}
	return clipwatch.Opciones{
		Modo:              string(p.Clipboard.Mode),
		FuentesProtegidas: p.Clipboard.ProtectedSources,
	}
}

// firma resume las opciones para detectar cambios de politica.
//
// Cuando cambia, hay que relanzar el auxiliar: las reglas viajan como argumentos
// al arrancarlo, asi que un proceso ya en marcha seguiria aplicando las
// anteriores indefinidamente.
func firma(op clipwatch.Opciones) string {
	fuentes := append([]string{}, op.FuentesProtegidas...)
	sort.Strings(fuentes)
	return op.Modo + "|" + strings.Join(fuentes, ",")
}

func (c *ClipboardCollector) Run(ctx context.Context, emit Emit) {
	if sesionPropia() != 0 {
		c.log.Info().Msg("observando el portapapeles directamente (agente en la sesion del usuario)")
		c.observarAqui(ctx, emit)
		return
	}

	c.log.Info().Msg("agente en la sesion 0: el portapapeles se observa con un proceso auxiliar en la sesion del usuario")
	c.supervisarAuxiliar(ctx, emit)
}

/* ----------------------------------------- Caso 1: ya estamos en sesion --- */

func (c *ClipboardCollector) observarAqui(ctx context.Context, emit Emit) {
	lector, escritor, err := os.Pipe()
	if err != nil {
		c.log.Error().Err(err).Msg("no se pudo crear el canal interno del portapapeles")
		return
	}

	go func() {
		defer escritor.Close()
		if err := clipwatch.Ejecutar(ctx, escritor, c.opciones()); err != nil && ctx.Err() == nil {
			c.log.Warn().Err(err).Msg("la vigilancia del portapapeles termino")
		}
	}()

	c.consumir(ctx, lector, emit)
	lector.Close()
}

/* ------------------------------- Caso 2: lanzar el auxiliar en la sesion --- */

// IntervaloReintentoAuxiliar es cuanto se espera antes de volver a lanzar el
// auxiliar. Sin espera, un equipo en la pantalla de inicio de sesion —donde no
// hay usuario al que adjuntarse— generaria un bucle de creacion de procesos.
const IntervaloReintentoAuxiliar = 20 * time.Second

func (c *ClipboardCollector) supervisarAuxiliar(ctx context.Context, emit Emit) {
	for {
		if ctx.Err() != nil {
			return
		}

		if err := c.lanzarYLeer(ctx, emit); err != nil && ctx.Err() == nil {
			c.log.Debug().Err(err).Msg("el auxiliar del portapapeles termino; se reintenta")
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(IntervaloReintentoAuxiliar):
		}
	}
}

func (c *ClipboardCollector) lanzarYLeer(ctx context.Context, emit Emit) error {
	token, err := tokenDeSesionActiva()
	if err != nil {
		// Normal en la pantalla de bloqueo o sin nadie con sesion iniciada: no
		// hay usuario al que adjuntarse todavia.
		return err
	}
	defer token.Close()

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	op := c.opciones()
	args := []string{"clipboard-watch", "-mode", op.Modo}
	if len(op.FuentesProtegidas) > 0 {
		args = append(args, "-protected", strings.Join(op.FuentesProtegidas, ","))
	}

	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token: syscall.Token(token),
		// Sin ventana: el usuario no debe ver una consola aparecer y
		// desaparecer en su escritorio.
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}

	salida, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	// Si la politica cambia, el auxiliar en marcha seguiria aplicando las reglas
	// con las que arranco. Se le termina para que el supervisor lo relance con
	// las nuevas: es instantaneo y evita mantener un canal bidireccional solo
	// para esto.
	hijo, detener := context.WithCancel(ctx)
	defer detener()
	go func() {
		inicial := firma(op)
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-hijo.Done():
				return
			case <-t.C:
				if firma(c.opciones()) != inicial {
					c.log.Info().Msg("la politica de portapapeles cambio; se relanza el vigilante")
					_ = cmd.Process.Kill()
					return
				}
			}
		}
	}()

	c.consumir(ctx, salida, emit)
	return cmd.Wait()
}

/* ------------------------------------------------------------- Consumo --- */

// consumir lee avisos en JSON, uno por linea, y los convierte en telemetria.
func (c *ClipboardCollector) consumir(ctx context.Context, r interface{ Read([]byte) (int, error) }, emit Emit) {
	sc := bufio.NewScanner(r)
	// Un aviso son unos cientos de bytes; el tope evita que una linea corrupta
	// enorme haga crecer el bufer sin limite.
	sc.Buffer(make([]byte, 0, 8*1024), 64*1024)

	for sc.Scan() {
		if ctx.Err() != nil {
			return
		}

		var a clipwatch.Aviso
		if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
			continue
		}

		// El enforcement lo dice el AUXILIAR, no la politica: es el unico que
		// sabe si el vaciado se pudo hacer. Tomarlo de la politica reportaria
		// "bloqueado" sobre contenido que sigue en el portapapeles.
		aplicado := a.Enforcement
		if aplicado == "" {
			aplicado = c.opciones().Modo
		}

		ev := c.maquina.observar(copiaPortapapeles{
			AplicacionOrigen: a.AplicacionOrigen,
			Bytes:            a.Bytes,
			// El formato se normaliza aqui y no se acepta tal cual: un auxiliar
			// de otra version podria mandar una cadena que la consola rechaza, y
			// el evento se perderia en silencio.
			Formato: FormatoValido(a.Formato),
			Usuario: a.Usuario,
			Momento: a.Momento,
		}, aplicado)

		if ev != nil {
			c.log.Info().
				Str("origen", a.AplicacionOrigen).
				Int64("bytes", a.Bytes).
				Msg("copia al portapapeles")
			emit(*ev)
		}
	}
}

/* --------------------------------------------------- Sesion y credencial --- */

// `wtsapi32` y `procProcessIdToSessionId` ya los declaran wts_windows.go y
// apps_windows.go: son el mismo paquete y volver a declararlos no compila.
var (
	procWTSQueryUserToken   = wtsapi32.NewProc("WTSQueryUserToken")
	procWTSGetActiveConsole = windows.NewLazySystemDLL("kernel32.dll").
				NewProc("WTSGetActiveConsoleSessionId")
)

// sesionPropia devuelve la sesion de Windows de este proceso. 0 es la de los
// servicios.
func sesionPropia() uint32 {
	var sesion uint32
	r, _, _ := procProcessIdToSessionId.Call(
		uintptr(windows.GetCurrentProcessId()),
		uintptr(unsafe.Pointer(&sesion)),
	)
	if r == 0 {
		return 0
	}
	return sesion
}

// tokenDeSesionActiva obtiene la credencial del usuario que esta delante.
//
// Exige el privilegio SE_TCB_NAME, que tiene SYSTEM y no tiene un usuario
// normal: si el agente corre en primer plano esto falla, y por eso ese caso se
// resuelve antes observando directamente en vez de lanzar un auxiliar.
func tokenDeSesionActiva() (windows.Token, error) {
	r, _, _ := procWTSGetActiveConsole.Call()
	sesion := uint32(r)

	// 0xFFFFFFFF significa que no hay sesion de consola: el equipo esta
	// arrancando o nadie ha iniciado sesion.
	if sesion == 0xFFFFFFFF {
		return 0, os.ErrNotExist
	}

	var token windows.Token
	ok, _, err := procWTSQueryUserToken.Call(
		uintptr(sesion),
		uintptr(unsafe.Pointer(&token)),
	)
	if ok == 0 {
		return 0, err
	}
	return token, nil
}
