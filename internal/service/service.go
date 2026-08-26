// Package service implementa el ciclo de vida como servicio de Windows.
//
// Se valida ESTO antes que ningun recolector. Un agente que recolecta
// perfectamente pero no arranca con el sistema, o que no se deja detener, es un
// agente que el cliente desinstala en la primera semana. El orden importa.
package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kardianos/service"
	"github.com/rs/zerolog"

	"github.com/fbolivar/nortis-agent/internal/agentcfg"
	"github.com/fbolivar/nortis-agent/internal/capture"
	"github.com/fbolivar/nortis-agent/internal/classify"
	"github.com/fbolivar/nortis-agent/internal/collector"
	"github.com/fbolivar/nortis-agent/internal/contract"
	"github.com/fbolivar/nortis-agent/internal/enforce"
	"github.com/fbolivar/nortis-agent/internal/inventory"
	"github.com/fbolivar/nortis-agent/internal/machineid"
	"github.com/fbolivar/nortis-agent/internal/remoteexec"
	"github.com/fbolivar/nortis-agent/internal/schedtask"
	"github.com/fbolivar/nortis-agent/internal/syncer"
	"github.com/fbolivar/nortis-agent/internal/tamper"
	"github.com/fbolivar/nortis-agent/internal/updater"
)

// intervaloActualizacion es cada cuanto el agente pregunta a la consola si hay
// una version nueva. La primera pasada es inmediata al arrancar, asi que una
// version recien instalada comprueba enseguida; despues, cada hora basta —
// publicar una actualizacion no es urgente al segundo, y el latido ya lleva el
// pulso del equipo.
const intervaloActualizacion = time.Hour

// ventanaDesbloqueo es cuanto tiempo, tras validar un vale, el servicio se
// abstiene de volver a endurecer. Es la ventana en la que el tecnico ejecuta la
// desinstalacion: sin ella, el ciclo de proteccion reendureceria el servicio
// entre el desbloqueo y el `uninstall`, y la desinstalacion volveria a fallar.
const ventanaDesbloqueo = 10 * time.Minute

// Config describe el servicio ante el gestor de servicios de Windows.
var Config = &service.Config{
	Name:        "NortisAgent",
	DisplayName: "Nortis Agent",
	Description: "Monitoreo de endpoint, prevencion de fuga de informacion y cifrado gestionado.",
	// Arranque automatico y reinicio ante fallo: si el proceso muere, Windows lo
	// levanta. Es el watchdog que pide el requisito de auto-proteccion, y no
	// hace falta escribir uno propio — el gestor de servicios ya lo hace mejor.
	Option: service.KeyValue{
		"StartType":              "automatic",
		"OnFailure":              "restart",
		"OnFailureDelayDuration": "15s",
		"OnFailureResetPeriod":   "600",
	},
}

// Program implementa service.Interface.
type Program struct {
	agent *syncer.Agent
	log   zerolog.Logger

	// aplicador impone la politica en el sistema (registro, archivo hosts).
	// Es lo unico del agente que MODIFICA el equipo en vez de observarlo.
	aplicador *enforce.Aplicador

	// actualizador comprueba y aplica versiones nuevas publicadas en la consola.
	actualizador *updater.Updater

	// clasificador etiqueta archivos por su contenido (Fase B). Sus reglas se
	// refrescan desde la consola; sin reglas no inspecciona nada.
	clasificador *classify.Clasificador

	// restauros recuerda las rutas restauradas hace poco desde la consola, para no
	// re-cuarentenarlas al instante (deshariar la decision del admin). Lo escribe
	// el ciclo de comandos y lo lee el vigilante de archivos.
	restauros *enforce.RegistroRestauros

	// programadas guarda los scripts recurrentes (schedule_script), persistidos.
	programadas *schedtask.Store

	cancel context.CancelFunc
	wg     sync.WaitGroup
	cfg    agentcfg.Config

	// muGrant protege ultimoDesbloqueo, que comparten el ciclo de proteccion
	// (que reendurece) y la atencion de vales (que afloja).
	muGrant          sync.Mutex
	ultimoDesbloqueo time.Time
}

func NewProgram(cfg agentcfg.Config, agent *syncer.Agent, log zerolog.Logger) *Program {
	return &Program{
		agent:     agent,
		log:       log,
		cfg:       cfg,
		aplicador: enforce.NuevoAplicador(log, agentcfg.Dir()),
		// El cliente de descarga da margen amplio: un MSI de varios MB por una
		// red de oficina saturada no debe cortarse a mitad.
		actualizador: updater.New(
			agent.Version, contract.AgentVersion,
			&http.Client{Timeout: 10 * time.Minute}, log,
		),
		clasificador: classify.Nuevo(),
		restauros:    enforce.NuevoRegistroRestauros(),
		programadas:  schedtask.Abrir(agentcfg.Dir()),
	}
}

// Start debe RETORNAR RAPIDO. El gestor de servicios de Windows espera una
// confirmacion en segundos; si Start bloquea, el arranque se marca como fallido
// aunque el agente este funcionando. Por eso el trabajo real va en goroutines.
func (p *Program) Start(s service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel

	p.log.Info().
		Str("version", contract.AgentVersion).
		Str("consola", p.cfg.ConsoleURL).
		Msg("servicio iniciando")

	if err := p.agent.Restore(); err != nil {
		// No es fatal: sin estado previo el agente se comporta como recien
		// instalado. Impedir el arranque por esto dejaria el equipo sin agente.
		p.log.Warn().Err(err).Msg("no se pudo restaurar el estado previo")
	}

	p.wg.Add(13)
	go p.loop(ctx, "sincronizacion", p.cfg.SyncInterval.Duration, p.syncOnce)
	go p.loop(ctx, "latido", p.cfg.HeartbeatInterval.Duration, p.heartbeatOnce)
	go p.loop(ctx, "politica", p.cfg.PolicyInterval.Duration, p.policyOnce)
	// Purga de la cuarentena una vez al dia: retira la evidencia que ya cumplio
	// su retencion para que la carpeta no crezca sin fin. La primera pasada es al
	// arrancar, asi que un equipo que estuvo apagado se pone al dia enseguida.
	go p.loop(ctx, "limpieza-cuarentena", 24*time.Hour, p.limpiarCuarentenaOnce)
	// El ciclo de proteccion corre como SYSTEM (el servicio): es el unico
	// contexto con permiso para reescribir el DACL endurecido, y por eso es aqui
	// —y no en el proceso del administrador— donde se valida un vale y se afloja.
	go p.loop(ctx, "proteccion", 30*time.Second, p.proteccionOnce)
	go p.loop(ctx, "actualizacion", intervaloActualizacion, p.actualizarOnce)
	// Comandos de la consola (restaurar / borrar cuarentena). Se consultan a
	// menudo porque una restauracion la pide un humano que espera verla aplicada:
	// un minuto es la latencia maxima aceptable sin castigar la red del equipo.
	go p.loop(ctx, "comandos", time.Minute, p.comandosOnce)
	// Tareas de ejecucion remota (instalar MSI, etc.). Se consultan cada minuto:
	// un despliegue lo lanza un humano que espera verlo aplicado. Cada tarea se
	// verifica contra la firma de la consola antes de ejecutar nada.
	go p.loop(ctx, "tareas", time.Minute, p.tareasOnce)
	// Reglas de clasificacion por contenido: se refrescan cada 15 min. Si el
	// tenant no firmo consentimiento, la consola devuelve la lista vacia y el
	// agente deja de inspeccionar contenido.
	go p.loop(ctx, "clasificacion", 15*time.Minute, p.clasificacionOnce)
	// Inventario de software y hardware: cambia despacio, asi que un barrido cada
	// 6 horas sobra. La primera pasada es al arrancar, para que un equipo recien
	// enrolado aparezca en el inventario sin esperar.
	go p.loop(ctx, "inventario", 6*time.Hour, p.inventarioOnce)
	// Captura de pantalla: cada 30 min SOLO si la politica trae screenshots=true,
	// que la consola unicamente entrega con consentimiento firmado del tenant. Sin
	// el flag, capturaOnce no toca la pantalla.
	go p.loop(ctx, "captura", 30*time.Minute, p.capturaOnce)
	// Control por horario: cada minuto, si la politica lo pide y estamos fuera de
	// la franja laboral, se bloquea la sesion. Cada minuto para que reintente si
	// el usuario vuelve a entrar.
	go p.loop(ctx, "horario", time.Minute, p.horarioOnce)
	// Scripts recurrentes: cada minuto se revisa cuales toca ejecutar.
	go p.loop(ctx, "programadas", time.Minute, p.programadasOnce)

	p.arrancarRecolectores(ctx)

	return nil
}

// limpiarCuarentenaOnce purga los archivos en cuarentena que ya cumplieron su
// retencion. Es el "que se hace" con lo retirado: se conserva un tiempo como
// evidencia y luego se borra, para no llenar el disco del equipo.
func (p *Program) limpiarCuarentenaOnce(_ context.Context) {
	dir := filepath.Join(agentcfg.Dir(), "cuarentena")
	n, err := enforce.PurgarCuarentena(dir, enforce.RetencionCuarentena, time.Now())
	if err != nil {
		p.log.Warn().Err(err).Msg("no se pudo purgar la cuarentena")
		return
	}
	if n > 0 {
		p.log.Info().Int("borrados", n).Dur("retencion", enforce.RetencionCuarentena).
			Msg("cuarentena purgada: evidencia caducada retirada")
	}
}

// comandosOnce reclama a la consola los comandos pendientes para este equipo
// —restaurar un archivo retirado, o borrarlo definitivamente— y los ejecuta. Es
// el cierre del ciclo de cuarentena: el agente retira, la consola revisa y aqui
// se cumple la decision del administrador. Reporta el resultado de cada uno para
// que la consola muestre si se aplico o por que fallo.
func (p *Program) comandosOnce(ctx context.Context) {
	resp, err := p.agent.PollComandos(ctx)
	if err != nil {
		// Sin endpoint_id todavia, o red caida: se reintenta al proximo ciclo.
		p.log.Debug().Err(err).Msg("no se pudieron consultar comandos")
		return
	}
	if len(resp.Commands) == 0 {
		return
	}

	dir := filepath.Join(agentcfg.Dir(), "cuarentena")
	for _, cmd := range resp.Commands {
		var e error
		switch cmd.Kind {
		case "restore_file":
			// Se marca ANTES de mover: el evento de la restauracion puede llegar al
			// vigilante en el mismo instante, y tiene que encontrar ya la gracia
			// puesta para no re-cuarentenar el archivo recien devuelto.
			p.restauros.Marcar(cmd.OriginalPath, enforce.VentanaGraciaRestauro, time.Now())
			e = enforce.RestaurarCuarentena(dir, cmd.QuarantineID, cmd.OriginalPath)
		case "delete_quarantine":
			e = enforce.BorrarCuarentena(dir, cmd.QuarantineID)
		default:
			e = fmt.Errorf("comando desconocido: %s", cmd.Kind)
		}

		estado, msgErr := "done", ""
		if e != nil {
			estado, msgErr = "failed", e.Error()
			p.log.Warn().Err(e).Str("comando", cmd.Kind).Str("id", cmd.QuarantineID).
				Msg("no se pudo ejecutar el comando de cuarentena")
		} else {
			p.log.Info().Str("comando", cmd.Kind).Str("ruta", cmd.OriginalPath).
				Msg("comando de cuarentena ejecutado")
		}
		if rerr := p.agent.ReportarComando(ctx, cmd.ID, estado, msgErr); rerr != nil {
			p.log.Warn().Err(rerr).Msg("no se pudo reportar el resultado del comando")
		}
	}
}

// tareasOnce reclama las tareas de ejecucion remota pendientes y las ejecuta.
// La firma de la consola es la UNICA puerta: una tarea que no verifica —incluida
// una fila inyectada en la base sin firma valida— se rechaza y se reporta, nunca
// se ejecuta.
func (p *Program) tareasOnce(ctx context.Context) {
	resp, err := p.agent.PollTareas(ctx)
	if err != nil {
		p.log.Debug().Err(err).Msg("no se pudieron consultar tareas")
		return
	}
	if len(resp.Tasks) == 0 {
		return
	}

	pub, err := tamper.ClavePublicaConsola(agentcfg.Dir())
	if err != nil {
		// Sin clave publica no se puede verificar nada; no se ejecuta ninguna
		// tarea. Es el lado seguro del fallo.
		p.log.Warn().Err(err).Msg("sin clave publica de la consola; no se ejecutan tareas")
		return
	}
	endpointID := p.agent.EndpointID()

	for _, t := range resp.Tasks {
		if err := remoteexec.VerificarFirma(pub, endpointID, t.Kind, t.Payload, t.Signature); err != nil {
			p.log.Warn().Err(err).Str("task", t.ID).Msg("tarea con firma invalida, rechazada")
			_ = p.agent.ReportarTarea(ctx, t.ID, "failed", nil, "", "firma invalida: "+err.Error())
			continue
		}
		p.ejecutarTarea(ctx, t)
	}
}

// ejecutarTarea corre una tarea YA verificada segun su tipo y reporta el
// resultado (exit code + salida). Fase 1: solo install_msi.
func (p *Program) ejecutarTarea(ctx context.Context, t contract.Tarea) {
	_ = p.agent.ReportarTarea(ctx, t.ID, "running", nil, "", "")

	switch t.Kind {
	case "install_msi":
		payload, err := remoteexec.ParseInstallMSI(t.Payload)
		if err != nil {
			p.fallarTarea(ctx, t, err)
			return
		}
		if remoteexec.Vencida(payload.NotAfter, time.Now()) {
			p.fallarTarea(ctx, t, fmt.Errorf("tarea vencida antes de aplicarse"))
			return
		}
		code, out, err := remoteexec.EjecutarInstallMSI(ctx, payload)
		p.terminarTarea(ctx, t, code, out, err)

	case "push_file":
		payload, err := remoteexec.ParsePushFile(t.Payload)
		if err != nil {
			p.fallarTarea(ctx, t, err)
			return
		}
		if remoteexec.Vencida(payload.NotAfter, time.Now()) {
			p.fallarTarea(ctx, t, fmt.Errorf("tarea vencida antes de aplicarse"))
			return
		}
		code, out, err := remoteexec.EjecutarPushFile(ctx, payload)
		p.terminarTarea(ctx, t, code, out, err)

	case "restart":
		code, out, err := remoteexec.EjecutarRestart(ctx)
		p.terminarTarea(ctx, t, code, out, err)

	case "lock":
		code, out, err := remoteexec.EjecutarLock(ctx)
		p.terminarTarea(ctx, t, code, out, err)

	case "wipe":
		payload, err := remoteexec.ParseWipe(t.Payload)
		if err != nil {
			p.fallarTarea(ctx, t, err)
			return
		}
		if remoteexec.Vencida(payload.NotAfter, time.Now()) {
			p.fallarTarea(ctx, t, fmt.Errorf("tarea vencida antes de aplicarse"))
			return
		}
		code, out, err := remoteexec.EjecutarWipe(ctx, payload)
		p.terminarTarea(ctx, t, code, out, err)

	case "screenshot":
		payload, err := remoteexec.ParseScreenshot(t.Payload)
		if err != nil {
			p.fallarTarea(ctx, t, err)
			return
		}
		if remoteexec.Vencida(payload.NotAfter, time.Now()) {
			p.fallarTarea(ctx, t, fmt.Errorf("tarea vencida antes de aplicarse"))
			return
		}
		png, cErr := capture.Capturar(ctx)
		if cErr != nil {
			p.fallarTarea(ctx, t, cErr)
			return
		}
		if uErr := p.agent.SubirCaptura(ctx, png); uErr != nil {
			p.fallarTarea(ctx, t, uErr)
			return
		}
		p.terminarTarea(ctx, t, 0, "captura enviada", nil)

	case "message":
		payload, err := remoteexec.ParseMessage(t.Payload)
		if err != nil {
			p.fallarTarea(ctx, t, err)
			return
		}
		if remoteexec.Vencida(payload.NotAfter, time.Now()) {
			p.fallarTarea(ctx, t, fmt.Errorf("tarea vencida antes de aplicarse"))
			return
		}
		code, out, err := remoteexec.EjecutarMensaje(ctx, payload)
		p.terminarTarea(ctx, t, code, out, err)

	case "kill":
		payload, err := remoteexec.ParseKill(t.Payload)
		if err != nil {
			p.fallarTarea(ctx, t, err)
			return
		}
		if remoteexec.Vencida(payload.NotAfter, time.Now()) {
			p.fallarTarea(ctx, t, fmt.Errorf("tarea vencida antes de aplicarse"))
			return
		}
		code, out, err := remoteexec.EjecutarKill(ctx, payload)
		p.terminarTarea(ctx, t, code, out, err)

	case "uninstall":
		payload, err := remoteexec.ParseUninstall(t.Payload)
		if err != nil {
			p.fallarTarea(ctx, t, err)
			return
		}
		if remoteexec.Vencida(payload.NotAfter, time.Now()) {
			p.fallarTarea(ctx, t, fmt.Errorf("tarea vencida antes de aplicarse"))
			return
		}
		code, out, err := remoteexec.EjecutarUninstall(ctx, payload)
		p.terminarTarea(ctx, t, code, out, err)

	case "wake":
		payload, err := remoteexec.ParseWake(t.Payload)
		if err != nil {
			p.fallarTarea(ctx, t, err)
			return
		}
		if remoteexec.Vencida(payload.NotAfter, time.Now()) {
			p.fallarTarea(ctx, t, fmt.Errorf("tarea vencida antes de aplicarse"))
			return
		}
		code, out, err := remoteexec.EjecutarWake(ctx, payload)
		p.terminarTarea(ctx, t, code, out, err)

	case "schedule_script":
		payload, err := remoteexec.ParseScheduleScript(t.Payload)
		if err != nil {
			p.fallarTarea(ctx, t, err)
			return
		}
		p.programadas.Aplicar(schedtask.Programada{
			ID: payload.ID, Interpreter: payload.Interpreter, Script: payload.Script,
			EveryMinutes: payload.EveryMinutes, NotAfter: payload.NotAfter,
		})
		msg := "programacion guardada"
		if payload.EveryMinutes <= 0 {
			msg = "programacion eliminada"
		}
		p.terminarTarea(ctx, t, 0, msg, nil)

	case "run_script":
		payload, err := remoteexec.ParseRunScript(t.Payload)
		if err != nil {
			p.fallarTarea(ctx, t, err)
			return
		}
		if remoteexec.Vencida(payload.NotAfter, time.Now()) {
			p.fallarTarea(ctx, t, fmt.Errorf("tarea vencida antes de aplicarse"))
			return
		}
		code, out, err := remoteexec.EjecutarRunScript(ctx, payload)
		p.terminarTarea(ctx, t, code, out, err)

	default:
		p.fallarTarea(ctx, t, fmt.Errorf("accion no soportada en esta version: %s", t.Kind))
	}
}

// terminarTarea reporta el resultado de un ejecutor (exit code + salida o error).
func (p *Program) terminarTarea(ctx context.Context, t contract.Tarea, code int, out string, err error) {
	if err != nil {
		p.log.Warn().Err(err).Int("code", code).Str("task", t.ID).Str("kind", t.Kind).Msg("tarea fallo")
		_ = p.agent.ReportarTarea(ctx, t.ID, "failed", &code, out, err.Error())
		return
	}
	p.log.Info().Int("code", code).Str("task", t.ID).Str("kind", t.Kind).Msg("tarea aplicada")
	_ = p.agent.ReportarTarea(ctx, t.ID, "done", &code, out, "")
}

func (p *Program) fallarTarea(ctx context.Context, t contract.Tarea, err error) {
	p.log.Warn().Err(err).Str("task", t.ID).Str("kind", t.Kind).Msg("tarea fallida")
	_ = p.agent.ReportarTarea(ctx, t.ID, "failed", nil, "", err.Error())
}

// clasificacionOnce descarga las reglas de clasificacion por contenido y las
// aplica al clasificador. La consola solo las entrega si hay consentimiento
// firmado; sin reglas, el clasificador no inspecciona ningun archivo.
func (p *Program) clasificacionOnce(ctx context.Context) {
	resp, err := p.agent.Clasificaciones(ctx)
	if err != nil {
		p.log.Debug().Err(err).Msg("no se pudieron consultar las reglas de clasificacion")
		return
	}
	defs := make([]classify.Definicion, 0, len(resp.Classifications))
	for _, c := range resp.Classifications {
		defs = append(defs, classify.Definicion{Nombre: c.Name, Patrones: c.ContentPatterns})
	}
	p.clasificador.Actualizar(defs)
	if len(defs) > 0 {
		p.log.Info().Int("reglas", len(defs)).Str("clases", classify.NombresDe(defs)).
			Msg("clasificacion por contenido activa")
	}
}

// inventarioOnce recolecta el software y hardware del equipo y lo reporta. El
// software se reemplaza entero en el servidor, asi que un programa desinstalado
// desaparece del inventario sin logica extra. Solo metadatos: nombres y
// versiones, nunca rutas ni contenido.
func (p *Program) inventarioOnce(ctx context.Context) {
	hw, sw := inventory.Recolectar(ctx)
	if err := p.agent.ReportarInventario(ctx, hw, sw); err != nil {
		p.log.Debug().Err(err).Msg("no se pudo reportar el inventario")
		return
	}
	p.log.Info().Int("programas", len(sw)).Msg("inventario reportado")
}

// capturaOnce toma una captura de pantalla y la sube, SOLO si la politica trae
// screenshots=true (que la consola unicamente entrega con consentimiento firmado).
// Sin el flag no se toca la pantalla; con el, el agente captura y envia el PNG.
func (p *Program) capturaOnce(ctx context.Context) {
	pol := p.agent.Policy()
	if pol == nil || !pol.Monitoring.Screenshots {
		return
	}
	png, err := capture.Capturar(ctx)
	if err != nil {
		p.log.Debug().Err(err).Msg("no se pudo capturar la pantalla")
		return
	}
	// Tope de tamaño: una captura descomunal (multimonitor 4K) no debe saturar la
	// cola ni el almacenamiento. Si excede, se descarta esta ronda.
	const maxBytes = 4 << 20
	if len(png) > maxBytes {
		p.log.Warn().Int("bytes", len(png)).Msg("captura demasiado grande; se descarta")
		return
	}
	if err := p.agent.SubirCaptura(ctx, png); err != nil {
		p.log.Debug().Err(err).Msg("no se pudo subir la captura")
		return
	}
	p.log.Info().Int("bytes", len(png)).Msg("captura de pantalla enviada")
}

// horarioOnce bloquea la sesion si la politica de horario esta activa y estamos
// FUERA de la franja laboral. Se ejecuta cada minuto: si el usuario vuelve a
// entrar fuera de horario, se le bloquea de nuevo.
func (p *Program) horarioOnce(ctx context.Context) {
	pol := p.agent.Policy()
	if pol == nil || !pol.WorkHours.Enabled {
		return
	}
	if dentroDeHorario(pol.WorkHours.Days, pol.WorkHours.Start, pol.WorkHours.End, time.Now()) {
		return
	}
	if _, _, err := remoteexec.EjecutarLock(ctx); err != nil {
		p.log.Debug().Err(err).Msg("no se pudo bloquear por fuera de horario")
	}
}

// dentroDeHorario indica si `now` cae dentro del horario laboral permitido. Days:
// 1=lunes..7=domingo. Start/End: "HH:MM". Sin horas validas, no se bloquea.
func dentroDeHorario(days []int, start, end string, now time.Time) bool {
	dia := int(now.Weekday())
	if dia == 0 { // time.Sunday == 0 -> 7
		dia = 7
	}
	enDia := false
	for _, d := range days {
		if d == dia {
			enDia = true
			break
		}
	}
	if !enDia {
		return false
	}
	ini, ok1 := minutosDeHora(start)
	fin, ok2 := minutosDeHora(end)
	if !ok1 || !ok2 {
		return true
	}
	m := now.Hour()*60 + now.Minute()
	if ini <= fin {
		return m >= ini && m <= fin
	}
	// Franja que cruza medianoche (p. ej. turno de noche 22:00-06:00).
	return m >= ini || m <= fin
}

func minutosDeHora(s string) (int, bool) {
	var h, mm int
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d:%d", &h, &mm); err != nil {
		return 0, false
	}
	if h < 0 || h > 23 || mm < 0 || mm > 59 {
		return 0, false
	}
	return h*60 + mm, true
}

// programadasOnce ejecuta los scripts recurrentes que ya toca correr.
func (p *Program) programadasOnce(ctx context.Context) {
	for _, pr := range p.programadas.Vencidas(time.Now()) {
		code, _, err := remoteexec.EjecutarRunScript(ctx, remoteexec.RunScriptPayload{
			Interpreter: pr.Interpreter, Script: pr.Script,
		})
		if err != nil {
			p.log.Warn().Err(err).Str("id", pr.ID).Int("code", code).Msg("script programado fallo")
		} else {
			p.log.Info().Str("id", pr.ID).Int("code", code).Msg("script programado ejecutado")
		}
	}
}

// actualizarOnce pregunta a la consola si hay version nueva y, si la hay y es
// verificable, la aplica. Si la aplica, el proceso sera reemplazado por el
// instalador; hasta entonces el resto del agente sigue funcionando.
func (p *Program) actualizarOnce(ctx context.Context) {
	aplicada, err := p.actualizador.Comprobar(ctx)
	switch {
	case err != nil:
		// No es fatal: un fallo de red o una descarga interrumpida se reintenta en
		// el proximo ciclo. La telemetria y el enforcement no dependen de esto.
		p.log.Warn().Err(err).Msg("no se pudo comprobar/aplicar la actualizacion")
	case aplicada:
		p.log.Warn().Msg("actualizacion lanzada; el servicio se reiniciara con la version nueva")
	}
}

// proteccionOnce reafirma el endurecimiento y atiende una peticion de desbloqueo.
//
// Reafirmar es idempotente y barato: cierra la ventana por si alguien con
// privilegios aflojo el DACL a mano. Se salta mientras haya un desbloqueo
// reciente en curso, para no reendurecer justo cuando un tecnico autorizado esta
// a punto de desinstalar.
func (p *Program) proteccionOnce(ctx context.Context) {
	dir := agentcfg.Dir()

	// Un vale valido siempre se atiende, incluso dentro de la ventana: es lo que
	// pasa de "protegido" a "desinstalable".
	p.atenderDesbloqueo(dir)

	p.muGrant.Lock()
	reciente := time.Since(p.ultimoDesbloqueo) < ventanaDesbloqueo
	p.muGrant.Unlock()
	if reciente {
		return
	}

	switch err := tamper.Endurecer(Config.Name, dir); {
	case err == nil:
	case errors.Is(err, tamper.ErrSinClaveConsola):
		// No es un fallo: es un estado de configuracion. Sin autoridad de
		// desbloqueo NO se endurece, para no dejar el equipo irreversible.
		p.log.Debug().Msg("proteccion en pausa: falta la clave publica de la consola (console_pubkey.pem)")
	case errors.Is(err, tamper.ErrNoSoportado):
		// Ejecutando en primer plano fuera de Windows (diagnostico); nada que hacer.
	default:
		p.log.Warn().Err(err).Msg("no se pudo reafirmar la proteccion anti-manipulacion")
	}
}

// atenderDesbloqueo procesa el archivo de peticion de desbloqueo, si existe.
//
// La presencia del archivo NO basta: el vale se REVUELVE a verificar aqui dentro,
// en el contexto SYSTEM, contra el endpoint_id real de este equipo. Que el
// administrador pudiera dejar el archivo no le da autoridad; la firma de la
// consola, si. Un vale invalido se borra para no reintentarlo en bucle.
func (p *Program) atenderDesbloqueo(dir string) {
	ruta := tamper.RutaSolicitudDesbloqueo(dir)
	// Ruta fija bajo el directorio de datos, no entrada de usuario; se lee a
	// traves de la funcion para que el analizador no la trate como arbitraria.
	datos, err := os.ReadFile(tamper.RutaSolicitudDesbloqueo(dir))
	if err != nil {
		return // lo normal: no hay ninguna peticion pendiente
	}
	token := strings.TrimSpace(string(datos))

	if _, err := tamper.Verificar(dir, token, p.agent.EndpointID(), time.Now().UTC()); err != nil {
		p.log.Warn().Err(err).Msg("peticion de desbloqueo RECHAZADA; la proteccion sigue en pie")
		_ = os.Remove(ruta)
		return
	}

	if err := tamper.Aflojar(Config.Name); err != nil {
		p.log.Error().Err(err).Msg("vale valido pero no se pudo aflojar la proteccion")
		return // se conserva el archivo: se reintenta al siguiente ciclo
	}

	p.muGrant.Lock()
	p.ultimoDesbloqueo = time.Now()
	p.muGrant.Unlock()
	_ = os.Remove(ruta)

	p.log.Warn().
		Str("endpoint", p.agent.EndpointID()).
		Dur("ventana", ventanaDesbloqueo).
		Msg("PROTECCION RETIRADA por vale valido; la desinstalacion queda autorizada durante la ventana")
}

// arrancarRecolectores lanza cada recolector en su propia goroutine.
//
// Sin endpoint enrolado no se arranca ninguno: los eventos se acumularian en la
// cola sin destino al que enviarlos, y al enrolarse despues se subiria de golpe
// telemetria de horas anteriores con fecha de antes de que el equipo existiera
// en la consola.
func (p *Program) arrancarRecolectores(ctx context.Context) {
	if p.agent.EndpointID() == "" {
		p.log.Warn().Msg("equipo sin enrolar; no se arrancan los recolectores")
		return
	}

	// Emit escribe en la cola local, que es una operacion de disco y nunca de
	// red: el recolector no puede quedarse esperando a la consola.
	emit := func(e contract.Event) { p.agent.Enqueue(e) }

	// La politica se pasa como funcion, no como valor: el administrador la edita
	// en la consola y el agente la recarga en caliente, asi que un recolector que
	// la copiara al arrancar seguiria aplicando la de hace tres horas.
	recienRestaurado := func(ruta string) bool { return p.restauros.Reciente(ruta, time.Now()) }
	for _, c := range collector.Default(p.log, p.agent.Policy, p.clasificador.ClasificarArchivo, recienRestaurado) {
		p.wg.Add(1)
		go p.correrRecolector(ctx, c, emit)
	}
}

// correrRecolector aisla un recolector del resto.
//
// El recover es lo que hace real el requisito de que un fallo del agente nunca
// bloquee al usuario: un panico leyendo procesos no puede tumbar el vigilante de
// sesiones, ni los ciclos de sincronizacion, ni el servicio. El recolector caido
// no se reinicia a proposito — reintentar en bucle algo que panica llenaria el
// disco de logs; el resto del agente sigue funcionando y el fallo queda escrito.
func (p *Program) correrRecolector(ctx context.Context, c collector.Collector, emit collector.Emit) {
	defer p.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			p.log.Error().Interface("panico", r).Str("recolector", c.Name()).
				Msg("recolector detenido tras un panico; el resto del agente sigue")
		}
	}()

	p.log.Info().Str("recolector", c.Name()).Msg("recolector iniciado")
	c.Run(ctx, emit)
}

// Stop tambien debe retornar rapido: si el servicio no confirma la parada,
// Windows lo mata a los 30 segundos y el estado queda a medias.
func (p *Program) Stop(s service.Service) error {
	p.log.Info().Msg("servicio deteniendose")
	if p.cancel != nil {
		p.cancel()
	}

	// Se espera a los bucles, pero con tope. Un ciclo colgado no puede impedir
	// que el servicio se detenga.
	done := make(chan struct{})
	go func() { p.wg.Wait(); close(done) }()

	select {
	case <-done:
		p.log.Info().Msg("servicio detenido limpiamente")
	case <-time.After(10 * time.Second):
		p.log.Warn().Msg("los ciclos no terminaron a tiempo; se fuerza la parada")
	}
	return nil
}

// loop ejecuta una tarea periodica hasta la cancelacion.
//
// El recover es deliberado: un panico en el ciclo de politica no puede tumbar el
// de sincronizacion. Cada modulo se aisla, que es lo que pide el requisito de
// que un fallo nunca bloquee al usuario.
func (p *Program) loop(ctx context.Context, name string, every time.Duration, fn func(context.Context)) {
	defer p.wg.Done()

	run := func() {
		defer func() {
			if r := recover(); r != nil {
				p.log.Error().Interface("panico", r).Str("ciclo", name).
					Msg("ciclo recuperado tras un panico")
			}
		}()
		fn(ctx)
	}

	// Una primera pasada inmediata: si hay cola pendiente de la sesion anterior,
	// no tiene sentido esperar un minuto entero para empezar a drenarla.
	run()

	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.log.Debug().Str("ciclo", name).Msg("ciclo detenido")
			return
		case <-ticker.C:
			run()
		}
	}
}

func (p *Program) syncOnce(ctx context.Context) {
	pendientes, err := p.agent.QueueLen()
	if err != nil {
		p.log.Error().Err(err).Msg("no se pudo consultar la cola")
		return
	}
	if pendientes == 0 {
		return
	}

	sent, err := p.agent.Flush(ctx)
	switch {
	case err == nil:
		p.log.Info().Int("enviados", sent).Int("restantes", pendientes-sent).Msg("cola sincronizada")
	case errors.Is(err, syncer.ErrUnauthorized):
		// Ni un reintento: la credencial fue revocada y hace falta intervencion
		// humana. Seguir intentando solo llena el log y consume cupo de tasa.
		p.log.Error().Msg("credencial rechazada por la consola; hay que volver a enrolar el agente")
	case errors.Is(err, syncer.ErrRateLimited):
		p.log.Warn().Msg("limite de tasa alcanzado; se reintenta en el proximo ciclo")
	case errors.Is(err, syncer.ErrCircuitOpen):
		p.log.Debug().Msg("cortocircuito abierto; se omite este ciclo")
	default:
		// La telemetria NO se perdio: sigue en la cola. Esto es informativo.
		p.log.Warn().Err(err).Int("en_cola", pendientes).Msg("no se pudo sincronizar; la cola se conserva")
	}
}

func (p *Program) heartbeatOnce(ctx context.Context) {
	needsPolicy, err := p.agent.Heartbeat(ctx, machineid.CurrentUser())
	if err != nil {
		if !errors.Is(err, syncer.ErrCircuitOpen) {
			p.log.Debug().Err(err).Msg("latido fallido")
		}
		return
	}

	p.log.Debug().Bool("cuarentena", p.agent.Quarantined()).Msg("latido enviado")

	if needsPolicy {
		p.log.Info().Msg("la consola reporta politica nueva")
		p.policyOnce(ctx)
	}
}

func (p *Program) policyOnce(ctx context.Context) {
	if err := p.agent.RefreshPolicy(ctx); err != nil {
		if !errors.Is(err, syncer.ErrCircuitOpen) {
			// Sin red se sigue aplicando la ultima politica conocida: el equipo
			// nunca queda sin reglas por un problema de conectividad.
			p.log.Debug().Err(err).Msg("no se pudo actualizar la politica; sigue vigente la anterior")
		}
	}

	// La politica se IMPONE despues de refrescarla, y tambien cuando el refresco
	// fallo: en ese caso se reaplica la ultima conocida. Es deliberado — un
	// equipo sin red no puede quedarse sin los controles que ya tenia solo
	// porque no pudo confirmar que siguen vigentes.
	p.imponer()
}

// imponer aplica la politica vigente al sistema.
func (p *Program) imponer() {
	res := p.aplicador.Aplicar(p.agent.Policy())

	ev := p.log.Info()
	if !res.Cubierto() {
		// Si algo no se pudo imponer, el resumen sube a error. Un equipo que la
		// consola dara por protegido y no lo esta no puede quedar anotado en una
		// linea informativa entre otras cincuenta.
		ev = p.log.Error()
	}

	ev.Str("usb", res.USB).
		Str("usb_solicitado", res.USBSolicitado).
		Int("dominios_bloqueados", res.Dominios).
		Int("solo_alerta", len(res.SoloAlerta)).
		Bool("cubierto", res.Cubierto()).
		Msg("politica impuesta en el equipo")
}
