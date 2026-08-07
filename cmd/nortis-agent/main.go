// Comando nortis-agent: servicio de endpoint de Nortis.
//
// Verbos:
//
//	enroll -key <API_KEY> [-url <CONSOLA>]   registra el equipo y guarda la credencial
//	install | start | stop | uninstall       ciclo de vida del servicio de Windows
//	run                                      ejecuta en primer plano (diagnostico)
//	status                                   estado local, sin tocar la red
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/kardianos/service"
	"github.com/rs/zerolog"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/fbolivar/nortis-agent/internal/agentcfg"
	"github.com/fbolivar/nortis-agent/internal/clipwatch"
	"github.com/fbolivar/nortis-agent/internal/contract"
	"github.com/fbolivar/nortis-agent/internal/enforce"
	"github.com/fbolivar/nortis-agent/internal/machineid"
	"github.com/fbolivar/nortis-agent/internal/queue"
	svc "github.com/fbolivar/nortis-agent/internal/service"
	"github.com/fbolivar/nortis-agent/internal/syncer"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "enroll":
		err = cmdEnroll(os.Args[2:])
	case "install", "uninstall", "start", "stop", "restart":
		err = cmdControl(os.Args[1])
	case "run":
		err = cmdRun(true)
	case "service":
		// Verbo interno: es con el que el gestor de servicios de Windows
		// arranca el binario.
		err = cmdRun(false)
	case "clipboard-watch":
		// Verbo interno: lo lanza el servicio DENTRO de la sesion del usuario.
		// No es para uso manual y por eso no aparece en la ayuda.
		err = cmdClipboardWatch(os.Args[2:])
	case "revert":
		err = cmdRevert()
	case "status":
		err = cmdStatus()
	case "selftest":
		err = cmdSelfTest()
	case "version":
		fmt.Printf("nortis-agent %s (contrato de politica v%d)\n", contract.AgentVersion, contract.PolicySchemaVersion)
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `nortis-agent — agente de endpoint de Nortis

  enroll -key <API_KEY> [-url <URL>]   Registra este equipo en la consola
  install                              Instala el servicio de Windows
  start | stop | restart               Controla el servicio
  uninstall                            Desinstala el servicio y revierte los controles
  revert                               Revierte los controles sin tocar el servicio
  run                                  Ejecuta en primer plano (diagnostico)
  status                               Estado local, sin tocar la red
  selftest                             Valida el camino cola -> consola
  version                              Version del agente

La credencial se guarda cifrada con DPAPI y solo se puede descifrar en esta
maquina. El servicio requiere privilegios de administrador para instalarse.
`)
}

/* --------------------------------------------------------------- Logger --- */

// newLogger escribe a archivo con rotacion y, opcionalmente, a consola.
//
// La rotacion con tope no es un lujo: un agente que corre durante meses y
// escribe un log sin limite acaba llenando el disco del cliente — el mismo
// problema que el producto dice prevenir, causado por el propio agente.
func newLogger(alsoConsole bool) zerolog.Logger {
	rotador := &lumberjack.Logger{
		Filename:   agentcfg.LogPath(),
		MaxSize:    10, // MB
		MaxBackups: 3,
		MaxAge:     30, // dias
		Compress:   true,
	}

	var w io.Writer = rotador
	if alsoConsole {
		w = zerolog.MultiLevelWriter(
			rotador,
			zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339},
		)
	}

	return zerolog.New(w).With().Timestamp().Logger()
}

/* --------------------------------------------------------------- enroll --- */

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	key := fs.String("key", "", "credencial del tenant (nrt_live_...)")
	url := fs.String("url", "", "URL de la consola")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *key == "" {
		return errors.New("falta -key")
	}

	cfg, err := agentcfg.Load()
	if err != nil {
		return err
	}
	if *url != "" {
		cfg.ConsoleURL = *url
		if err := agentcfg.Save(cfg); err != nil {
			return err
		}
	}

	fingerprint, err := machineid.Fingerprint()
	if err != nil {
		return fmt.Errorf("no se pudo derivar la identidad de la maquina: %w", err)
	}

	log := newLogger(true)

	q, err := queue.Open(agentcfg.QueuePath())
	if err != nil {
		return err
	}
	defer q.Close()

	client := syncer.New(cfg.ConsoleURL, *key)
	agent := syncer.NewAgent(cfg, q, client, log)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Enroll protege con DPAPI la credencial que devuelve la consola ANTES de dar
	// el alta por terminada.
	err = agent.Enroll(ctx, contract.EnrollRequest{
		MachineFingerprint: fingerprint,
		Hostname:           machineid.Hostname(),
		OSVersion:          machineid.OSVersion(),
		AgentVersion:       contract.AgentVersion,
		User:               machineid.CurrentUser(),
	}, agentcfg.SaveEndpointCredential)
	if err != nil {
		return fmt.Errorf("no se pudo registrar el equipo: %w", err)
	}

	// LA CLAVE DE LA ORGANIZACION NO SE GUARDA: ya cumplio su unica funcion.
	//
	// Dejarla en disco era el agujero. La misma clave vivia en cada portatil de
	// la flota, y quien la extrajera de uno podia enrolar equipos nuevos y
	// —antes de separar las credenciales— escribir telemetria en nombre de
	// cualquier otro equipo del cliente. De aqui en adelante el agente firma
	// todo con la credencial propia.
	//
	// Se borra tambien la que hubiera dejado una version anterior del agente,
	// que si la persistia.
	if err := agentcfg.DiscardOrganizationKey(); err != nil {
		log.Warn().Err(err).Msg("no se pudo borrar del disco la clave de la organizacion; conviene revisarlo")
	}

	// Se descarga la politica de inmediato: si el servicio arranca antes del
	// primer ciclo, ya tiene reglas que aplicar.
	if err := agent.RefreshPolicy(ctx); err != nil {
		log.Warn().Err(err).Msg("no se pudo descargar la politica inicial; se hara en el primer ciclo")
	}

	fmt.Printf("Equipo registrado.\n  endpoint: %s\n  consola:  %s\n\nSiguiente paso: nortis-agent install\n",
		agent.EndpointID(), cfg.ConsoleURL)
	return nil
}

/* ------------------------------------------------------------- servicio --- */

func buildProgram(console bool) (*svc.Program, *queue.Queue, error) {
	cfg, err := agentcfg.Load()
	if err != nil {
		return nil, nil, err
	}

	// El servicio arranca con la credencial del EQUIPO. La de la organizacion ya
	// no existe en disco tras el alta, y aunque existiera no serviria: la
	// consola solo la acepta para enrolar.
	endpointCred, err := agentcfg.LoadEndpointCredential()
	if err != nil {
		return nil, nil, err
	}

	log := newLogger(console)

	q, err := queue.Open(agentcfg.QueuePath())
	if err != nil {
		return nil, nil, err
	}

	// La clave de organizacion va vacia: este proceso no vuelve a enrolar. Si
	// alguna vez lo intentara, el cliente falla de inmediato por credencial
	// ausente en vez de mandar una peticion sin firmar.
	client := syncer.New(cfg.ConsoleURL, "")
	client.SetEndpointCredential(endpointCred)

	agent := syncer.NewAgent(cfg, q, client, log)

	return svc.NewProgram(cfg, agent, log), q, nil
}

func cmdRun(console bool) error {
	prog, q, err := buildProgram(console)
	if err != nil {
		return err
	}
	defer q.Close()

	s, err := service.New(prog, svc.Config)
	if err != nil {
		return err
	}
	return s.Run()
}

func cmdControl(action string) error {
	// Para install/uninstall no hace falta credencial ni cola: solo hablar con
	// el gestor de servicios. Exigirlas obligaria a enrolar antes de instalar, y
	// el instalador MSI hace justo lo contrario.
	s, err := service.New(&noopProgram{}, svc.Config)
	if err != nil {
		return err
	}

	errServicio := service.Control(s, action)

	// LA REVERSION VA SOLO EN LA DESINSTALACION, nunca en `stop`.
	//
	// Es deliberado: si detener el servicio levantara los bloqueos, cualquiera
	// con permiso para parar un servicio desbloquearia el USB en dos clics y el
	// control no valdria nada. El precio es que un agente que muera de forma
	// anomala deja el equipo protegido hasta que alguien lo desinstale — que es
	// el lado correcto en el que equivocarse para un producto de seguridad.
	//
	// Va DESPUES de detener el servicio para que no vuelva a aplicar la politica
	// entre la reversion y su parada.
	//
	// Y SE REVIERTE AUNQUE LA DESINSTALACION FALLE. La primera version devolvia
	// el error de service.Control antes de llegar aqui, y bastaba con que el
	// servicio no estuviera instalado —porque se probo el agente en primer plano,
	// o porque alguien ya lo quito a mano— para que `uninstall` se negara a hacer
	// NADA y el equipo se quedara con el USB en solo lectura y el archivo hosts
	// intervenido para siempre, sin ninguna via dentro del producto para
	// deshacerlo. Es justo el escenario contra el que se escribio este paquete:
	// un agente que se desinstala dejando el equipo bloqueado no es un producto
	// de seguridad, es una incidencia de soporte. El error del servicio se
	// reporta, pero no puede impedir que el equipo vuelva a su estado.
	if action == "uninstall" {
		enforce.NuevoAplicador(newLogger(true), agentcfg.Dir()).Revertir()
	}

	if errServicio != nil {
		return fmt.Errorf("%s: %w (¿tiene privilegios de administrador?)", action, errServicio)
	}

	fmt.Printf("Servicio: %s completado.\n", action)
	return nil
}

// cmdRevert deshace los controles sin tocar el servicio.
//
// `uninstall` mezcla dos cosas que no siempre van juntas: quitar el servicio y
// devolver el equipo a su estado. Hace falta poder hacer lo segundo solo — al
// diagnosticar, tras una prueba en primer plano, o cuando el servicio ya no esta
// pero los controles si.
func cmdRevert() error {
	enforce.NuevoAplicador(newLogger(true), agentcfg.Dir()).Revertir()
	fmt.Println("Controles revertidos: el equipo queda como estaba antes de aplicar la politica.")
	return nil
}

// noopProgram existe solo para poder construir el service.Service en las
// operaciones de control, que no ejecutan nada.
type noopProgram struct{}

func (n *noopProgram) Start(service.Service) error { return nil }
func (n *noopProgram) Stop(service.Service) error  { return nil }

/* ------------------------------------------------------------- selftest --- */

// cmdSelfTest valida el camino completo recolector -> cola -> consola.
//
// Existe porque los recolectores reales son Fase 1 y todavia no hay ninguno: sin
// esto, la unica forma de saber si la sincronizacion funciona seria esperar a
// tener el USN Journal enganchado, y entonces un fallo podria estar en
// cualquiera de las dos mitades. Se valida la tuberia antes de conectarle nada.
//
// Los eventos que emite son REALES y quedan en la telemetria del equipo: es un
// diagnostico para instalacion y soporte, no algo que ejecutar en produccion a
// la ligera.
func cmdSelfTest() error {
	cfg, err := agentcfg.Load()
	if err != nil {
		return err
	}

	apiKey, err := agentcfg.LoadCredential()
	if err != nil {
		return err
	}

	log := newLogger(true)

	q, err := queue.Open(agentcfg.QueuePath())
	if err != nil {
		return err
	}
	defer q.Close()

	agent := syncer.NewAgent(cfg, q, syncer.New(cfg.ConsoleURL, apiKey), log)
	if err := agent.Restore(); err != nil {
		return err
	}
	if agent.EndpointID() == "" {
		return errors.New("el agente no esta enrolado: ejecute primero nortis-agent enroll")
	}

	antes, _ := q.Len()

	ahora := time.Now().UTC()
	agent.Enqueue(contract.Event{
		Type: contract.EventLogon, OccurredAt: ahora,
		Payload: map[string]any{"user": machineid.CurrentUser(), "session_type": "console"},
	})
	agent.Enqueue(contract.Event{
		Type: contract.EventAppOpen, OccurredAt: ahora,
		Payload: map[string]any{"app": "nortis-agent.exe", "category": "seguridad"},
	})
	// Evento deliberadamente invalido: la consola debe descartarlo SIN tumbar el
	// lote. Si tumbara el lote, un bug del agente dejaria al equipo mudo.
	agent.Enqueue(contract.Event{
		Type: contract.EventWebVisit, OccurredAt: ahora,
		Payload: map[string]any{"domain": ""},
	})

	encolados, _ := q.Len()
	fmt.Printf("encolados: %d eventos (habia %d)\n", encolados-antes, antes)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	enviados, err := agent.Flush(ctx)
	if err != nil {
		return fmt.Errorf("la sincronizacion fallo: %w", err)
	}

	restantes, _ := q.Len()
	fmt.Printf("aceptados por la consola: %d\nen cola tras sincronizar: %d\n", enviados, restantes)

	if restantes != 0 {
		return fmt.Errorf("la cola no quedo vacia: %d eventos siguen pendientes", restantes)
	}

	necesita, err := agent.Heartbeat(ctx, machineid.CurrentUser())
	if err != nil {
		return fmt.Errorf("el latido fallo: %w", err)
	}
	fmt.Printf("latido: correcto (politica nueva: %v, cuarentena: %v)\n", necesita, agent.Quarantined())

	fmt.Println("\nAutodiagnostico superado: cola, sincronizacion, latido y politica funcionan.")
	return nil
}

/* --------------------------------------------------------------- status --- */

func cmdStatus() error {
	cfg, err := agentcfg.Load()
	if err != nil {
		return err
	}

	q, err := queue.Open(agentcfg.QueuePath())
	if err != nil {
		return err
	}
	defer q.Close()

	pendientes, _ := q.Len()
	endpointID, _ := q.GetMeta(queue.MetaEndpointID)
	lastSync, _ := q.GetMeta(queue.MetaLastSyncAt)
	politica, _ := q.GetMeta(queue.MetaPolicyUpdatedAt)

	fingerprint, ferr := machineid.Fingerprint()
	if ferr != nil {
		fingerprint = "(no disponible)"
	}

	fmt.Printf(`nortis-agent %s

  consola:          %s
  equipo:           %s
  huella:           %s
  credencial:       %s
  eventos en cola:  %d
  ultima sincro:    %s
  politica desde:   %s
  datos en:         %s
`,
		contract.AgentVersion,
		cfg.ConsoleURL,
		orDash(endpointID),
		fingerprint[:min(16, len(fingerprint))],
		credentialState(),
		pendientes,
		orDash(lastSync),
		orDash(politica),
		agentcfg.Dir(),
	)
	return nil
}

func credentialState() string {
	if !agentcfg.HasCredential() {
		return "sin enrolar"
	}
	if _, err := agentcfg.LoadCredential(); err != nil {
		return "presente pero ilegible en esta maquina"
	}
	return "protegida con DPAPI"
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// cmdClipboardWatch ejecuta el vigilante del portapapeles.
//
// Lo lanza el SERVICIO dentro de la sesion del usuario y lee su salida estandar;
// no esta pensado para ejecutarse a mano. Existe como subcomando del mismo
// binario, y no como un segundo ejecutable, para que el instalador despliegue un
// solo archivo y la firma de codigo cubra las dos piezas a la vez.
func cmdClipboardWatch(args []string) error {
	fs := flag.NewFlagSet("clipboard-watch", flag.ExitOnError)
	modo := fs.String("mode", "allow", "modo de portapapeles: allow, alert o block")
	protegidas := fs.String("protected", "", "procesos protegidos, separados por comas")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var fuentes []string
	for _, f := range strings.Split(*protegidas, ",") {
		if f = strings.TrimSpace(f); f != "" {
			fuentes = append(fuentes, f)
		}
	}

	// EL HILO SE FIJA. Los mensajes de ventana se entregan al hilo que creo la
	// ventana, y el planificador de Go mueve las goroutines entre hilos del
	// sistema cuando le conviene. Sin fijarlo, la ventana deja de recibir
	// WM_CLIPBOARDUPDATE en cuanto la goroutine migra — y no hay ningun error:
	// simplemente no vuelve a llegar nada, que es el peor modo de fallo posible.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// La salida va sin bufer al proceso padre, una linea JSON por copia.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	return clipwatch.Ejecutar(ctx, os.Stdout, clipwatch.Opciones{
		Modo:              *modo,
		FuentesProtegidas: fuentes,
	})
}
