// Package service implementa el ciclo de vida como servicio de Windows.
//
// Se valida ESTO antes que ningun recolector. Un agente que recolecta
// perfectamente pero no arranca con el sistema, o que no se deja detener, es un
// agente que el cliente desinstala en la primera semana. El orden importa.
package service

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/kardianos/service"
	"github.com/rs/zerolog"

	"github.com/fbolivar/nortis-agent/internal/agentcfg"
	"github.com/fbolivar/nortis-agent/internal/collector"
	"github.com/fbolivar/nortis-agent/internal/contract"
	"github.com/fbolivar/nortis-agent/internal/machineid"
	"github.com/fbolivar/nortis-agent/internal/syncer"
)

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

	cancel context.CancelFunc
	wg     sync.WaitGroup
	cfg    agentcfg.Config
}

func NewProgram(cfg agentcfg.Config, agent *syncer.Agent, log zerolog.Logger) *Program {
	return &Program{agent: agent, log: log, cfg: cfg}
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

	p.wg.Add(3)
	go p.loop(ctx, "sincronizacion", p.cfg.SyncInterval.Duration, p.syncOnce)
	go p.loop(ctx, "latido", p.cfg.HeartbeatInterval.Duration, p.heartbeatOnce)
	go p.loop(ctx, "politica", p.cfg.PolicyInterval.Duration, p.policyOnce)

	p.arrancarRecolectores(ctx)

	return nil
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

	for _, c := range collector.Default(p.log) {
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
}
