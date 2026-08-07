//go:build windows

package collector

import (
	"context"
	"time"

	"github.com/rs/zerolog"
)

// IntervaloSesiones es cada cuanto se sondean las sesiones.
//
// 30 segundos: suficiente para que un inicio de sesion aparezca en el panel casi
// al momento, y lo bastante espaciado para que el sondeo sea invisible. La
// precision del umbral de inactividad es de +-30s, que para "lleva cinco minutos
// sin tocar el equipo" sobra.
const IntervaloSesiones = 30 * time.Second

// SessionCollector observa las sesiones interactivas: inicio y cierre de sesion,
// y entrada y salida de inactividad.
type SessionCollector struct {
	log     zerolog.Logger
	maquina *maquinaSesiones
}

func NewSessionCollector(log zerolog.Logger) *SessionCollector {
	return &SessionCollector{
		log:     log.With().Str("recolector", "sesiones").Logger(),
		maquina: nuevaMaquinaSesiones(),
	}
}

func (c *SessionCollector) Name() string { return "sesiones" }

func (c *SessionCollector) Run(ctx context.Context, emit Emit) {
	ticker := time.NewTicker(IntervaloSesiones)
	defer ticker.Stop()

	// El primer sondeo NO emite eventos: solo siembra el estado inicial. Sin
	// esto, cada arranque del servicio generaria un logon falso por cada sesion
	// ya abierta, y el panel mostraria como "entro al equipo" lo que en realidad
	// fue "se reinicio el agente".
	c.sembrar()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.sondear(emit)
		}
	}
}

func (c *SessionCollector) sembrar() {
	sesiones, err := enumerarSesiones()
	if err != nil {
		c.log.Warn().Err(err).Msg("no se pudieron enumerar las sesiones al arrancar")
		return
	}
	// Se descarta el resultado: solo interesa que la maquina quede con el estado
	// actual como punto de partida.
	_ = c.maquina.observar(sesiones, time.Now().UTC())
	c.log.Debug().Int("sesiones", len(sesiones)).Msg("estado inicial de sesiones registrado")
}

func (c *SessionCollector) sondear(emit Emit) {
	sesiones, err := enumerarSesiones()
	if err != nil {
		c.log.Warn().Err(err).Msg("no se pudieron enumerar las sesiones")
		return
	}

	for _, e := range c.maquina.observar(sesiones, time.Now().UTC()) {
		c.log.Debug().Str("tipo", string(e.Type)).Interface("payload", e.Payload).Msg("evento de sesion")
		emit(e)
	}
}
