package collector

import (
	"time"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// wtsConnectState es el estado de conexion de una sesion, tal como lo reporta
// Terminal Services. Vive aqui y no en el archivo de Windows porque describe el
// DOMINIO —en que estado esta una sesion— y no como se consulta.
type wtsConnectState uint32

const (
	wtsActive       wtsConnectState = 0 // usuario conectado y en uso
	wtsConnected    wtsConnectState = 1
	wtsDisconnected wtsConnectState = 4 // sesion viva pero sin nadie delante
)

// sesion describe el estado observable de una sesion interactiva.
type sesion struct {
	ID        uint32
	Usuario   string
	Estado    wtsConnectState
	Inactivo  time.Duration
	LogonTime time.Time
}

// UmbralInactividad es cuanto sin teclado ni raton se considera inactividad.
//
// Cinco minutos: por debajo, cualquier pausa para leer un documento generaria un
// par idle_start/idle_end y el reporte de uso se llenaria de ruido. Por encima,
// se dejarian de ver ausencias reales de media hora.
const UmbralInactividad = 5 * time.Minute

// estadoSesion es lo que el recolector recuerda de una sesion entre sondeos.
type estadoSesion struct {
	Usuario  string
	Inactiva bool
	// Desconectada distingue "bloqueo la pantalla" de "cerro sesion": en la
	// primera la sesion sigue viva y el usuario volvera; en la segunda no.
	Desconectada bool
}

// maquinaSesiones convierte una secuencia de sondeos en eventos.
//
// Se mantiene PURA —sin llamadas al sistema— para poder probar las transiciones,
// que es donde estan los errores sutiles: un logoff que no se emite deja una
// sesion abierta para siempre en el panel, y un idle_start repetido en cada
// sondeo inunda la cola.
type maquinaSesiones struct {
	previo map[uint32]estadoSesion
}

func nuevaMaquinaSesiones() *maquinaSesiones {
	return &maquinaSesiones{previo: map[uint32]estadoSesion{}}
}

// observar compara el sondeo actual contra el anterior y devuelve los eventos.
func (m *maquinaSesiones) observar(actual []sesion, ahora time.Time) []contract.Event {
	var eventos []contract.Event
	visto := make(map[uint32]bool, len(actual))

	for _, s := range actual {
		visto[s.ID] = true
		anterior, existia := m.previo[s.ID]

		inactiva := s.Inactivo >= UmbralInactividad
		desconectada := s.Estado == wtsDisconnected

		switch {
		case !existia:
			// Sesion nueva. Solo se emite logon si hay usuario: una sesion sin
			// nombre es una pantalla de bloqueo, no una persona entrando.
			eventos = append(eventos, contract.Event{
				Type: contract.EventLogon, OccurredAt: ahora,
				Payload: map[string]any{
					"user":         s.Usuario,
					"session_type": tipoSesion(s.Estado),
				},
			})

		case anterior.Usuario != s.Usuario:
			// Cambio de usuario en el mismo identificador de sesion (cambio
			// rapido de usuario). Sin el logoff explicito, el panel atribuiria
			// al usuario nuevo la actividad del anterior.
			eventos = append(eventos,
				contract.Event{
					Type: contract.EventLogoff, OccurredAt: ahora,
					Payload: map[string]any{"user": anterior.Usuario},
				},
				contract.Event{
					Type: contract.EventLogon, OccurredAt: ahora,
					Payload: map[string]any{"user": s.Usuario, "session_type": tipoSesion(s.Estado)},
				},
			)
		}

		// Transiciones de inactividad. Se emiten SOLO en el cambio de estado: si
		// se emitieran mientras dura, cada sondeo añadiria un evento y una noche
		// entera generaria miles.
		if existia && inactiva != anterior.Inactiva {
			tipo := contract.EventIdleEnd
			if inactiva {
				tipo = contract.EventIdleStart
			}
			eventos = append(eventos, contract.Event{
				Type: tipo, OccurredAt: ahora,
				Payload: map[string]any{
					"user":         s.Usuario,
					"idle_seconds": int(s.Inactivo.Seconds()),
				},
			})
		}

		m.previo[s.ID] = estadoSesion{
			Usuario:      s.Usuario,
			Inactiva:     inactiva,
			Desconectada: desconectada,
		}
	}

	// Sesiones que desaparecieron: el usuario cerro sesion.
	for id, anterior := range m.previo {
		if visto[id] {
			continue
		}
		eventos = append(eventos, contract.Event{
			Type: contract.EventLogoff, OccurredAt: ahora,
			Payload: map[string]any{"user": anterior.Usuario},
		})
		delete(m.previo, id)
	}

	return eventos
}

func tipoSesion(estado wtsConnectState) string {
	switch estado {
	case wtsDisconnected:
		return "remote"
	default:
		return "console"
	}
}
