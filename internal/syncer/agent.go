package syncer

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/fbolivar/nortis-agent/internal/agentcfg"
	"github.com/fbolivar/nortis-agent/internal/contract"
	"github.com/fbolivar/nortis-agent/internal/queue"
)

// batchSize es cuantos eventos se envian por peticion. La consola rechaza lotes
// de mas de 1000; se deja margen para no rozar el limite.
const batchSize = 500

// maxAttempts es cuantas veces se reintenta un evento antes de descartarlo.
// Un evento que la consola rechaza siempre bloquearia la cabeza de la cola —y
// con ella toda la telemetria posterior— si no se sacrificara.
const maxEventAttempts = 5

// Agent coordina la cola, el sincronizador y la politica vigente.
//
// No recolecta nada todavia: los recolectores son Fase 1 y se conectan aqui
// llamando a Enqueue. La separacion es deliberada — el ciclo de vida y la
// sincronizacion se validan solos antes de sumar la complejidad de leer el USN
// Journal o enganchar el portapapeles.
type Agent struct {
	cfg    agentcfg.Config
	q      *queue.Queue
	client *Client
	log    zerolog.Logger

	mu         sync.RWMutex
	endpointID string
	policy     *contract.Policy
	quarantine bool
}

func NewAgent(cfg agentcfg.Config, q *queue.Queue, client *Client, log zerolog.Logger) *Agent {
	return &Agent{cfg: cfg, q: q, client: client, log: log}
}

// Enqueue es el punto de entrada de los recolectores. No toca la red.
func (a *Agent) Enqueue(e contract.Event) {
	if err := a.q.Enqueue(e); err != nil {
		// Un fallo al encolar no puede tumbar al recolector: se registra y se
		// sigue. Perder un evento es malo; dejar de recolectar es peor.
		a.log.Error().Err(err).Str("tipo", string(e.Type)).Msg("no se pudo encolar el evento")
	}
}

// Policy devuelve la politica vigente, o nil si el equipo no tiene perfil.
func (a *Agent) Policy() *contract.Policy {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.policy
}

func (a *Agent) EndpointID() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.endpointID
}

// Restore recupera el estado persistido: identidad del equipo y ultima politica
// conocida.
//
// Es lo que permite que el agente arranque OFFLINE y siga aplicando la ultima
// politica en vez de quedarse sin reglas hasta que haya red. Un equipo que
// reinicia sin conexion no puede quedar desprotegido.
func (a *Agent) Restore() error {
	id, err := a.q.GetMeta(queue.MetaEndpointID)
	if err != nil {
		return err
	}

	raw, err := a.q.GetMeta(queue.MetaPolicyJSON)
	if err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.endpointID = id

	if raw != "" {
		var p contract.Policy
		if err := json.Unmarshal([]byte(raw), &p); err == nil {
			a.policy = &p
		} else {
			a.log.Warn().Err(err).Msg("la politica guardada no se pudo leer; se aplicara la que envie la consola")
		}
	}
	return nil
}

// Enroll registra el equipo, guarda su identidad y CUSTODIA la credencial propia
// que devuelve la consola.
//
// `saveCredential` se recibe como parametro en vez de llamar a agentcfg
// directamente: asi este paquete no depende del almacenamiento concreto —que es
// DPAPI y por tanto solo existe en Windows— y las pruebas pueden ejercitar el
// alta sin tocar el disco.
//
// El ORDEN importa. La credencial se persiste ANTES de dar el alta por buena: si
// se guardara despues y el proceso muriera en medio, el equipo quedaria
// registrado en la consola pero sin forma de hablar con ella, y la unica salida
// seria volver a enrolarlo.
func (a *Agent) Enroll(ctx context.Context, req contract.EnrollRequest, saveCredential func(string) error) error {
	res, err := a.client.Enroll(ctx, req)
	if err != nil {
		return err
	}

	// La consola siempre la devuelve. Si falta, este agente esta hablando con
	// una version anterior de la API: seguir adelante dejaria un agente que se
	// cree enrolado y no puede enviar nada, que es peor que fallar aqui.
	if res.AgentCredential == "" {
		return errors.New("la consola no devolvio la credencial del equipo; probablemente esta desactualizada")
	}

	if err := saveCredential(res.AgentCredential); err != nil {
		return err
	}
	a.client.SetEndpointCredential(res.AgentCredential)

	a.mu.Lock()
	a.endpointID = res.EndpointID
	a.mu.Unlock()

	a.log.Info().
		Str("endpoint_id", res.EndpointID).
		Str("perfil", res.ProfileID).
		Msg("equipo registrado en la consola")

	return a.q.SetMeta(queue.MetaEndpointID, res.EndpointID)
}

// Flush drena la cola hacia la consola. Devuelve cuantos eventos se enviaron.
func (a *Agent) Flush(ctx context.Context) (int, error) {
	endpointID := a.EndpointID()
	if endpointID == "" {
		return 0, errors.New("el agente no esta enrolado")
	}

	total := 0

	for {
		pending, err := a.q.Dequeue(batchSize)
		if err != nil {
			return total, err
		}
		if len(pending) == 0 {
			return total, nil
		}

		events := make([]contract.Event, len(pending))
		ids := make([]int64, len(pending))
		for i, p := range pending {
			events[i] = p.Event
			ids[i] = p.ID
		}

		res, err := a.client.Ingest(ctx, contract.IngestRequest{EndpointID: endpointID, Events: events})
		if err != nil {
			// Los eventos NO se borran: se quedan para el siguiente ciclo. Solo
			// se cuenta el intento, para que un lote imposible acabe cediendo el
			// paso en vez de bloquear la cola para siempre.
			dropped, ferr := a.q.Fail(ids, maxEventAttempts)
			if ferr != nil {
				a.log.Error().Err(ferr).Msg("no se pudo registrar el intento fallido")
			}
			if dropped > 0 {
				a.log.Warn().Int("descartados", dropped).
					Msg("eventos descartados tras agotar reintentos")
			}
			return total, err
		}

		// Rejected NO es un error: la consola descarta eventos individuales (por
		// ejemplo con fecha fuera de la ventana de retencion) sin tumbar el
		// lote. Reintentarlos seria un bucle infinito, asi que se confirman
		// igual y solo se deja constancia.
		if res.Rejected > 0 {
			a.log.Warn().
				Int("aceptados", res.Accepted).
				Int("rechazados", res.Rejected).
				Msg("la consola descarto parte del lote")
		}

		// Duplicados: la consola ya tenia estos eventos y los conto como
		// aceptados. Que aparezcan es NORMAL —significa que un envio anterior si
		// llego y la respuesta se perdio, exactamente el caso que la
		// deduplicacion existe para cubrir—. Que aparezcan SIEMPRE no lo es:
		// indica que esta cola no se esta purgando tras confirmar, y sin este
		// aviso ese fallo no se ve desde ningun lado.
		if res.Duplicates > 0 {
			a.log.Info().
				Int("duplicados", res.Duplicates).
				Msg("la consola ya tenia parte del lote; un envio anterior si habia llegado")
		}

		if err := a.q.Ack(ids); err != nil {
			return total, err
		}
		total += res.Accepted

		// Si el lote no venia lleno, la cola quedo vacia.
		if len(pending) < batchSize {
			break
		}
	}

	if total > 0 {
		_ = a.q.SetMeta(queue.MetaLastSyncAt, time.Now().UTC().Format(time.RFC3339))
	}
	return total, nil
}

// RefreshPolicy descarga la politica vigente y la persiste.
func (a *Agent) RefreshPolicy(ctx context.Context) error {
	endpointID := a.EndpointID()
	if endpointID == "" {
		return errors.New("el agente no esta enrolado")
	}

	res, err := a.client.Policy(ctx, endpointID)
	if err != nil {
		return err
	}

	if res.Profile == nil {
		a.log.Warn().Msg("el equipo no tiene perfil asignado: el agente observa pero no interviene")
		a.mu.Lock()
		a.policy = nil
		a.mu.Unlock()
		return a.q.SetMeta(queue.MetaPolicyJSON, "")
	}

	// AGENTE DESACTUALIZADO. Si la consola habla una version de contrato mayor
	// que la que este binario entiende, NO se aplica la politica nueva: se sigue
	// con la ultima conocida. Aplicar la mitad de una politica es peor que no
	// aplicarla, porque el panel diria que el equipo esta cubierto.
	if res.Profile.SchemaVersion > contract.PolicySchemaVersion {
		a.log.Error().
			Int("consola", res.Profile.SchemaVersion).
			Int("agente", contract.PolicySchemaVersion).
			Msg("politica mas nueva que este agente; se mantiene la anterior y hace falta actualizar")
		return nil
	}

	raw, err := json.Marshal(res.Profile.Config)
	if err != nil {
		return err
	}

	a.mu.Lock()
	cfg := res.Profile.Config
	a.policy = &cfg
	a.mu.Unlock()

	a.log.Info().
		Str("perfil", res.Profile.Name).
		Bool("monitoreo_autorizado", res.MonitoringAllowed).
		Msg("politica actualizada")

	if err := a.q.SetMeta(queue.MetaPolicyJSON, string(raw)); err != nil {
		return err
	}
	return a.q.SetMeta(queue.MetaPolicyUpdatedAt, res.Profile.UpdatedAt.Format(time.RFC3339))
}

// Heartbeat reporta señal de vida y devuelve si hay que recargar la politica.
func (a *Agent) Heartbeat(ctx context.Context, user string) (needsPolicy bool, err error) {
	endpointID := a.EndpointID()
	if endpointID == "" {
		return false, errors.New("el agente no esta enrolado")
	}

	res, err := a.client.Heartbeat(ctx, contract.HeartbeatRequest{
		EndpointID:   endpointID,
		AgentVersion: contract.AgentVersion,
		User:         user,
	})
	if err != nil {
		return false, err
	}

	a.mu.Lock()
	wasQuarantined := a.quarantine
	a.quarantine = res.Quarantined
	a.mu.Unlock()

	if res.Quarantined && !wasQuarantined {
		a.log.Warn().Msg("la consola puso este equipo en cuarentena")
	}

	if res.PolicyUpdatedAt == nil {
		return false, nil
	}

	// Se compara con lo guardado para no descargar la politica entera en cada
	// latido: con doscientos equipos latiendo cada cinco minutos, la diferencia
	// entre pedir una marca de tiempo y pedir el objeto completo es real.
	known, _ := a.q.GetMeta(queue.MetaPolicyUpdatedAt)
	return known != res.PolicyUpdatedAt.Format(time.RFC3339), nil
}

// Quarantined indica si la consola marco el equipo en cuarentena.
func (a *Agent) Quarantined() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.quarantine
}

// QueueLen expone cuantos eventos esperan.
func (a *Agent) QueueLen() (int, error) { return a.q.Len() }

// Version consulta la version disponible en la consola. Lo usa el updater; se
// expone aqui para no filtrar el cliente HTTP fuera del sincronizador.
func (a *Agent) Version(ctx context.Context) (contract.VersionResponse, error) {
	return a.client.Version(ctx)
}
