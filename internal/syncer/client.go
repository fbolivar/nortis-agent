// Package syncer habla con la API de la consola.
//
// PRINCIPIO RECTOR: el agente nunca bloquea al usuario esperando a la red. Todo
// aqui tiene tiempo limite, reintenta con retroceso exponencial y se rinde
// abriendo un cortocircuito. Si la consola esta caida una hora, el equipo del
// usuario funciona exactamente igual — la telemetria se acumula en la cola.
package syncer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// Errores que el llamador necesita distinguir para decidir que hacer.
var (
	// ErrUnauthorized: la credencial ya no sirve. NO tiene sentido reintentar;
	// hace falta volver a enrolar el agente.
	ErrUnauthorized = errors.New("credencial invalida o revocada")
	// ErrRateLimited: hay que esperar. Reintentar de inmediato solo empeora.
	ErrRateLimited = errors.New("limite de tasa excedido")
	// ErrInvalidRequest: el lote esta mal formado. Reenviarlo tal cual daria el
	// mismo resultado eternamente.
	ErrInvalidRequest = errors.New("peticion invalida")
	// ErrCircuitOpen: se acumularon fallos y el cliente dejo de intentar por un
	// rato.
	ErrCircuitOpen = errors.New("cortocircuito abierto")
)

type Client struct {
	baseURL string
	orgKey  string
	http    *http.Client

	// credMu protege endpointCred, que se rellena al enrolar y cambia si el
	// equipo se re-enrola: la consola ROTA la credencial en cada alta.
	credMu       sync.RWMutex
	endpointCred string

	mu              sync.Mutex
	consecutiveFail int
	openUntil       time.Time
}

// New construye el cliente con la clave de la ORGANIZACION, que solo sirve para
// el alta. La credencial del equipo se instala despues con SetEndpointCredential.
func New(baseURL, orgKey string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		orgKey:  orgKey,
		http: &http.Client{
			// Limite total por peticion. Sin el, una conexion a medio abrir
			// puede dejar una goroutine colgada indefinidamente y, con ella, el
			// ciclo de sincronizacion entero.
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					// InsecureSkipVerify NO se pone NUNCA, ni siquiera en
					// desarrollo. Un agente que acepta cualquier certificado es
					// un agente que se puede interceptar, y por ahi se va toda
					// la telemetria de la organizacion. Para desarrollo se usa
					// http://localhost, que no pasa por aqui.
				},
				MaxIdleConns:    4,
				IdleConnTimeout: 90 * time.Second,
			},
		},
	}
}

/* --------------------------------------------------------- Credenciales --- */

// ErrNotEnrolled se devuelve cuando se intenta una operacion que exige la
// credencial del equipo sin haberla instalado. Es distinto de ErrUnauthorized:
// aqui no hemos llegado a preguntarle nada al servidor.
var ErrNotEnrolled = errors.New("el agente no esta enrolado: falta la credencial del equipo")

// SetEndpointCredential instala la credencial propia del equipo. La llama el
// enrolamiento y, al arrancar, la restauracion del estado guardado.
func (c *Client) SetEndpointCredential(cred string) {
	c.credMu.Lock()
	defer c.credMu.Unlock()
	c.endpointCred = cred
}

func (c *Client) endpointCredential() string {
	c.credMu.RLock()
	defer c.credMu.RUnlock()
	return c.endpointCred
}

/* ------------------------------------------------------- Cortocircuito --- */

const (
	circuitThreshold = 5
	circuitCooldown  = 2 * time.Minute
)

func (c *Client) circuitOpen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Before(c.openUntil)
}

func (c *Client) recordSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.consecutiveFail = 0
	c.openUntil = time.Time{}
}

func (c *Client) recordFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.consecutiveFail++
	if c.consecutiveFail >= circuitThreshold {
		// Tras varios fallos seguidos se deja de intentar un rato. Con doscientos
		// equipos reintentando contra una consola caida, el trafico agregado
		// impide que se recupere: el cortocircuito es tanto por el agente como
		// por el servidor.
		c.openUntil = time.Now().Add(circuitCooldown)
		c.consecutiveFail = 0
	}
}

/* -------------------------------------------------------------- Llamada --- */

const maxAttempts = 3

// post envia una peticion firmada con `credential`. La credencial se pasa
// explicitamente en cada llamada, en vez de guardarse una sola en el cliente,
// para que sea imposible mandar la clave de la organizacion a una ruta de
// telemetria por descuido: aqui se ve cual va en cada sitio.
func (c *Client) post(ctx context.Context, path, credential string, body, out any) error {
	if credential == "" {
		return ErrNotEnrolled
	}
	if c.circuitOpen() {
		return ErrCircuitOpen
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("serializando la peticion: %w", err)
	}

	var lastErr error

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			// Retroceso exponencial: 1s, 2s. Se respeta la cancelacion para que
			// detener el servicio no tenga que esperar al reintento.
			wait := time.Duration(math.Pow(2, float64(attempt-1))) * time.Second
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}

		err := c.doOnce(ctx, path, credential, payload, out)
		if err == nil {
			c.recordSuccess()
			return nil
		}

		// Estos errores no mejoran reintentando: son decisiones del servidor.
		if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrInvalidRequest) {
			c.recordSuccess() // el servidor respondio: la red esta bien
			return err
		}
		if errors.Is(err, ErrRateLimited) {
			c.recordSuccess()
			return err
		}

		lastErr = err
	}

	c.recordFailure()
	return lastErr
}

func (c *Client) doOnce(ctx context.Context, path, credential string, payload []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("User-Agent", "nortis-agent/"+contract.AgentVersion)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("red: %w", err)
	}
	defer resp.Body.Close()

	// Se acota la lectura: una respuesta gigante de un intermediario mal
	// configurado no puede agotar la memoria del agente.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("leyendo la respuesta: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("respuesta ilegible: %w", err)
		}
		return nil

	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusTooManyRequests:
		return ErrRateLimited
	case http.StatusBadRequest:
		return fmt.Errorf("%w: %s", ErrInvalidRequest, apiMessage(body))
	default:
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, apiMessage(body))
	}
}

func apiMessage(body []byte) string {
	var e contract.APIError
	if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
		return e.Error.Message
	}
	if len(body) > 200 {
		body = body[:200]
	}
	return string(body)
}

/* ------------------------------------------------------------ Endpoints --- */

// Enroll es la UNICA llamada que presenta la clave de la organizacion, y lo que
// devuelve a cambio es la credencial propia del equipo. El llamador debe
// instalarla con SetEndpointCredential y persistirla: viaja en claro una sola
// vez.
func (c *Client) Enroll(ctx context.Context, req contract.EnrollRequest) (contract.EnrollResponse, error) {
	var out contract.EnrollResponse
	err := c.post(ctx, "/api/agent/enroll", c.orgKey, req, &out)
	return out, err
}

func (c *Client) Ingest(ctx context.Context, req contract.IngestRequest) (contract.IngestResponse, error) {
	var out contract.IngestResponse
	err := c.post(ctx, "/api/agent/events", c.endpointCredential(), req, &out)
	return out, err
}

func (c *Client) Policy(ctx context.Context, endpointID string) (contract.PolicyResponse, error) {
	var out contract.PolicyResponse
	err := c.post(ctx, "/api/agent/policy", c.endpointCredential(), contract.PolicyRequest{EndpointID: endpointID}, &out)
	return out, err
}

func (c *Client) Heartbeat(ctx context.Context, req contract.HeartbeatRequest) (contract.HeartbeatResponse, error) {
	var out contract.HeartbeatResponse
	err := c.post(ctx, "/api/agent/heartbeat", c.endpointCredential(), req, &out)
	return out, err
}

// Version consulta la version disponible. No lleva credencial: un agente con la
// clave revocada tiene que poder enterarse igualmente de que hay una version
// nueva — es justo el caso en que mas falta hace actualizarlo.
func (c *Client) Version(ctx context.Context) (contract.VersionResponse, error) {
	var out contract.VersionResponse

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/agent/version", nil)
	if err != nil {
		return out, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return out, fmt.Errorf("red: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return out, err
	}
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return out, json.Unmarshal(body, &out)
}

// PollComandos reclama los comandos pendientes del equipo. El servidor los marca
// enviados al devolverlos.
func (c *Client) PollComandos(ctx context.Context, endpointID string) (contract.PollComandosResponse, error) {
	var out contract.PollComandosResponse
	err := c.post(ctx, "/api/agent/commands", c.endpointCredential(),
		contract.PollComandosRequest{EndpointID: endpointID}, &out)
	return out, err
}

// ReportarComando informa el resultado de ejecutar un comando.
func (c *Client) ReportarComando(ctx context.Context, req contract.ReportarComandoRequest) error {
	var out struct {
		OK bool `json:"ok"`
	}
	return c.post(ctx, "/api/agent/commands/result", c.endpointCredential(), req, &out)
}

// PollTareas reclama las tareas pendientes del equipo.
func (c *Client) PollTareas(ctx context.Context, endpointID string) (contract.PollTareasResponse, error) {
	var out contract.PollTareasResponse
	err := c.post(ctx, "/api/agent/tasks", c.endpointCredential(),
		contract.PollTareasRequest{EndpointID: endpointID}, &out)
	return out, err
}

// ReportarTarea informa el resultado de ejecutar una tarea.
func (c *Client) ReportarTarea(ctx context.Context, req contract.ReportarTareaRequest) error {
	var out struct {
		OK bool `json:"ok"`
	}
	return c.post(ctx, "/api/agent/tasks/result", c.endpointCredential(), req, &out)
}

// Clasificaciones descarga las reglas de contenido para clasificar archivos.
func (c *Client) Clasificaciones(ctx context.Context, endpointID string) (contract.ClasificacionesResponse, error) {
	var out contract.ClasificacionesResponse
	err := c.post(ctx, "/api/agent/classifications", c.endpointCredential(),
		contract.ClasificacionesRequest{EndpointID: endpointID}, &out)
	return out, err
}

// ReportarInventario envia el inventario de software y hardware del equipo.
func (c *Client) ReportarInventario(ctx context.Context, req contract.InventoryRequest) error {
	var out struct {
		OK bool `json:"ok"`
	}
	return c.post(ctx, "/api/agent/inventory", c.endpointCredential(), req, &out)
}
