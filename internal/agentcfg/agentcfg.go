// Package agentcfg gestiona la configuracion local del agente.
//
// Todo el estado del agente vive en un solo directorio bajo ProgramData:
//
//	config.json   parametros no secretos (URL de la consola, intervalos)
//	credential    la API key del tenant, cifrada con DPAPI
//	queue.db      la cola de eventos pendientes
//	agent.log     el registro de diagnostico, rotado
//
// Un unico directorio hace que desinstalar sea borrar una carpeta, y que
// diagnosticar un equipo sea pedir una copia de ella.
package agentcfg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config son los parametros NO secretos. La credencial va aparte y cifrada: si
// estuviera aqui, cualquier volcado de configuracion para diagnostico la
// filtraria.
type Config struct {
	// ConsoleURL es la base de la API, sin barra final. Ej: https://nortis.app
	ConsoleURL string `json:"console_url"`

	// SyncInterval es cada cuanto se drena la cola.
	SyncInterval Duration `json:"sync_interval"`
	// HeartbeatInterval es cada cuanto se reporta señal de vida.
	HeartbeatInterval Duration `json:"heartbeat_interval"`
	// PolicyInterval es cada cuanto se comprueba si cambio la politica.
	PolicyInterval Duration `json:"policy_interval"`
}

// Duration envuelve time.Duration para poder escribirla como "30s" en el JSON.
// Sin esto habria que poner nanosegundos, que nadie sabe leer en un archivo de
// configuracion que un tecnico va a editar a mano.
type Duration struct{ time.Duration }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("duracion invalida %q: %w", s, err)
	}
	d.Duration = v
	return nil
}

// Default devuelve la configuracion inicial.
func Default() Config {
	return Config{
		ConsoleURL: "http://localhost:3000",
		// 60s: suficientemente frecuente para que el panel se sienta vivo y
		// suficientemente espaciado para que doscientos equipos no golpeen la
		// ingesta a la vez.
		SyncInterval:      Duration{60 * time.Second},
		HeartbeatInterval: Duration{5 * time.Minute},
		PolicyInterval:    Duration{15 * time.Minute},
	}
}

// Dir devuelve el directorio de datos del agente.
func Dir() string {
	if base := os.Getenv("ProgramData"); base != "" {
		return filepath.Join(base, "Nortis", "Agent")
	}
	// Fuera de Windows (solo pruebas) se usa un directorio local.
	return filepath.Join(".", "nortis-agent-data")
}

func ConfigPath() string { return filepath.Join(Dir(), "config.json") }

// CredentialPath guarda la clave de la ORGANIZACION (nrt_live_…). Vive solo
// entre la instalacion y el primer enrolamiento correcto: despues se borra.
func CredentialPath() string { return filepath.Join(Dir(), "credential") }

// EndpointCredentialPath guarda la credencial de ESTE equipo (nrt_ep_…), con la
// que se firma todo lo posterior al alta. Es la que perdura.
func EndpointCredentialPath() string { return filepath.Join(Dir(), "endpoint.cred") }

func QueuePath() string { return filepath.Join(Dir(), "queue.db") }
func LogPath() string   { return filepath.Join(Dir(), "agent.log") }

// EnsureDir crea el directorio de datos si no existe.
func EnsureDir() error {
	return os.MkdirAll(Dir(), 0o700)
}

// Load lee la configuracion, creandola con valores por defecto si no existe.
func Load() (Config, error) {
	if err := EnsureDir(); err != nil {
		return Config{}, err
	}

	data, err := os.ReadFile(ConfigPath())
	if os.IsNotExist(err) {
		cfg := Default()
		return cfg, Save(cfg)
	}
	if err != nil {
		return Config{}, fmt.Errorf("leyendo la configuracion: %w", err)
	}

	cfg := Default()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("configuracion invalida: %w", err)
	}

	cfg.ConsoleURL = strings.TrimRight(strings.TrimSpace(cfg.ConsoleURL), "/")
	if cfg.ConsoleURL == "" {
		return Config{}, fmt.Errorf("console_url no puede estar vacio")
	}
	return cfg, nil
}

func Save(cfg Config) error {
	if err := EnsureDir(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigPath(), data, 0o600)
}
