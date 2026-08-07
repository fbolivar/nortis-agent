package service

import (
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/fbolivar/nortis-agent/internal/agentcfg"
	"github.com/fbolivar/nortis-agent/internal/queue"
	"github.com/fbolivar/nortis-agent/internal/syncer"
)

// programa construye un Program aislado, sin red y con intervalos cortos.
//
// Se apunta a un host inexistente a proposito: valida que el ciclo de vida
// funciona AUNQUE la consola este caida, que es el escenario que de verdad
// importa. Un servicio que solo arranca con red es un servicio que no arranca.
func programa(t *testing.T, every time.Duration) *Program {
	t.Helper()

	q, err := queue.Open(filepath.Join(t.TempDir(), "queue.db"))
	if err != nil {
		t.Fatalf("abriendo la cola: %v", err)
	}
	t.Cleanup(func() { q.Close() })

	cfg := agentcfg.Config{
		ConsoleURL:        "http://127.0.0.1:1", // puerto que nadie escucha
		SyncInterval:      agentcfg.Duration{Duration: every},
		HeartbeatInterval: agentcfg.Duration{Duration: every},
		PolicyInterval:    agentcfg.Duration{Duration: every},
	}

	log := zerolog.New(io.Discard)
	agent := syncer.NewAgent(cfg, q, syncer.New(cfg.ConsoleURL, "nrt_live_0000000000000000000000000000000000000000000000000000000000000000"), log)

	return NewProgram(cfg, agent, log)
}

// Start debe RETORNAR RAPIDO. El gestor de servicios de Windows espera la
// confirmacion en segundos: si Start bloquea, el arranque se marca como fallido
// aunque el agente este funcionando perfectamente.
func TestStartRetornaRapido(t *testing.T) {
	p := programa(t, 50*time.Millisecond)

	inicio := time.Now()
	if err := p.Start(nil); err != nil {
		t.Fatalf("Start fallo: %v", err)
	}
	transcurrido := time.Since(inicio)

	t.Cleanup(func() { _ = p.Stop(nil) })

	if transcurrido > 2*time.Second {
		t.Fatalf("Start tardo %v; el gestor de servicios lo daria por fallido", transcurrido)
	}
}

// Stop debe terminar los ciclos y devolver el control. Si no confirma la parada,
// Windows mata el proceso a los 30 segundos y el estado queda a medias.
func TestStopTerminaLimpio(t *testing.T) {
	p := programa(t, 50*time.Millisecond)

	if err := p.Start(nil); err != nil {
		t.Fatalf("Start fallo: %v", err)
	}

	// Se deja correr para que los tres ciclos hayan hecho al menos una pasada
	// contra un host inalcanzable: es cuando mas facil seria quedarse colgado.
	time.Sleep(300 * time.Millisecond)

	hecho := make(chan error, 1)
	go func() { hecho <- p.Stop(nil) }()

	select {
	case err := <-hecho:
		if err != nil {
			t.Fatalf("Stop devolvio error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Stop no retorno: los ciclos quedaron colgados")
	}
}

// El servicio tiene que arrancar aunque la consola este caida. Sin red, el
// agente sigue aplicando la ultima politica conocida y acumulando telemetria.
func TestArrancaSinRed(t *testing.T) {
	p := programa(t, 50*time.Millisecond)

	if err := p.Start(nil); err != nil {
		t.Fatalf("el servicio no arranco sin consola: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	if err := p.Stop(nil); err != nil {
		t.Fatalf("Stop fallo: %v", err)
	}
}
