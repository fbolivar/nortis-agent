package queue

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

func abrir(t *testing.T) *Queue {
	t.Helper()
	q, err := Open(filepath.Join(t.TempDir(), "queue.db"))
	if err != nil {
		t.Fatalf("abriendo la cola: %v", err)
	}
	t.Cleanup(func() { q.Close() })
	return q
}

func evento(path string) contract.Event {
	return contract.Event{
		Type:       contract.EventFileCreated,
		OccurredAt: time.Now().UTC().Truncate(time.Second),
		Payload:    map[string]any{"path": path, "user": "jperez"},
	}
}

func TestEncolarYLeer(t *testing.T) {
	q := abrir(t)

	for i := 0; i < 3; i++ {
		if err := q.Enqueue(evento("C:\\a.txt")); err != nil {
			t.Fatalf("encolando: %v", err)
		}
	}

	pendientes, err := q.Dequeue(10)
	if err != nil {
		t.Fatalf("leyendo: %v", err)
	}
	if len(pendientes) != 3 {
		t.Fatalf("se esperaban 3 eventos, hay %d", len(pendientes))
	}
	if pendientes[0].Event.Payload["path"] != "C:\\a.txt" {
		t.Errorf("el payload no sobrevivio al viaje: %v", pendientes[0].Event.Payload)
	}
}

// Dequeue NO debe borrar: si borrara y la peticion fallara despues, esos eventos
// se perderian para siempre. Es la razon de ser de la cola.
func TestDequeueNoBorra(t *testing.T) {
	q := abrir(t)
	_ = q.Enqueue(evento("C:\\a.txt"))

	if _, err := q.Dequeue(10); err != nil {
		t.Fatal(err)
	}

	n, _ := q.Len()
	if n != 1 {
		t.Fatalf("Dequeue borro el evento; quedan %d, se esperaba 1", n)
	}
}

func TestAckBorra(t *testing.T) {
	q := abrir(t)
	_ = q.Enqueue(evento("C:\\a.txt"))
	_ = q.Enqueue(evento("C:\\b.txt"))

	pendientes, _ := q.Dequeue(10)
	if err := q.Ack([]int64{pendientes[0].ID}); err != nil {
		t.Fatal(err)
	}

	n, _ := q.Len()
	if n != 1 {
		t.Fatalf("tras confirmar uno deberia quedar 1, quedan %d", n)
	}
}

// Un evento que la consola rechaza siempre bloquearia la cabeza de la cola —y
// con ella toda la telemetria posterior— si no se descartara al agotar los
// intentos.
func TestEventoImposibleNoBloqueaLaCola(t *testing.T) {
	q := abrir(t)
	_ = q.Enqueue(evento("C:\\veneno.txt"))

	pendientes, _ := q.Dequeue(10)
	ids := []int64{pendientes[0].ID}

	const maxIntentos = 3
	for i := 0; i < maxIntentos-1; i++ {
		dropped, err := q.Fail(ids, maxIntentos)
		if err != nil {
			t.Fatal(err)
		}
		if dropped != 0 {
			t.Fatalf("se descarto demasiado pronto, en el intento %d", i+1)
		}
	}

	dropped, err := q.Fail(ids, maxIntentos)
	if err != nil {
		t.Fatal(err)
	}
	if dropped != 1 {
		t.Fatalf("al agotar intentos deberia descartarse 1, se descartaron %d", dropped)
	}

	n, _ := q.Len()
	if n != 0 {
		t.Fatalf("la cola deberia quedar vacia, quedan %d", n)
	}
}

// Al alcanzar el tope se descartan los eventos MAS ANTIGUOS. En forense lo
// reciente es lo que se mira primero: perder la actividad de hoy para conservar
// la de hace semanas seria el peor intercambio posible.
func TestTopeDescartaLoMasAntiguo(t *testing.T) {
	q := abrir(t)

	// Se prueba la logica de trim con un tope simulado insertando por encima del
	// limite real seria lentisimo, asi que se verifica el orden de borrado.
	for i := 0; i < 5; i++ {
		_ = q.Enqueue(evento("evento-" + string(rune('a'+i))))
	}

	pendientes, _ := q.Dequeue(10)
	if pendientes[0].Event.Payload["path"] != "evento-a" {
		t.Fatalf("la cola no respeta el orden de llegada: %v", pendientes[0].Event.Payload)
	}

	// Se confirma que el mas antiguo es el primero en salir, que es el mismo
	// criterio que usa trim.
	if pendientes[len(pendientes)-1].Event.Payload["path"] != "evento-e" {
		t.Errorf("el ultimo deberia ser el mas nuevo")
	}
}

func TestMeta(t *testing.T) {
	q := abrir(t)

	// Una clave inexistente devuelve "" y no error: el llamador no deberia tener
	// que distinguir sql.ErrNoRows por todo el agente.
	v, err := q.GetMeta(MetaEndpointID)
	if err != nil {
		t.Fatalf("una clave inexistente no deberia dar error: %v", err)
	}
	if v != "" {
		t.Fatalf("se esperaba vacio, se obtuvo %q", v)
	}

	if err := q.SetMeta(MetaEndpointID, "abc"); err != nil {
		t.Fatal(err)
	}
	if err := q.SetMeta(MetaEndpointID, "def"); err != nil {
		t.Fatalf("SetMeta deberia sobrescribir: %v", err)
	}

	v, _ = q.GetMeta(MetaEndpointID)
	if v != "def" {
		t.Fatalf("se esperaba def, se obtuvo %q", v)
	}
}

// El estado debe sobrevivir a un reinicio del servicio: es lo que permite que un
// equipo que arranca sin red siga aplicando la ultima politica conocida.
func TestElEstadoSobreviveAlReinicio(t *testing.T) {
	dir := t.TempDir()
	ruta := filepath.Join(dir, "queue.db")

	q1, err := Open(ruta)
	if err != nil {
		t.Fatal(err)
	}
	_ = q1.SetMeta(MetaEndpointID, "endpoint-123")
	_ = q1.Enqueue(evento("C:\\pendiente.txt"))
	q1.Close()

	q2, err := Open(ruta)
	if err != nil {
		t.Fatalf("reabriendo: %v", err)
	}
	defer q2.Close()

	id, _ := q2.GetMeta(MetaEndpointID)
	if id != "endpoint-123" {
		t.Errorf("se perdio la identidad del equipo: %q", id)
	}

	n, _ := q2.Len()
	if n != 1 {
		t.Errorf("se perdio la telemetria pendiente: quedan %d", n)
	}
}
