// Package queue implementa la cola local de eventos pendientes de sincronizar.
//
// PRINCIPIO RECTOR: el recolector nunca espera a la red. Todo evento se escribe
// primero en SQLite y el sincronizador drena la cola aparte. Si el equipo pasa
// tres dias sin conexion, la telemetria no se pierde; y si la consola esta
// caida, el usuario no nota absolutamente nada.
package queue

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // driver SQLite en Go puro, sin cgo

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// MaxEvents es el tope de la cola.
//
// Sin tope, un equipo que pase semanas sin red llenaria el disco: es el mismo
// fallo que el producto dice prevenir, provocado por el propio agente. Al
// alcanzarlo se descartan los eventos MAS ANTIGUOS, no los nuevos: en una
// investigacion forense lo reciente es lo que se mira primero, y perder la
// actividad de hoy para conservar la de hace tres semanas seria el peor
// intercambio posible.
const MaxEvents = 200_000

// Queue es la cola persistente. Segura para uso concurrente: SQLite serializa
// las escrituras y el agente no necesita mas paralelismo que ese.
type Queue struct {
	db *sql.DB
}

// Pending es un evento en cola, con el identificador que hay que confirmar.
type Pending struct {
	ID    int64
	Event contract.Event
}

// Open abre (o crea) la cola en la ruta indicada.
func Open(path string) (*Queue, error) {
	// _busy_timeout: si el sincronizador tiene la escritura tomada, el
	// recolector espera en vez de fallar. Sin esto, un evento se perderia justo
	// cuando mas actividad hay.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("abriendo la cola: %w", err)
	}

	// WAL permite leer mientras se escribe: el sincronizador puede drenar sin
	// bloquear al recolector.
	if _, err := db.Exec(schema); err != nil {
		// El error del cierre se descarta explicitamente: ya estamos en el
		// camino de error y lo que importa devolver es la causa original, no un
		// fallo secundario al limpiar.
		_ = db.Close()
		return nil, fmt.Errorf("creando el esquema de la cola: %w", err)
	}

	return &Queue{db: db}, nil
}

func (q *Queue) Close() error { return q.db.Close() }

const schema = `
create table if not exists events (
  id          integer primary key autoincrement,
  event_type  text    not null,
  occurred_at text    not null,          -- RFC3339 en UTC
  payload     text    not null,          -- JSON del payload
  attempts    integer not null default 0,
  created_at  text    not null default (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- Clave-valor para el estado del agente: endpoint_id, ultima politica conocida,
-- marca de la ultima sincronizacion. Va en la misma base para que una sola
-- copia del archivo sea todo el estado del agente.
create table if not exists meta (
  key   text primary key,
  value text not null
);
`

// Enqueue guarda un evento. Es la unica operacion en el camino critico del
// recolector, y por eso es lo mas barata posible: un INSERT y nada mas.
func (q *Queue) Enqueue(e contract.Event) error {
	payload, err := json.Marshal(e.Payload)
	if err != nil {
		return fmt.Errorf("serializando el payload: %w", err)
	}

	if _, err := q.db.Exec(
		`insert into events (event_type, occurred_at, payload) values (?, ?, ?)`,
		string(e.Type), e.OccurredAt.UTC().Format(time.RFC3339), string(payload),
	); err != nil {
		return fmt.Errorf("encolando: %w", err)
	}

	return q.trim()
}

// trim aplica el tope descartando los eventos mas antiguos.
func (q *Queue) trim() error {
	var n int
	if err := q.db.QueryRow(`select count(*) from events`).Scan(&n); err != nil {
		return err
	}
	if n <= MaxEvents {
		return nil
	}

	_, err := q.db.Exec(
		`delete from events where id in (select id from events order by id asc limit ?)`,
		n-MaxEvents,
	)
	return err
}

// Dequeue devuelve hasta limit eventos SIN borrarlos.
//
// El borrado es un paso aparte (Ack) que solo ocurre cuando la consola confirma.
// Si se borraran aqui y la petición fallara despues, esos eventos se perderian
// para siempre — justo el escenario que la cola existe para evitar.
func (q *Queue) Dequeue(limit int) ([]Pending, error) {
	rows, err := q.db.Query(
		`select id, event_type, occurred_at, payload from events order by id asc limit ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("leyendo la cola: %w", err)
	}
	defer rows.Close()

	var out []Pending
	for rows.Next() {
		var (
			id                        int64
			eventType, occurred, body string
		)
		if err := rows.Scan(&id, &eventType, &occurred, &body); err != nil {
			return nil, err
		}

		at, err := time.Parse(time.RFC3339, occurred)
		if err != nil {
			// Una fila corrupta no puede bloquear la cola entera: se descarta y
			// se sigue. Bloquear aqui dejaria al equipo mudo indefinidamente.
			_, _ = q.db.Exec(`delete from events where id = ?`, id)
			continue
		}

		var payload map[string]any
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			_, _ = q.db.Exec(`delete from events where id = ?`, id)
			continue
		}

		out = append(out, Pending{
			ID:    id,
			Event: contract.Event{Type: contract.EventType(eventType), OccurredAt: at, Payload: payload},
		})
	}

	return out, rows.Err()
}

// Ack borra los eventos que la consola ya acepto.
func (q *Queue) Ack(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	tx, err := q.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`delete from events where id = ?`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, id := range ids {
		if _, err := stmt.Exec(id); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// Fail incrementa el contador de intentos y descarta los eventos que llevan
// demasiados.
//
// Un evento que la consola rechaza una y otra vez —por un payload que su
// version no entiende— bloquearia la cabeza de la cola para siempre y con ella
// toda la telemetria posterior. Se sacrifica ese evento para no perder el resto.
func (q *Queue) Fail(ids []int64, maxAttempts int) (dropped int, err error) {
	if len(ids) == 0 {
		return 0, nil
	}

	tx, err := q.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	for _, id := range ids {
		if _, err := tx.Exec(`update events set attempts = attempts + 1 where id = ?`, id); err != nil {
			return 0, err
		}
	}

	res, err := tx.Exec(`delete from events where attempts >= ?`, maxAttempts)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(n), nil
}

// Len devuelve cuantos eventos hay pendientes.
func (q *Queue) Len() (int, error) {
	var n int
	err := q.db.QueryRow(`select count(*) from events`).Scan(&n)
	return n, err
}

/* ------------------------------------------------------------------ Meta --- */

// GetMeta devuelve un valor de estado. Devuelve "" si no existe: el llamador
// distingue "sin valor" de "valor vacio" por contexto, y asi no hay que
// propagar sql.ErrNoRows por todo el agente.
func (q *Queue) GetMeta(key string) (string, error) {
	var v string
	err := q.db.QueryRow(`select value from meta where key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (q *Queue) SetMeta(key, value string) error {
	_, err := q.db.Exec(
		`insert into meta (key, value) values (?, ?)
		 on conflict (key) do update set value = excluded.value`,
		key, value,
	)
	return err
}

// Claves de estado conocidas.
const (
	MetaEndpointID      = "endpoint_id"
	MetaPolicyJSON      = "policy_json"
	MetaPolicyUpdatedAt = "policy_updated_at"
	MetaLastSyncAt      = "last_sync_at"
)
