// Package schedtask guarda y programa los scripts recurrentes que encarga la
// consola. Persiste en disco (bajo el directorio del agente) para sobrevivir a
// reinicios, y decide cuales toca ejecutar en cada minuto.
package schedtask

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Programada es un script recurrente ya verificado (la firma la comprobo el
// servicio antes de guardarlo).
type Programada struct {
	ID           string `json:"id"`
	Interpreter  string `json:"interpreter"`
	Script       string `json:"script"`
	EveryMinutes int    `json:"every_minutes"`
	NotAfter     int64  `json:"not_after"`
	LastRun      int64  `json:"last_run"`
}

// Store es el conjunto persistido de programaciones. Seguro para uso concurrente.
type Store struct {
	mu    sync.Mutex
	ruta  string
	items map[string]Programada
}

// Abrir carga el store desde `dir` (o arranca vacio si no existe).
func Abrir(dir string) *Store {
	s := &Store{ruta: filepath.Join(dir, "programadas.json"), items: map[string]Programada{}}
	if data, err := os.ReadFile(s.ruta); err == nil {
		var lista []Programada
		if json.Unmarshal(data, &lista) == nil {
			for _, p := range lista {
				s.items[p.ID] = p
			}
		}
	}
	return s
}

// Aplicar agrega o reemplaza una programacion. Con EveryMinutes <= 0 la elimina.
func (s *Store) Aplicar(p Programada) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.EveryMinutes <= 0 {
		delete(s.items, p.ID)
	} else {
		// Conserva el LastRun si ya existia, para no reejecutar al reprogramar.
		if prev, ok := s.items[p.ID]; ok {
			p.LastRun = prev.LastRun
		}
		s.items[p.ID] = p
	}
	s.guardar()
}

// Vencidas devuelve las programaciones que toca ejecutar ahora (y no vencidas),
// marcandolas como ejecutadas. Las que ya pasaron su NotAfter se purgan.
func (s *Store) Vencidas(ahora time.Time) []Programada {
	s.mu.Lock()
	defer s.mu.Unlock()

	var listo []Programada
	cambio := false
	for id, p := range s.items {
		if p.NotAfter > 0 && ahora.Unix() > p.NotAfter {
			delete(s.items, id)
			cambio = true
			continue
		}
		if ahora.Unix()-p.LastRun >= int64(p.EveryMinutes)*60 {
			p.LastRun = ahora.Unix()
			s.items[id] = p
			listo = append(listo, p)
			cambio = true
		}
	}
	if cambio {
		s.guardar()
	}
	return listo
}

// guardar persiste el store. Se llama con el lock tomado.
func (s *Store) guardar() {
	lista := make([]Programada, 0, len(s.items))
	for _, p := range s.items {
		lista = append(lista, p)
	}
	if data, err := json.Marshal(lista); err == nil {
		_ = os.WriteFile(s.ruta, data, 0o600)
	}
}
