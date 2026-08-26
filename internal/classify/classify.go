// Package classify etiqueta un archivo por su CONTENIDO (Fase B de la
// clasificacion de datos). Evalua expresiones regulares —definidas en la consola
// y descargadas por el agente— sobre los primeros KB del archivo, y devuelve el
// nombre de la primera clasificacion que casa. Nunca sale contenido del equipo:
// solo la ETIQUETA.
//
// Se usa el motor regexp de Go (RE2): no hay backtracking, asi que una regla mal
// escrita no puede colgar al agente (sin ReDoS).
package classify

import (
	"bytes"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
)

// maxBytes acota cuanto se lee de cada archivo: suficiente para pescar un dato
// sensible cerca del inicio, sin cargar documentos enteros a memoria ni gastar
// disco por evento.
const maxBytes = 512 * 1024

// Definicion es una clasificacion con sus patrones de contenido, tal como llega
// de la consola.
type Definicion struct {
	Nombre   string
	Patrones []string
}

type reglaCompilada struct {
	nombre   string
	patrones []*regexp.Regexp
}

// Clasificador guarda las reglas compiladas y clasifica archivos. Es seguro para
// uso concurrente: el ciclo que refresca las reglas y el colector que clasifica
// corren en goroutines distintas.
type Clasificador struct {
	mu     sync.RWMutex
	reglas []reglaCompilada
}

func Nuevo() *Clasificador { return &Clasificador{} }

// Actualizar recompila las reglas. Una regla que no compila se descarta con el
// resto intacto: una expresion mal escrita en la consola no debe dejar al agente
// sin clasificar nada.
func (c *Clasificador) Actualizar(defs []Definicion) {
	compiladas := make([]reglaCompilada, 0, len(defs))
	for _, d := range defs {
		var res []*regexp.Regexp
		for _, p := range d.Patrones {
			if re, err := regexp.Compile(p); err == nil {
				res = append(res, re)
			}
		}
		if len(res) > 0 {
			compiladas = append(compiladas, reglaCompilada{nombre: d.Nombre, patrones: res})
		}
	}
	c.mu.Lock()
	c.reglas = compiladas
	c.mu.Unlock()
}

// Activo indica si hay reglas cargadas (si no, no se inspecciona nada).
func (c *Clasificador) Activo() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.reglas) > 0
}

// ClasificarArchivo lee los primeros KB del archivo y devuelve el nombre de la
// primera clasificacion cuyo patron casa, o "" si ninguna (o si no hay reglas, o
// el archivo parece binario). Nunca devuelve el contenido.
func (c *Clasificador) ClasificarArchivo(ruta string) string {
	c.mu.RLock()
	reglas := c.reglas
	c.mu.RUnlock()
	if len(reglas) == 0 {
		return ""
	}

	f, err := os.Open(ruta)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	datos, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil || len(datos) == 0 {
		return ""
	}
	// Un archivo binario (con bytes nulos) no lleva texto que clasificar por
	// patron; evaluarlo solo gastaria CPU y podria dar falsos positivos.
	if bytes.IndexByte(datos, 0) >= 0 {
		return ""
	}

	texto := string(datos)
	for _, r := range reglas {
		for _, re := range r.patrones {
			if re.MatchString(texto) {
				return r.nombre
			}
		}
	}
	return ""
}

// NombresDe devuelve los nombres de las definiciones, para el log de diagnostico
// (sin exponer los patrones).
func NombresDe(defs []Definicion) string {
	nombres := make([]string, 0, len(defs))
	for _, d := range defs {
		nombres = append(nombres, d.Nombre)
	}
	return strings.Join(nombres, ", ")
}
