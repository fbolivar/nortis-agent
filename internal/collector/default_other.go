//go:build !windows

package collector

import "github.com/rs/zerolog"

// Default no tiene recolectores fuera de Windows.
//
// El agente es un producto solo para Windows, pero el paquete tiene que compilar
// en otras plataformas: asi la logica pura —las maquinas de estado, que es donde
// estan las pruebas— se puede analizar y probar sin depender del sistema.
func Default(log zerolog.Logger) []Collector {
	log.Warn().Msg("no hay recolectores disponibles en esta plataforma")
	return nil
}
