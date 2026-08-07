//go:build windows

package collector

import "github.com/rs/zerolog"

// Default son los recolectores de Fase 1 que arrancan con el servicio.
//
// Sesion y aplicaciones son telemetria BASE: no dependen de
// monitoring_consent_signed_at porque no capturan contenido —quien entro al
// equipo y que programa abrio, nada mas—. Lo que si exige consentimiento
// firmado, titulos de ventana y capturas de pantalla, no se recolecta aqui y el
// agente nunca lo activa por su cuenta.
func Default(log zerolog.Logger) []Collector {
	return []Collector{
		NewSessionCollector(log),
		NewAppsCollector(log),
	}
}
