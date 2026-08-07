//go:build windows

package collector

import (
	"github.com/rs/zerolog"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// PoliticaVigente da acceso a la politica que el agente tiene aplicada.
//
// Se pasa como funcion y no como valor porque la politica CAMBIA en caliente:
// el administrador la edita en la consola y el agente la recarga en el siguiente
// latido, sin reiniciarse. Un recolector que hubiera copiado la politica al
// arrancar seguiria aplicando la de hace tres horas.
//
// Puede devolver nil: significa que el equipo no tiene perfil asignado y el
// agente observa sin intervenir.
type PoliticaVigente func() *contract.Policy

// Default son los recolectores que arrancan con el servicio.
//
// TELEMETRIA BASE (sesion, aplicaciones): no dependen del consentimiento firmado
// porque no capturan contenido — quien entro al equipo y que programa abrio.
//
// TELEMETRIA DLP (USB, archivos): tampoco lo requieren. Registran movimiento de
// informacion —rutas, seriales, tamaños—, nunca lo que hay dentro. Lo que si
// exige consentimiento es el titulo de la ventana y la captura de pantalla, que
// no se recolectan aqui y que el agente no activa por su cuenta bajo ninguna
// circunstancia.
func Default(log zerolog.Logger, politica PoliticaVigente) []Collector {
	// Las carpetas de la politica se vigilan ADEMAS del perfil del usuario.
	//
	// `allowed_paths` puede parecer contraintuitivo —¿por que vigilar lo que
	// esta autorizado?—: es que la regla de carpeta no autorizada necesita ver
	// tambien lo que SALE de ahi, y `confidential_paths` marca justo el material
	// cuyo movimiento mas importa.
	rutasPolitica := func() []string {
		p := politica()
		if p == nil {
			return nil
		}
		return append(append([]string{}, p.Storage.AllowedPaths...), p.Encryption.ConfidentialPaths...)
	}

	return []Collector{
		NewSessionCollector(log),
		NewAppsCollector(log),
		NewUSBCollector(log, politica),
		NewFilesCollector(log, rutasPolitica),
		NewWebCollector(log),
		NewClipboardCollector(log, politica),
		NewPrintCollector(log, politica),
	}
}
