// Package collector contiene los recolectores de telemetria.
//
// Cada recolector es independiente y se ejecuta en su propia goroutine con
// recuperacion de panicos: un fallo leyendo procesos no puede tumbar el que
// vigila las sesiones, ni el servicio entero. Es el requisito de que un error
// del agente nunca bloquee al usuario, aplicado modulo a modulo.
package collector

import (
	"context"

	"github.com/fbolivar/nortis-agent/internal/contract"
)

// Emit entrega un evento a la cola. Nunca toca la red ni bloquea.
type Emit func(contract.Event)

// Collector es un recolector de telemetria.
//
// Run debe respetar la cancelacion del contexto y retornar: si no lo hace, el
// servicio no puede detenerse y Windows acaba matando el proceso.
type Collector interface {
	Name() string
	Run(ctx context.Context, emit Emit)
}

// categoriaPorProceso clasifica un ejecutable para el reporte de uso por
// categoria de software.
//
// La clasificacion vive en el AGENTE y no en la consola porque el nombre del
// proceso es lo unico que se reporta, y hacerla despues obligaria a mantener el
// mapa sincronizado con datos ya escritos. Lo desconocido se marca como tal en
// vez de forzarlo a una categoria: un dato honesto vale mas que uno completo.
var categoriaPorProceso = map[string]string{
	// Navegadores
	"chrome.exe": "navegador", "msedge.exe": "navegador", "firefox.exe": "navegador",
	"brave.exe": "navegador", "opera.exe": "navegador",

	// Ofimatica
	"excel.exe": "ofimatica", "winword.exe": "ofimatica", "powerpnt.exe": "ofimatica",
	"onenote.exe": "ofimatica", "wordpad.exe": "ofimatica",

	// Correo y comunicacion
	"outlook.exe": "correo", "teams.exe": "comunicacion", "ms-teams.exe": "comunicacion",
	"slack.exe": "comunicacion", "zoom.exe": "comunicacion", "whatsapp.exe": "comunicacion",
	"discord.exe": "comunicacion",

	// Documentos
	"acrord32.exe": "documentos", "acrobat.exe": "documentos", "sumatrapdf.exe": "documentos",

	// Desarrollo
	"code.exe": "desarrollo", "devenv.exe": "desarrollo", "notepad++.exe": "desarrollo",
	"windowsterminal.exe": "desarrollo", "powershell.exe": "desarrollo", "cmd.exe": "desarrollo",
	"pycharm64.exe": "desarrollo", "idea64.exe": "desarrollo",

	// Utilidades del sistema que interesan por seguridad, no por productividad
	"explorer.exe": "sistema", "taskmgr.exe": "sistema", "mmc.exe": "sistema",
	"regedit.exe": "sistema", "mstsc.exe": "acceso_remoto", "anydesk.exe": "acceso_remoto",
	"teamviewer.exe": "acceso_remoto", "rustdesk.exe": "acceso_remoto",

	// Compresores y transferencia: canales habituales de salida de informacion
	"7zfm.exe": "archivadores", "winrar.exe": "archivadores", "filezilla.exe": "transferencia",
	"winscp.exe": "transferencia",
}

// Categoria devuelve la categoria de un ejecutable, o "sin clasificar".
func Categoria(exe string) string {
	if c, ok := categoriaPorProceso[normalizar(exe)]; ok {
		return c
	}
	return "sin clasificar"
}

func normalizar(exe string) string {
	out := make([]rune, 0, len(exe))
	for _, r := range exe {
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		out = append(out, r)
	}
	return string(out)
}
